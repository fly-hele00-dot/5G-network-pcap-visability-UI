#!/usr/bin/env python3
"""pcapx - identity-aware pcap filtering on top of tshark.

Examples:
  pcapx.py trace.pcapng --stats
  pcapx.py trace.pcapng -f "imsi=262011234567890"
  pcapx.py trace.pcapng -f "msisdn=4915112345678 and proto~=NGAP|HTTP2"
  pcapx.py trace.pcapng -f "imsi=262011234567890" --follow      # everything tied to that subscriber
  pcapx.py trace.pcapng --seq 1000 --any-hop                    # same payload even if seq differs (NAT/proxy)
  pcapx.py trace.pcapng -f "imsi=2620*" -w out.pcapng           # export matches
"""
import argparse, fnmatch, hashlib, json, os, re, shutil, subprocess, sys, tempfile
from collections import defaultdict

# key -> tshark field(s). Fields the local tshark doesn't know are dropped automatically.
FIELDS = {
    "src": ["ip.src", "ipv6.src"], "dst": ["ip.dst", "ipv6.dst"],
    "proto": ["_ws.col.protocol"], "info": ["_ws.col.info"],
    "sport": ["tcp.srcport", "udp.srcport"], "dport": ["tcp.dstport", "udp.dstport"],
    "h2_stream": ["http2.streamid"],
    "tcp_stream": ["tcp.stream"], "udp_stream": ["udp.stream"],
    "seq": ["tcp.seq"], "seq_raw": ["tcp.seq_raw"],
    "payload": ["tcp.payload", "udp.payload"],
    "sctp_tsn": ["sctp.tsn"],
    # subscriber identities
    "imsi": ["e212.imsi", "gsm_map.imsi_digits", "diameter.User-Name"],
    "msisdn": ["e164.msisdn", "gsm_map.msisdn", "gsm_map.address.digits"],
    "imei": ["gsm_a.imei", "e212.imei"],
    "sbi_json": ["json.value.string", "http2.header.value", "http.request.uri"],
    # correlation handles (stay constant while seq / ports / IPs change)
    "teid": ["gtp.teid", "gtpv2.teid", "gtpv2.teid_or_gre_key"],
    "seid": ["pfcp.seid"],
    "ue_id": ["ngap.AMF_UE_NGAP_ID", "ngap.RAN_UE_NGAP_ID", "s1ap.MME_UE_S1AP_ID"],
    "tcap_tid": ["tcap.otid", "tcap.dtid"],
    "call_id": ["sip.Call-ID"], "diam_sess": ["diameter.Session-Id"],
    "sccp_gt": ["sccp.calling.digits", "sccp.called.digits"],
}
ID_KEYS = ["imsi", "msisdn", "imei", "teid", "seid", "ue_id", "tcap_tid", "call_id", "diam_sess"]
SBI_RE = {"imsi": re.compile(r"imsi-(\d{6,15})"), "msisdn": re.compile(r"(?:msisdn|tel:\+?)[-:]?(\d{6,15})")}


def tshark_fields(tshark):
    out = subprocess.run([tshark, "-G", "fields"], capture_output=True, text=True, check=True).stdout
    return {l.split("\t")[2] for l in out.splitlines() if l.startswith("F\t")}


def load(path, tshark="tshark", extra_filter=None):
    known = tshark_fields(tshark)
    cols = [(k, f) for k, fs in FIELDS.items() for f in fs if f in known]
    cmd = [tshark, "-r", path, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
           "-E", "aggregator=,", "-e", "frame.number", "-e", "frame.time_epoch"]
    for _, f in cols:
        cmd += ["-e", f]
    if extra_filter:
        cmd += ["-Y", extra_filter]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode and not p.stdout:
        sys.exit(p.stderr)
    pkts = []
    for line in p.stdout.splitlines():
        v = line.split("\t")
        v += [""] * (2 + len(cols) - len(v))
        pkt = {"frame": int(v[0]), "time": float(v[1] or 0)}
        for (k, _), val in zip(cols, v[2:]):
            if val:
                pkt[k] = f"{pkt[k]},{val}" if k in pkt else val
        pkts.append(finish(pkt))
    return pkts


def norm(k, val):
    """Normalise identity values so 'imsi-2620..', '+49151..' and TBCD digits all compare equal."""
    if k in ("imsi", "msisdn", "imei", "sccp_gt"):
        return re.sub(r"\D", "", val)
    return val.strip()


def finish(pkt):
    ids = defaultdict(set)
    for k in ID_KEYS:
        for val in filter(None, pkt.get(k, "").split(",")):
            ids[k].add(norm(k, val))
    for m in SBI_RE:  # 5G SBI carries SUPI/GPSI inside JSON/headers
        for val in SBI_RE[m].findall(pkt.get("sbi_json", "")):
            ids[m].add(val)
    for val in filter(None, pkt.get("sccp_gt", "").split(",")):
        ids["sccp_gt"].add(norm("sccp_gt", val))
    pkt["ids"] = ids
    if pkt.get("payload"):
        pkt["payload_hash"] = hashlib.sha1(pkt["payload"].encode()).hexdigest()[:16]
    return pkt


# ---- filter language: key=val | key!=val | key~=regex, joined by and/or; '*' wildcards on '=' ----
TERM = re.compile(r"\s*(\w+)\s*(!=|~=|=)\s*(\S+)\s*")


def parse(expr):
    def term(t):
        m = TERM.fullmatch(t)
        if not m:
            raise ValueError(f"bad filter term {t!r} - use key=value, key!=value or key~=regex")
        return m.groups()
    return [[term(t) for t in re.split(r"\s+and\s+", clause, flags=re.I)]
            for clause in re.split(r"\s+or\s+", expr, flags=re.I)]


def values(pkt, key):
    if key in pkt["ids"]:
        return pkt["ids"][key]
    return [x for x in str(pkt.get(key, "")).split(",") if x]


def match_term(pkt, key, op, want):
    vals = values(pkt, key)
    if key in ID_KEYS or key == "sccp_gt":
        want = norm(key, want) if "*" not in want and op != "~=" else want
    if op == "=":
        return any(fnmatch.fnmatchcase(str(v), want) for v in vals)
    if op == "!=":
        return not any(fnmatch.fnmatchcase(str(v), want) for v in vals)
    return any(re.search(want, str(v), re.I) for v in vals)


def apply_filter(pkts, expr):
    dnf = parse(expr)
    return [p for p in pkts if any(all(match_term(p, *t) for t in clause) for clause in dnf)]


# ---- correlation ----
def follow(pkts, seeds):
    """Grow the seed set: any packet sharing an identity/handle value with it joins, repeat to fixpoint.
    Finds e.g. IMSI -> NGAP UE ids -> PFCP SEID -> GTP TEID -> the user-plane packets."""
    keys = {(k, v) for p in seeds for k, vs in p["ids"].items() for v in vs}
    got = {p["frame"] for p in seeds}
    while True:
        new = [p for p in pkts if p["frame"] not in got and any((k, v) in keys for k, vs in p["ids"].items() for v in vs)]
        if not new:
            return [p for p in pkts if p["frame"] in got]
        for p in new:
            got.add(p["frame"])
            keys |= {(k, v) for k, vs in p["ids"].items() for v in vs}


def any_hop(pkts, seeds):
    """Same TCP/UDP payload seen elsewhere (before/after NAT, proxy, SBC) even though seq/ports differ."""
    hashes = {p["payload_hash"] for p in seeds if "payload_hash" in p}
    return [p for p in pkts if p.get("payload_hash") in hashes]


def query(pkts, filt=None, seq=None, hop=False, follow_=False):
    """Shared by the CLI and the web UI."""
    res = apply_filter(pkts, filt) if filt else pkts
    if seq:
        res = [p for p in res if seq in (p.get("seq"), p.get("seq_raw"))]
        if hop:
            res = any_hop(pkts, res)
    return follow(pkts, res) if follow_ else res


def complete_exchanges(pkts, sel):
    """Add the rest of every HTTP/2 exchange that has a selected packet, e.g. the response, which usually
    does not carry the IMSI itself. Uses (tcp stream, h2 stream) of every selected packet, NAT copies included."""
    def key(p):
        m = H2.match(p.get("info", "")) if p.get("proto", "").startswith("HTTP2") else None
        return (p["tcp_stream"], int(m.group(1))) if m and p.get("tcp_stream") else None
    want = {k for k in map(key, sel) if k}
    got = {p["frame"] for p in sel}
    return [p for p in pkts if p["frame"] in got or key(p) in want]


def identities(pkts):
    seen = defaultdict(set)
    for p in pkts:
        for k, vs in p["ids"].items():
            seen[k] |= vs
    return seen


NF = {"nudm": "UDM", "nudr": "UDR", "npcf": "PCF", "nausf": "AUSF", "namf": "AMF", "nsmf": "SMF", "nnrf": "NRF",
      "nnssf": "NSSF", "nudsf": "UDSF", "nchf": "CHF", "nnef": "NEF", "nsmsf": "SMSF", "nbsf": "BSF", "nlmf": "LMF"}
H2 = re.compile(r"(?:HEADERS|DATA|CONTINUATION)\[(\d+)\]")
H2_REQ = re.compile(r":\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)")
H2_RESP = re.compile(r":\s*(\d{3})\s*([A-Za-z ]*)")
H2_NOTE = re.compile(r"JSON \([^)]*\),\s*(.+)$")


def nat_twins(pkts, window=0.005):
    """A packet seen twice on one capture (before/after DNAT/SNAT): same payload, other address, within ms.
    Returns {twin index: primary index}."""
    groups = defaultdict(list)
    for i, p in enumerate(pkts):
        if len(p.get("payload", "")) >= 96:
            groups[p["payload_hash"]].append(i)
    twin = {}
    for idx in groups.values():
        for a, b in zip(idx, idx[1:]):
            pa, pb = pkts[a], pkts[b]
            if a not in twin and b not in twin and (pa.get("src"), pa.get("dst")) != (pb.get("src"), pb.get("dst")) \
                    and 0 <= pb["time"] - pa["time"] <= window:
                twin[b] = a
    return twin


def real_endpoints(a, b):
    """(src, dst) of a merged NAT pair. In request direction (dst port < src port) the address after NAT is the
    real destination; in response direction the address before reverse-NAT is the real source."""
    try:
        request = int(a["dport"].split(",")[0]) < int(a["sport"].split(",")[0])
    except (KeyError, ValueError):
        request = True
    return (a["src"], b["dst"]) if request else (a["src"], a["dst"])


def graph_data(pkts, max_rows=None):
    """Build the picture: one row per HTTP/2 exchange (request + response, NAT copies merged) or per packet,
    lanes named by network function, and 'caused by' links (a call made while answering another call)."""
    twin = nat_twins(pkts)
    twins = defaultdict(list)
    for b, a in twin.items():
        twins[a].append(b)
    roles = defaultdict(lambda: defaultdict(int))
    rows, keymap, pkt_row = [], {}, {}
    for i, p in enumerate(pkts):
        if i in twin:
            continue
        info = p.get("info", "")
        h = H2.match(info) if p.get("proto", "").startswith("HTTP2") else None
        members = [i] + twins.get(i, [])
        s, d = (real_endpoints(p, pkts[twins[i][0]]) if i in twins else (p.get("src", "?"), p.get("dst", "?")))
        req, resp = (H2_REQ.search(info[h.end():]), H2_RESP.match(info[h.end():])) if h else (None, None)
        if req:
            m = re.match(r"/(n[a-z]+)-", req.group(2))
            if m and m.group(1) in NF:
                for j in members:
                    roles[pkts[j].get("dst")][NF[m.group(1)]] += 1
        keys = [(pkts[j].get("tcp_stream"), int(h.group(1))) for j in members if pkts[j].get("tcp_stream")] if h else []
        r = next((keymap[k] for k in keys if k in keymap), None)
        if r is None:
            r = len(rows)
            rows.append({"id": r, "t": p["time"], "tend": p["time"], "s": s, "d": d, "kind": "txn" if h else "pkt",
                         "proto": p.get("proto", ""), "info": info, "method": "", "path": "", "status": "", "reason": "",
                         "note": "", "frames": [], "ids": defaultdict(set), "parent": None})
            if resp and not req:  # request not in the selection: the response tells us the direction
                rows[r]["s"], rows[r]["d"] = d, s
        row = rows[r]
        for k in keys:
            keymap[k] = r
        if req:
            row.update(method=req.group(1), path=req.group(2), s=s, d=d)
        elif resp:
            row.update(status=resp.group(1), reason=resp.group(2).strip())
        note = H2_NOTE.search(info)
        if note and not row["note"]:
            row["note"] = note.group(1)
        kind = "req" if req else "resp" if resp else "data" if h else "pkt"
        row["tend"] = max(row["tend"], p["time"])
        for j in members:
            q = pkts[j]
            row["frames"].append({"f": q["frame"], "s": q.get("src", "?"), "d": q.get("dst", "?"), "k": kind, "twin": j != i})
            pkt_row[j] = r
            for k, vs in q["ids"].items():
                row["ids"][k] |= vs
    # 'caused by': B is a probable child of A if A's server is B's client and B started while A was still open
    by_server = defaultdict(list)
    for row in rows:
        if row["kind"] == "txn":
            by_server[row["d"]].append(row)
    for row in rows:
        if row["kind"] != "txn":
            continue
        for cand in reversed([c for c in by_server.get(row["s"], []) if c["t"] <= row["t"] and c["id"] != row["id"]][-40:]):
            if cand["tend"] >= row["t"]:
                row["parent"] = cand["id"]
                break
    role = {ip: max(v, key=v.get) for ip, v in roles.items()}
    total = len(rows)
    rows = rows[:max_rows] if max_rows else rows
    for row in rows:
        row["ids"] = {k: sorted(v) for k, v in row["ids"].items()}
        if row["parent"] is not None and row["parent"] >= len(rows):
            row["parent"] = None
    keep = {r["id"] for r in rows}
    nodes = [{"f": p["frame"], "t": p["time"], "s": p.get("src", "?"), "d": p.get("dst", "?"), "sp": p.get("sport", ""),
              "dp": p.get("dport", ""), "proto": p.get("proto", ""), "info": p.get("info", ""), "row": pkt_row[i],
              "twin": i in twin, "ids": {k: sorted(v) for k, v in p["ids"].items()}, "seq": p.get("seq", "")}
             for i, p in enumerate(pkts) if pkt_row.get(i) in keep]
    return {"rows": rows, "packets": nodes, "roles": role, "rows_total": total}


def build_graph(pkts, path, max_rows=300):
    """Write a self-contained HTML file (static mode of graph_template.html)."""
    data = graph_data(pkts, max_rows)
    if data["rows_total"] > max_rows:
        print(f"-- graph limited to the first {max_rows} of {data['rows_total']} rows (use -f/--follow/--pre to narrow)", file=sys.stderr)
    tpl = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "graph_template.html")).read()
    open(path, "w").write(tpl.replace("/*DATA*/null", json.dumps(data).replace("</", "<\\/")))
    print(f"-- wrote {path}: {len(data['rows'])} rows, {len(data['packets'])} packets", file=sys.stderr)


def export(pcap, pkts, out):
    """Write the given packets to a new capture. editcap picks frames by number directly, which is far
    faster than a tshark 'frame.number in {...}' filter (that is tested against every packet).
    editcap only accepts ~500 ranges per run, so long selections are done in batches and merged."""
    frames = sorted({p["frame"] for p in pkts})
    ranges, start = [], 0
    for i, f in enumerate(frames):  # collapse runs: 5,6,7 -> 5-7
        if i + 1 == len(frames) or frames[i + 1] != f + 1:
            ranges.append(str(frames[start]) if start == i else f"{frames[start]}-{f}")
            start = i + 1
    batches = [ranges[i:i + 400] for i in range(0, len(ranges), 400)]
    with tempfile.TemporaryDirectory() as tmp:
        parts = []
        for n, batch in enumerate(batches):
            parts.append(os.path.join(tmp, f"part{n}.pcapng"))
            subprocess.run(["editcap", "-F", "pcapng", "-r", pcap, parts[-1], *batch], check=True, capture_output=True)
        if len(parts) == 1:
            shutil.move(parts[0], out)
        else:
            subprocess.run(["mergecap", "-F", "pcapng", "-w", out, *parts], check=True, capture_output=True)


def show(pkts):
    for p in pkts:
        ids = " ".join(f"{k}={','.join(sorted(v))}" for k, v in p["ids"].items())
        print(f"{p['frame']:>7} {p['time']:.6f} {p.get('src','?')}>{p.get('dst','?')} "
              f"{p.get('proto',''):<8} {p.get('info','')[:70]:<70} {ids}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("-f", "--filter", help="e.g. \"imsi=2620* and proto~=NGAP\"")
    ap.add_argument("--seq", help="TCP sequence number (relative or raw)")
    ap.add_argument("--any-hop", action="store_true", help="with --seq: also match the same payload where seq differs")
    ap.add_argument("--follow", action="store_true", help="expand matches to every packet tied to the same subscriber/session")
    ap.add_argument("--pre", help="native Wireshark display filter applied first (speeds up big files)")
    ap.add_argument("--graph", metavar="HTML", help="write an interactive packet graph (ladder diagram) to this file")
    ap.add_argument("--max-rows", type=int, default=300)
    ap.add_argument("-w", metavar="OUT", help="write matches to a pcap")
    ap.add_argument("--stats", action="store_true", help="list identities found in the trace")
    ap.add_argument("--tshark", default="tshark")
    a = ap.parse_args()

    pkts = load(a.pcap, a.tshark, a.pre)
    if a.stats:
        for k, vs in identities(pkts).items():
            print(f"{k}: {len(vs)} -> {', '.join(sorted(vs)[:10])}{' ...' if len(vs) > 10 else ''}")
        return
    try:
        res = query(pkts, a.filter, a.seq, a.any_hop, a.follow)
    except ValueError as e:
        sys.exit(str(e))
    if a.graph:
        build_graph(complete_exchanges(pkts, res), a.graph, a.max_rows)
    else:
        show(res)
    print(f"-- {len(res)} of {len(pkts)} packets", file=sys.stderr)
    if a.w and res:
        export(a.pcap, res, a.w)


if __name__ == "__main__":
    main()

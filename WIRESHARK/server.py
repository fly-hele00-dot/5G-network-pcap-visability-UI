#!/usr/bin/env python3
"""Local web UI for pcapx.  Usage: python3 server.py [--dir .] [--port 8000]  ->  http://localhost:8000"""
import argparse, atexit, json, os, re, subprocess, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pcapx

HERE = os.path.dirname(os.path.abspath(__file__))
EXTS = (".pcap", ".pcapng", ".cap")
# first 4 bytes of a pcap (either byte order, micro/nanosecond) and of a pcapng
MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
CACHE, LOCKS, GUARD = {}, {}, threading.Lock()


def pcap_path(name):
    if os.path.basename(name) != name or not name.lower().endswith(EXTS):
        raise ValueError("bad file name")
    path = os.path.join(ARGS.dir, name)
    if not os.path.isfile(path):
        raise ValueError(f"{name} not found")
    return path


class HttpError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


def clean_name(name):
    """Keep the client's file name, but only plain characters and a capture extension."""
    name = re.sub(r"[^\w.\- ]", "_", os.path.basename(name or "").strip()).lstrip(".")
    if not name.lower().endswith(EXTS):
        raise HttpError(400, "only .pcap, .pcapng and .cap files can be imported")
    return name[-200:]


def api_upload(h, q):
    """POST /api/upload?name=x.pcapng, body = the raw file. Streamed to a temp file in the pcap folder, checked for a
    pcap/pcapng header, then linked in under a free name (an existing capture is never overwritten)."""
    if h.headers.get("X-Requested-With") != "pcapx":  # a custom header cannot be sent cross-site without CORS approval
        raise HttpError(403, "missing X-Requested-With header")
    name = clean_name(q.get("name"))
    h.left = int(h.headers.get("Content-Length") or 0)
    if h.left <= 0:
        raise HttpError(400, "empty upload")
    if h.left > ARGS.max_upload_mb * 1024 * 1024:
        raise HttpError(413, f"file is larger than the {ARGS.max_upload_mb} MB limit (raise it with --max-upload-mb)")
    fd, tmp = tempfile.mkstemp(prefix=".upload-", suffix=".part", dir=ARGS.dir)
    try:
        with os.fdopen(fd, "wb") as out:
            first = True
            while h.left:
                chunk = h.rfile.read(min(1 << 20, h.left))
                if not chunk:
                    h.left = 0  # client went away, nothing to drain
                    raise HttpError(400, "upload interrupted")
                h.left -= len(chunk)
                if first and chunk[:4] not in MAGIC:
                    raise HttpError(400, f"{name} is not a pcap/pcapng file (compressed? unzip it first)")
                first = False
                out.write(chunk)
        stem, ext = os.path.splitext(name)
        final, n = name, 0
        while True:
            try:
                os.link(tmp, os.path.join(ARGS.dir, final))
                break
            except FileExistsError:
                n += 1
                final = f"{stem}_{n}{ext}"
    finally:
        os.remove(tmp)
    return {"name": final, "mb": round(os.path.getsize(os.path.join(ARGS.dir, final)) / 1e6, 1)}


def packets(name, pre):
    """Parse once per (file, mtime, pre-filter); concurrent requests wait for the same parse."""
    path = pcap_path(name)
    key = (path, os.path.getmtime(path), pre or "")
    with GUARD:
        lock = LOCKS.setdefault(key, threading.Lock())
    with lock:
        if key not in CACHE:
            CACHE[key] = pcapx.load(path, ARGS.tshark, pre or None)
    return CACHE[key]


class Sharkd:
    """One long-lived sharkd per pcap. It keeps the whole capture loaded, so a single frame can be fully
    dissected with the state of earlier packets (HTTP/2 header compression, TCP reassembly)."""

    def __init__(self, path):
        self.p = subprocess.Popen(["sharkd", "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.lock, self.n = threading.Lock(), 0
        self.call("load", {"file": path})

    def alive(self):
        return self.p.poll() is None

    def call(self, method, params):
        with self.lock:
            self.n += 1
            self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}) + "\n")
            self.p.stdin.flush()
            while True:
                line = self.p.stdout.readline()
                if not line:
                    raise RuntimeError("sharkd exited")
                d = json.loads(line)
                if d.get("id") == self.n:
                    break
        if "error" in d:
            raise ValueError(d["error"].get("message", "sharkd error"))
        return d.get("result")


SHARKD = {}


def sharkd_for(path):
    key = (path, os.path.getmtime(path))
    with GUARD:
        sd = SHARKD.get(key)
        if not sd or not sd.alive():
            sd = SHARKD[key] = Sharkd(path)
    return sd


def api_frame(q):
    r = sharkd_for(pcap_path(q["file"])).call("frame", {"frame": int(q["frame"]), "proto": True, "bytes": True})
    return {"tree": r["tree"], "bytes": r.get("bytes", "")}


@atexit.register
def _stop_sharkd():
    for sd in SHARKD.values():
        sd.p.terminate()


def api_files(_):
    return [{"name": f, "mb": round(os.path.getsize(os.path.join(ARGS.dir, f)) / 1e6, 1)}
            for f in sorted(os.listdir(ARGS.dir)) if f.lower().endswith(EXTS)]


def api_ids(q):
    ids = pcapx.identities(packets(q["file"], q.get("pre")))
    return {k: sorted(v)[:200] for k, v in ids.items()} | {"_counts": {k: len(v) for k, v in ids.items()}}


def run(q):
    pkts = packets(q["file"], q.get("pre"))
    res = pcapx.query(pkts, q.get("f") or None, q.get("seq") or None, q.get("hop") == "1", q.get("follow") == "1")
    return pkts, res, pcapx.complete_exchanges(pkts, res)


def api_query(q):
    pkts, res, full = run(q)
    limit = max(1, min(int(q.get("max") or 300), 2000))
    data = pcapx.graph_data(full, limit)
    data.update(total=len(pkts), matched=len(res), context=len(full) - len(res), shown=len(data["rows"]))
    return data


def api_export(q):
    _, _, res = run(q)
    if not res:
        raise ValueError("nothing to export")
    out = os.path.join(tempfile.gettempdir(), f"pcapx-{os.getpid()}-{threading.get_ident()}.pcapng")
    try:
        pcapx.export(pcap_path(q["file"]), res, out)
        return open(out, "rb").read()
    finally:
        if os.path.exists(out):
            os.remove(out)


class Handler(BaseHTTPRequestHandler):
    def send(self, code, body, ctype="application/json", extra=None):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            if u.path == "/":
                html = open(os.path.join(HERE, "graph_template.html")).read()
                return self.send(200, html.encode(), "text/html; charset=utf-8")
            if u.path == "/api/files":
                return self.send(200, api_files(q))
            if u.path == "/api/ids":
                return self.send(200, api_ids(q))
            if u.path == "/api/query":
                return self.send(200, api_query(q))
            if u.path == "/api/frame":
                return self.send(200, api_frame(q))
            if u.path == "/api/export":
                body = api_export(q)
                return self.send(200, body, "application/octet-stream",
                                 {"Content-Disposition": 'attachment; filename="filtered.pcapng"'})
            self.send(404, {"error": "not found"})
        except (ValueError, KeyError) as e:
            self.send(400, {"error": str(e.args[0]) if e.args else "bad request"})
        except Exception as e:  # tshark failure etc.
            self.send(500, {"error": f"{type(e).__name__}: {e}"})

    def do_POST(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        self.left = 0
        try:
            if u.path != "/api/upload":
                raise HttpError(404, "not found")
            self.send(200, api_upload(self, q))
        except HttpError as e:
            while self.left:  # read the rest of the body, otherwise the browser sees a reset instead of our message
                self.left -= len(self.rfile.read(min(1 << 20, self.left)) or b"\0" * self.left)
            self.send(e.code, {"error": str(e)})
        except Exception as e:
            self.send(500, {"error": f"{type(e).__name__}: {e}"})

    def log_message(self, fmt, *a):
        pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=HERE, help="folder holding the pcap files")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--tshark", default="tshark")
    ap.add_argument("--max-upload-mb", type=int, default=2048, help="largest pcap the Import button accepts")
    ARGS = ap.parse_args()
    srv = ThreadingHTTPServer(("localhost", ARGS.port), Handler)
    print(f"pcapx web UI: http://localhost:{ARGS.port}  (pcaps from {ARGS.dir})")
    srv.serve_forever()

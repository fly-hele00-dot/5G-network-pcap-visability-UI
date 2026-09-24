# pcapx – 5G packet-flow explorer

A small local web UI (plus CLI) on top of `tshark` for exploring 5G core captures. It finds every packet that
belongs to a subscriber (IMSI / MSISDN / IMEI) or a session handle (TEID, SEID, UE NGAP ID, TCAP TID, SIP Call-ID,
Diameter Session-Id), and draws the result as a ladder diagram, one row per HTTP/2 request+response.

The captures come from a local 5G lab (free5GC + UERANSIM on a kind cluster). The map below shows what is being captured.

![Infrastructure map](infra_map.png)

Vector version: [`infra_map.svg`](infra_map.svg).

IP addresses and pod / deployment names in this README are the same as in the 5G lab project
(`../5g lab/lab/README.md`, section *Addressing & exposure*): cluster `corelab`, namespace `core`, Helm releases
`core` (pods `core-free5gc-<nf>-*`), `ran` (pods `ran-gnb-*`, `ran-ue-*`) and `ran-cell2` (second gNB).
The commands below can be copied as they are. The only exception is the screenshots, where the IP addresses are
replaced by dummy documentation-range addresses (`192.0.2.0/24`).

## Screenshots

The captures below are a 222 MB, 330k-packet lab trace imported through the UI. IP addresses in the screenshots
are replaced by dummy documentation-range addresses (`192.0.2.x`), unlike the rest of this README.

**1. Import.** Press **Import pcap…** (or drop the file on the page). The file is stored, selected in the drop-down,
and ready to run.

![Import](docs/01-import.png)

**2. Exchanges.** Filter on a subscriber (`imsi=...`) with *follow session* on. One row per HTTP/2 request and
response, lanes named by network function. The side panel lists the identities found in the trace.

![Exchanges](docs/02-exchanges.png)

**3. Details.** Click an exchange to see who called whom, timing, the call chain (what triggered it, what it
triggered) and every packet in it, including the NAT copies.

![Details](docs/03-details.png)

**4. Table.** The same exchanges as a sortable table.

![Table](docs/04-table.png)

## Files

| File | Purpose |
|---|---|
| `server.py` | Web server on `localhost:8000`. Serves the UI and `/api/*`, keeps one `sharkd` per pcap for full frame dissection |
| `pcapx.py` | Parser, filter language, correlation, graph builder, CLI |
| `graph_template.html` | The UI (also used for static HTML export via `--graph`) |
| `docs/` | Screenshots used in this README |
| `infra_map.svg` / `.png` | Infrastructure map |

Requirements: Python 3.8+, and `tshark`, `sharkd`, `editcap`, `mergecap` (all shipped with the Wireshark packages;
`sudo apt install tshark wireshark-common`). No Python packages needed.

## Run the app

```bash
cd /home/hele/Documents/Claude/whireshark
python3 server.py                     # http://localhost:8000, pcaps from this folder
python3 server.py --dir ~/captures    # pcaps from another folder
python3 server.py --port 8080         # another port
python3 server.py --max-upload-mb 8192  # allow bigger imports (default 2048)
```

Open <http://localhost:8000>, pick a file in the drop-down, type a filter, press the query button.
Stop it with `Ctrl-C` (or `pkill -f server.py` if it runs in the background).

## Import a pcap

**In the UI:** press **Import pcap…** in the toolbar and choose a `.pcap`, `.pcapng` or `.cap` file, or drag the
file anywhere onto the page. A progress readout shows the upload; when it finishes the file is selected in the
drop-down, and you press **Run**.

- The server checks the file header, so a compressed or renamed non-capture is rejected with a message
  (unzip `.gz` files first).
- An existing capture is never overwritten: a second `lab.pcap` is stored as `lab_1.pcap`.
- Uploads stream to disk in 1 MB chunks (a 222 MB trace takes about a second locally and uses no extra memory).
  The default size limit is 2048 MB, change it with `python3 server.py --max-upload-mb 8192`.
- Files land in the server's folder (the project folder, or `--dir`).

You can also put a file into that folder by hand (below). The UI picks it up on the next page load.

### 1. You already have a capture file (Wireshark, tcpdump, a colleague, a bug report)

```bash
cp ~/Downloads/incident.pcapng /home/hele/Documents/Claude/whireshark/
```

Reload the page. The file list is read on page load, so the file shows up without restarting the server.
Files with other extensions (`.pcap.gz`, `.snoop`, `.dmp`, ...) are ignored. Convert or unpack them first:

```bash
gunzip incident.pcap.gz                                    # compressed
editcap -F pcapng weird_format.snoop incident.pcapng       # other formats -> pcapng
```

Names must be plain file names (no sub-folders): the server rejects anything with a `/` in it.

### 2. Capture fresh traffic from the lab

The lab runs in two Docker containers (`corelab-worker`, `corelab-control-plane`). Every 5G pod is on the worker,
and the worker has `tcpdump`. Capturing on interface `any` there sees SBI (HTTP/2), N2 (NGAP), N3 (GTP-U),
N4 (PFCP), MongoDB and the Kubernetes NAT (before/after kube-proxy) in one file.

```bash
cd /home/hele/Documents/Claude/whireshark

# 60 second capture streamed straight to a file on the host
docker exec corelab-worker timeout -s INT 60 tcpdump -i any -s 0 -U -w - > lab_$(date +%Y%m%d_%H%M).pcap
```

- While it runs, generate the traffic you want to look at, for example restart the UE so it registers and opens a
  PDU session: `kubectl -n core rollout restart deploy/ran-ue`.
- Stream to stdout (`-w -`) as above instead of writing a file in the node and using `docker cp`.
  The node's `/tmp` is a tmpfs, and `docker cp` cannot read it (`Could not find the file /tmp/...`).
- Narrow the capture on the wire to keep files small, for example only the 5G control/user-plane protocols:
  `... tcpdump -i any -s 0 -U -w - 'sctp or udp port 8805 or udp port 2152 or tcp port 80' > lab.pcap`.
  Careful: this also drops the MongoDB and DNS traffic.
- `-s 0` keeps full packets. Without it tcpdump may truncate them and HTTP/2 / JSON will not decode.

### 3. Capture from a single pod (optional)

Most NF images have no `tcpdump`, so attach a debug container that shares the pod's network namespace
(standard `kubectl debug` usage, not tried in this lab):

```bash
kubectl -n core debug -it deploy/core-free5gc-smf-smf --image=nicolaka/netshoot --target=smf -- \
  tcpdump -i any -s 0 -U -w - > smf.pcap
```

Use this when you only want one NF's view, which also avoids duplicate "NAT twin" packets.

### 4. Big captures (hundreds of MB)

The first query of a file parses the whole capture and keeps the result in memory (a 222 MB / 330k-packet capture takes
about 15 s). Later queries on the same file and pre-filter are instant. To keep it fast:

- Fill the **pre-filter** box in the UI (or `--pre` on the CLI) with a native Wireshark display filter.
  It is applied by `tshark` before parsing, so it is much cheaper than the pcapx filter:
  `ip.addr==10.60.0.1 or sctp or pfcp or gtp`
- Or cut the file down first:
  ```bash
  editcap -A "2026-09-24 10:11:00" -B "2026-09-24 10:12:00" capture.pcapng slice.pcapng   # time window
  tshark -r capture.pcapng -Y "pfcp or ngap" -w control_plane.pcapng                        # protocols
  ```
- Changing a file (its modification time) invalidates the cache automatically.

### 5. Check the import worked

```bash
python3 pcapx.py lab.pcap --stats        # lists the identities found (imsi, msisdn, teid, seid, ue_id, ...)
capinfos lab.pcap                        # packet count, duration, link type
```

If `--stats` prints nothing, the capture has no subscriber identities. It may be idle traffic, the wrong time window,
or the registration was not captured. Restart the UE during the capture.
Then in the UI select the file and run a first query, for example `imsi=208930000000003`.

## Filter language

`key=value`, `key!=value`, `key~=regex`, joined with `and` / `or`. `*` is a wildcard for `=`.
Identity values are normalised, so `imsi-2089...`, `+49151...` and TBCD digits all compare equal.

```text
imsi=208930000000003
msisdn=4915112345678 and proto~=NGAP|HTTP2
imsi=2089*                       # wildcard
```

Options in the UI (and CLI flags):

| Option | Effect |
|---|---|
| follow (`--follow`) | Grow the match to everything tied to the same subscriber: IMSI → NGAP UE IDs → PFCP SEID → GTP TEID → user-plane packets |
| seq / any-hop (`--seq N --any-hop`) | Find a TCP sequence number, and the same payload elsewhere (NAT, proxy) even when seq or ports differ |
| pre-filter (`--pre`) | Native Wireshark filter applied first (speed) |
| max rows (`--max-rows`) | Limit the diagram (default 300, max 2000) |
| Export (`-w out.pcapng`) | Write the matching packets to a new capture |

CLI examples:

```bash
python3 pcapx.py capture.pcapng --stats
python3 pcapx.py capture.pcapng -f "imsi=208930000000003" --follow
python3 pcapx.py capture.pcapng -f "imsi=208930000000003" --follow --graph flow.html   # standalone HTML
python3 pcapx.py capture.pcapng -f "imsi=2089*" -w out.pcapng
```

## HTTP API (used by the UI)

| Endpoint | Returns |
|---|---|
| `GET /api/files` | Capture files in the folder |
| `GET /api/ids?file=&pre=` | Identities found in the capture |
| `GET /api/query?file=&f=&seq=&hop=1&follow=1&max=&pre=` | Rows and packets for the diagram |
| `GET /api/frame?file=&frame=` | Full protocol tree and hex of one frame (via `sharkd`) |
| `GET /api/export?...` | `filtered.pcapng` download |
| `POST /api/upload?name=x.pcapng` | Import: body is the raw file, header `X-Requested-With: pcapx` required. Returns `{name, mb}` |

The server only binds to `localhost` and has no authentication. Do not expose it. Captures contain subscriber identities.

## The lab

Kubernetes cluster `corelab` (kind, v1.31): `corelab-control-plane` and `corelab-worker`. Namespaces: `core`
(free5GC NFs from release `core`: NRF, AMF, SMF, UPF, AUSF, UDM, UDR, PCF, NSSF, WebUI, MongoDB; RAN from releases
`ran` (gNB + UE) and `ran-cell2` (second gNB)), `monitoring` (Prometheus, Grafana, kube-state-metrics).

| Interface | Network | Endpoints |
|---|---|---|
| SBI (HTTP/2, port 80) | Pod CIDR `10.212.0.0/16`, Service (ClusterIP) CIDR `10.213.0.0/16` | all NFs |
| N2 (NGAP, SCTP 38412) | Multus ipvlan `10.47.60.248/29` | AMF `.249`, gNB (`ran`) `.250`, cell2 gNB (`ran-cell2`) `.251` |
| N3 (GTP-U, UDP 2152) | Multus ipvlan `10.47.60.232/29` | UPF `.233`, cell2 gNB `.234`, gNB `.236` |
| N4 (PFCP, UDP 8805) | Multus ipvlan `10.47.60.240/29` | UPF `.241`, SMF `.244` |
| N9 (ULCL only) | Multus ipvlan `10.47.60.224/29` | |
| N6 | kind node network `corelab-net` `172.29.40.0/24` | UPF `172.29.40.200`, NAT to the internet, UE pool `10.60.0.0/17` (first UE `10.60.0.1`) |

Nodes are `.2` / `.3` on `corelab-net`, gateway `.1`.

Handy access: every Service is ClusterIP (no NodePorts). WebUI, Grafana and Prometheus are reached with
`./scripts/09-open-grafana.sh` from the 5G lab project, which port-forwards to `127.0.0.1` (WebUI `:5000`,
Grafana `:3000`, Prometheus `:9090`).

### Health check

```bash
kubectl -n core get pods                                                   # all Running, no restarts climbing
kubectl -n core logs deploy/ran-ue | grep -E "Registration|PDU Session|uesimtun"
kubectl -n core exec deploy/ran-ue -- ping -c 3 -I uesimtun0 <any-public-host>
```

## Troubleshooting: SMF and UPF in CrashLoopBackOff after a reboot

Seen on 2026-09-24 (the lab had been rebooted the day before).

**Symptoms**

```text
SMF: [ERRO][SMF][PFCP] Failed to listen: listen udp 10.47.60.244:8805: bind: cannot assign requested address
UPF: UPF Cli Run Error: open Gtp5g: open link: listen: listen udp4 10.47.60.233:2152: bind: cannot assign requested address
```

**Cause.** N2, N3, N4 and N6 are secondary interfaces attached by Multus when a pod sandbox is created.
After the host reboot the kubelet recreated the sandboxes with only `eth0` (kindnet); the Multus attach did
not happen. The pods therefore had no `10.47.60.x` address to bind to. Clues: `kubectl exec ... ip addr` shows only
`eth0`, and the pod annotation `k8s.v1.cni.cncf.io/network-status` still lists old addresses. AMF was affected too
(no `n2`), it just did not crash.

**Fix.** Recreate the pods so Multus attaches the interfaces, in this order (core first, RAN after the AMF listens):

```bash
kubectl -n core rollout restart deploy/core-free5gc-upf-upf deploy/core-free5gc-smf-smf deploy/core-free5gc-amf-amf
kubectl -n core rollout status  deploy/core-free5gc-amf-amf
# wait until the AMF log says "Listen on 10.47.60.249:38412", then:
kubectl -n core delete pod -l component=gnb                                # recreated by their deployments, see gotcha below
kubectl -n core rollout restart deploy/ran-ue
```

**Gotchas hit while fixing it**

- **Start order.** gNBs started before the AMF listened, got `SCTP could not connect: Connection refused`, and never
  retried, so the UE saw only barred cells (`Cell selection failure`). Restart the gNBs after the AMF is up.
- **Static IPs and rolling updates.** The gNB / UPF pods use fixed ipvlan addresses. A rolling update starts the new
  pod while the old one still holds the IP, and the new one hangs in `Init` with
  `failed to add IP addr ... address already in use`. Delete the old pod (or use `kubectl rollout undo`), or better set
  `strategy: type: Recreate` on those deployments (in the Helm values, so the change is not lost on upgrade).

**Verify.** `SMF` logs `Received PFCP Association Setup Accepted Response from UPF[10.47.60.241]`, the gNBs log
`NG Setup procedure is successful`, and the UE logs `PDU Session establishment is successful` with `uesimtun0` up.

## Notes and limits

- The correlation is heuristic. A "caused by" link in the diagram means a call started while another call to the same server was still open, not a proven causal chain.
- Only cleartext HTTP/2 (h2c, as in this lab) is decoded. TLS-encrypted SBI needs the keys in Wireshark first.
- A capture on interface `any` shows some packets twice (before and after kube-proxy NAT). pcapx merges them (rows marked `twin`).

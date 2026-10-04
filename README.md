# NetProbe — Portable Network Testing & Traffic Analysis Suite

One folder. Copy it to a USB stick or your laptop, double-click, and you have a
**GUI with one-click shortcut buttons** + **multiple parallel terminal panes** +
**traffic charts** + a **multi-ping comparison graph** + **live monitors** for
mDNS, ARP, HTTP, Wi-Fi, routes and interface errors. Windows, macOS (and Linux).

```
netprobe/
├── netprobe.py        # the whole app (GUI + terminals + graphs + monitors)
├── run.bat            # Windows double-click launcher
├── run.command        # macOS / Linux double-click launcher
├── requirements.txt   # optional: psutil
└── README.md
```

---

## 1. Quick start

**Windows** — install Python 3.8+ from python.org (tick *“Add python.exe to PATH”*),
then double-click **`run.bat`**.

**MacBook** — `brew install python3` (or python.org installer), then
double-click **`run.command`** (first time: right-click → Open).

**Optional but recommended:** `pip install psutil`

---

## 2. The window

| Area | What it does |
|---|---|
| **Top bar** | Target host, ping count, Run / Stop / Clear / Save / Copy |
| **Left sidebar** | Every shortcut button, grouped: QUICK TESTS + TRAFFIC MONITORS, plus a custom-command box and a port field (for the port check) |
| **Terminals tab** | **Multiple terminal panes** — each tab has its own output stream *and its own command line*, so several commands run side by side |
| **Ping Graph tab** | Continuous pings to **many hosts at once**, overlaid on one chart for comparison (per-host avg/min/max/loss, gaps = packet loss, CSV export) |
| **Traffic Monitor** | Live RX/TX charts for multiple interfaces simultaneously |
| **Connection Analyzer** | Every active socket: PID, process, local/remote, state — filter + CSV |
| **Multi-Host Matrix** | Parallel probes over a host list with green/amber/red status |

### Multiple terminals
- **＋ New Terminal** opens another pane (Term 2, Term 3 …), **✕** closes one.
- Each pane has `▶ Run / ■ Stop / Clear / Copy / Save` and its own command line.
- Sidebar buttons run in the **currently visible** pane — switch tabs to route
  output elsewhere. `Run All: Ping` fans one ping out per terminal.
- `Ctrl+Shift+T` jumps to the Terminals tab.

---

## 3. Shortcut keys — QUICK TESTS

| Key | Test | Key | Test |
|---|---|---|---|
| `Ctrl+1` | Ping | `Ctrl+G` | Listening ports |
| `Ctrl+2` | Traceroute | `Ctrl+A` | Protocol statistics (`netstat -s`) |
| `Ctrl+3` | DNS lookup | `Ctrl+I` | IP / geo / ASN info + public IP |
| `Ctrl+4` | HTTP timing breakdown | `Ctrl+V` | Reverse DNS (PTR) |
| `Ctrl+5` | Internet speed test | `Ctrl+Q` | DNS delegation trace |
| `Ctrl+6` | Interface config | `Ctrl+O` | TCP port check (one port, uses the *port* box) |
| `Ctrl+7` | Routing table | `Ctrl+H` | Path MTU discovery |
| `Ctrl+8` | ARP table | `Ctrl+Y` | Gateway / first-hop check |
| `Ctrl+9` | Wi-Fi info | `Ctrl+X` | Internet / captive-portal check |
| `Ctrl+W` | Wi-Fi scan (all APs) | `Ctrl+F` | Flush DNS cache |
| `Ctrl+K` | Active connections | `Ctrl+D` | Full diagnose |
| `Ctrl+L` / `Ctrl+S` | Clear / Save log | `Ctrl+0` | **SUPER diagnose** |
| `F5` | Run current test | | |

## 4. Shortcut keys — TRAFFIC MONITORS

| Key | Monitor | What you see |
|---|---|---|
| `Ctrl+E` | **Ping Graph (compare)** | N hosts pinged in parallel on one latency chart |
| `Ctrl+T` | Traffic charts | Live RX/TX per interface (multi-select) |
| `Ctrl+M` | Host matrix | Parallel probe table over a host list |
| `Ctrl+B` | **mDNS / Bonjour discovery** | LAN services & devices (UDP 5353) |
| `Ctrl+U` | **mDNS traffic monitor** | Passive 30 s mDNS listen — who announces what |
| `Ctrl+R` | **ARP watch** | 60 s neighbour watch: NEW / CHANGED / REMOVED devices |
| `Ctrl+P` | **TCP latency monitor** | 30 s @1 Hz, rolling avg/min/max/loss + sparkline |
| `Ctrl+Shift+P` | **ICMP ping monitor** | 30 s of real pings with loss % |
| `Ctrl+Shift+H` | **HTTP endpoint watch** | 60 s status/TTFB trend + sparkline for one URL |
| `Ctrl+Shift+R` | **Route change watch** | 4 traceroutes, reports path changes |
| `Ctrl+Shift+W` | **Wi-Fi signal watch** | RSSI / signal % trend (falls back to error counters) |
| `Ctrl+Shift+E` | **Error / drop watch** | Per-interface errors & drops delta — bad-cable detector |
| `Ctrl+N` | DNS resolver compare | system vs 1.1.1.1 / 8.8.8.8 / 9.9.9.9 / 223.5.5.5 |
| `Ctrl+J` | Top talkers | Processes ranked by sockets / peers |
| `Ctrl+Shift+T` | Focus Terminals tab | — |

All monitors stop early with **■ Stop Everything** (or the per-pane ■ Stop).

## 5. Shortcut keys — PROFESSIONAL TOOLKIT

| Key | Feature | What you get |
|---|---|---|
| `Ctrl+Shift+C` | **TLS / certificate inspector** | Protocol, cipher, handshake ms, cert subject/issuer/SAN/serial, days-to-expiry (warns < 21 days), full HTTP response headers |
| `Ctrl+Shift+D` | **DNS record browser** | A / AAAA / CNAME / MX / NS / TXT / SOA / CAA with TTL + parsed values (MX preference, SOA serial/refresh/expire) |
| `Ctrl+Shift+L` | **Latency statistics** | 50 samples → min/avg/max/stdev, p50/p90/p95/p99, loss %, histogram |
| `Ctrl+Shift+S` | **TCP state analyzer** | Socket-state distribution + leak/churn alerts (CLOSE_WAIT, SYN_SENT, TIME_WAIT) + retransmit/reset counters from `netstat -s` |
| `Ctrl+Shift+F` | **ECMP / path-flap detector** | 3 traceroutes compared hop-by-hop; flags load-balanced hops and route changes |
| `Ctrl+Shift+A` | **Wi-Fi channel survey** | Nearby APs (SSID/BSSID/channel/signal), per-channel congestion, best of 1/6/11 |
| `Ctrl+Shift+K` | **Link / NIC watch** | 60 s watch for up/down, speed and MTU transitions per interface |
| `Ctrl+Shift+B` | **VPN / split-tunnel report** | Interfaces (VPN-like flagged), routes, DNS servers, public IP, split-tunnel hints |
| `Ctrl+Shift+N` | **Long-run logger** | 10 min of latency + throughput → CSV + summary (p95/loss) for intermittent issues |
| `Ctrl+Shift+O` | **Report generator** | One-click Markdown report: DNS records, latency, HTTP/TLS, local network, verdict hints |


> Note: `Ctrl+A`, `Ctrl+C`, `Ctrl+V` inside a terminal text area still behave as
> select-all / copy / paste there; the shortcut fires when focus is elsewhere.

---

## 6. Terminal-only mode (SSH / scripts)

```bash
python netprobe.py --cli 8.8.8.8                 # quick text diagnostic
python netprobe.py --cli google.com --speed      # include speed test
python netprobe.py --cli --matrix 1.1.1.1 8.8.8.8 google.com
```

## 7. Single portable .exe / .app (optional)

```bash
pip install pyinstaller psutil
pyinstaller --onefile --windowed --name NetProbe netprobe.py
```

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| Traffic chart says “waiting for samples” | Wait 2–3 s; select an interface. Counters come from psutil → PowerShell → `netstat -ib` → `/proc/net/dev`, so it works without extras. |
| No mDNS records | AP “client isolation” blocks multicast; try the same LAN segment, or passive listen (`Ctrl+U`) |
| DNS trace shows SERVFAIL/REFUSED | That resolver blocks the query type upstream — the tool prints the rcode |
| Ping graph gaps | Red dashed lines = packet loss at that probe |
| `command not found: traceroute` (macOS) | `brew install traceroute` |
| Wi-Fi signal “unavailable” on macOS | Use an admin terminal, or rely on the error/drop watch |
| `traceroute` missing on Linux | The tool falls back to `tracepath`; install `traceroute` for full output |
| Long-run CSV location | Written to the app folder as `netprobe-longrun-*.csv` |
| Report file | `netprobe-report-*.md` in the app folder — hand it to the customer / NOC |

---
*NetProbe v1.3 — diagnostics only: ping, traceroute, DNS, HTTP/TLS timing,
statistics and configuration inspection. No port scanning or packet injection.*

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetProbe — Portable Network Testing & Traffic Analysis Suite
============================================================
One portable app for Windows / macOS / Linux laptops:

  * GUI with one-click shortcut buttons for every network test
  * Built-in terminal pane that streams every command's output live
  * Live multi-interface traffic charts (upload / download per NIC)
  * Active connection analyzer (per-process sockets)
  * Multi-host matrix: probe many hosts at once, compare latency/loss
  * Switchable colour themes (8 palettes: dark, light, high-contrast …)
  * Animated UI: typewriter intro, hover effects, spinners, progress bars

No installation needed beyond Python 3.8+.
Optional:  pip install psutil   (richer traffic + connection data)

Run:  python netprobe.py      (or double-click run.bat / run.command)
"""

from __future__ import annotations

import os
import re
import ssl
import sys
import json
import math
import time
import queue
import socket
import platform
import subprocess
import datetime
import urllib.request
import urllib.error
import threading
from collections import deque
from urllib.parse import urlparse

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    HAVE_TK = True
except Exception:  # headless build or python3-tk missing → CLI still works
    HAVE_TK = False

    class _W:
        def __init__(self, *a, **k):
            pass

        def __getattr__(self, n):
            return lambda *a, **k: None

    def _mk(name):
        return type(name, (_W,), {})

    class _NS:
        def __getattr__(self, n):
            return lambda *a, **k: None

    tk = _NS()
    for _n in ("Tk", "Text", "Canvas", "Listbox", "Entry", "Label", "Frame",
               "Button", "Scrollbar", "StringVar", "BooleanVar", "IntVar"):
        setattr(tk, _n, _mk(_n))
    tk.TclError = type("TclError", (Exception,), {})
    ttk = _NS()
    for _n in ("Frame", "Label", "Button", "Scrollbar", "Notebook", "Treeview",
               "Style", "Labelframe"):
        setattr(ttk, _n, _mk(_n))
    filedialog = _NS()
    messagebox = _NS()

try:
    import psutil  # optional
    HAVE_PSUTIL = True
except Exception:
    psutil = None
    HAVE_PSUTIL = False

APP_NAME = "NetProbe"
VERSION = "1.3"
IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
IS_NIX = not IS_WIN and not IS_MAC

# ----------------------------------------------------------------------------
# Theme engine
# ----------------------------------------------------------------------------
# "C" always holds the colours currently on screen.  Switching themes morphs
# every widget smoothly from the old palette to the new one (App.apply_theme).
C = {
    "bg":        "#101418",
    "panel":     "#171d24",
    "panel2":    "#1d252e",
    "border":    "#2b3540",
    "fg":        "#d8dee6",
    "dim":       "#8494a4",
    "accent":    "#37b6ff",
    "ok":        "#57d98a",
    "warn":      "#f2c14e",
    "err":       "#ff6b6b",
    "cmd":       "#7ee0ff",
    "head":      "#9fb2c4",
    "rx":        "#57d98a",
    "tx":        "#f2994a",
}

THEMES = {
    "Midnight": dict(C),
    "Dracula": {
        "bg": "#282a36", "panel": "#21222c", "panel2": "#343746",
        "border": "#44475a", "fg": "#f8f8f2", "dim": "#6272a4",
        "accent": "#bd93f9", "ok": "#50fa7b", "warn": "#f1fa8c",
        "err": "#ff5555", "cmd": "#8be9fd", "head": "#c9cdd8",
        "rx": "#50fa7b", "tx": "#ffb86c",
    },
    "Nord": {
        "bg": "#2e3440", "panel": "#3b4252", "panel2": "#434c5e",
        "border": "#4c566a", "fg": "#eceff4", "dim": "#7b88a1",
        "accent": "#88c0d0", "ok": "#a3be8c", "warn": "#ebcb8b",
        "err": "#bf616a", "cmd": "#8fbcbb", "head": "#d8dee6",
        "rx": "#a3be8c", "tx": "#d08770",
    },
    "Solarized Dark": {
        "bg": "#002b36", "panel": "#073642", "panel2": "#0a4552",
        "border": "#1f5c68", "fg": "#93a1a1", "dim": "#586e75",
        "accent": "#268bd2", "ok": "#859900", "warn": "#b58900",
        "err": "#dc322f", "cmd": "#2aa198", "head": "#839496",
        "rx": "#859900", "tx": "#cb4b16",
    },
    "Monokai": {
        "bg": "#272822", "panel": "#2f3027", "panel2": "#3b3c32",
        "border": "#49483e", "fg": "#f8f8f2", "dim": "#75715e",
        "accent": "#66d9ef", "ok": "#a6e22e", "warn": "#e6db74",
        "err": "#f92672", "cmd": "#a1efe4", "head": "#b8b8b2",
        "rx": "#a6e22e", "tx": "#fd971f",
    },
    "Gruvbox Dark": {
        "bg": "#282828", "panel": "#32302f", "panel2": "#3c3836",
        "border": "#504945", "fg": "#ebdbb2", "dim": "#928374",
        "accent": "#83a598", "ok": "#b8bb26", "warn": "#fabd2f",
        "err": "#fb4934", "cmd": "#8ec07c", "head": "#d5c4a1",
        "rx": "#b8bb26", "tx": "#fe8019",
    },
    "Light": {
        "bg": "#f4f6f8", "panel": "#ffffff", "panel2": "#e8ecf1",
        "border": "#c7d0d9", "fg": "#1c2733", "dim": "#5b6b7a",
        "accent": "#0a66c2", "ok": "#1a7f37", "warn": "#9a6700",
        "err": "#cf222e", "cmd": "#0a66c2", "head": "#334155",
        "rx": "#1a7f37", "tx": "#bc4c00",
    },
    "High Contrast": {
        "bg": "#000000", "panel": "#0a0a0a", "panel2": "#161616",
        "border": "#ffffff", "fg": "#ffffff", "dim": "#d0d0d0",
        "accent": "#00e5ff", "ok": "#00ff85", "warn": "#ffe600",
        "err": "#ff3b3b", "cmd": "#7df9ff", "head": "#e8e8e8",
        "rx": "#00ff85", "tx": "#ffb300",
    },
}
THEME_NAMES = list(THEMES.keys())
DEFAULT_THEME = "Midnight"

MONO = ("Consolas", 10) if IS_WIN else ("Menlo", 11)
UI_FONT = ("Segoe UI", 9) if IS_WIN else ("Helvetica Neue", 12)


# ----------------------------------------------------------------------------
# Colour helpers + animation utilities
# ----------------------------------------------------------------------------
def hex_to_rgb(h):
    h = (h or "").lstrip("#")
    if len(h) != 6:
        return None
    try:
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
    except ValueError:
        return None


def rgb_to_hex(rgb):
    return "#{:02x}{:02x}{:02x}".format(
        *(max(0, min(255, int(round(v)))) for v in rgb))


def lerp_color(a, b, t):
    """Blend colour a towards colour b (t in 0..1).  Unknown names pass through."""
    ra, rb = hex_to_rgb(a), hex_to_rgb(b)
    if ra is None or rb is None:
        return b
    return rgb_to_hex(tuple(ra[i] + (rb[i] - ra[i]) * t for i in range(3)))


def blend(fg, bg, alpha):
    """Composite fg over bg — used for soft chart fills and glows."""
    return lerp_color(bg, fg, max(0.0, min(1.0, alpha)))


def lighter(col, f=0.16):
    return lerp_color(col, "#ffffff", f)


SPIN_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


def render_bar(frac, width=22):
    frac = max(0.0, min(1.0, float(frac)))
    n = int(round(frac * width))
    return "█" * n + "░" * (width - n)


def _theme_config_path():
    try:
        return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "netprobe_theme.json")
    except Exception:
        return "netprobe_theme.json"


def load_theme_name():
    try:
        with open(_theme_config_path(), "r", encoding="utf-8") as f:
            name = json.load(f).get("theme", "")
        return name if name in THEMES else DEFAULT_THEME
    except Exception:
        return DEFAULT_THEME


def save_theme_name(name):
    try:
        with open(_theme_config_path(), "w", encoding="utf-8") as f:
            json.dump({"theme": name}, f)
    except Exception:
        pass


def attach_hover(widget, base_bg, base_fg=None, lift=0.16):
    """Buttons fade to a lighter shade on hover — colours follow the theme."""
    widget._hover_cfg = {"bg": base_bg, "fg": base_fg, "lift": lift}
    state = {"job": None}

    def go(target_bg, target_fg):
        if state["job"] is not None:
            try:
                widget.after_cancel(state["job"])
            except Exception:
                pass
            state["job"] = None
        try:
            start_bg = widget.cget("bg")
            start_fg = widget.cget("fg")
        except Exception:
            return
        steps, ms = 5, 14

        def tick(i=0):
            state["job"] = None
            try:
                if not widget.winfo_exists():
                    return
                t = i / steps
                widget.configure(bg=lerp_color(start_bg, target_bg, t))
                if target_fg:
                    widget.configure(fg=lerp_color(start_fg, target_fg, t))
                if i < steps:
                    state["job"] = widget.after(ms, tick, i + 1)
            except Exception:
                pass

        tick()

    def enter(_e):
        cfg = getattr(widget, "_hover_cfg", {})
        base = cfg.get("bg", base_bg)
        go(lighter(base, cfg.get("lift", 0.16)), cfg.get("fg"))

    def leave(_e):
        cfg = getattr(widget, "_hover_cfg", {})
        go(cfg.get("bg", base_bg), cfg.get("fg"))

    try:
        widget.bind("<Enter>", enter, add="+")
        widget.bind("<Leave>", leave, add="+")
    except Exception:
        pass


def recolor_widget_tree(root, old2new):
    """Translate every colour attribute/tag found under root through old2new."""
    stack = [root]
    while stack:
        w = stack.pop()
        try:
            stack.extend(w.winfo_children())
        except Exception:
            pass
        try:
            if not w.winfo_exists():
                continue
        except Exception:
            continue
        for attr in ("bg", "background", "fg", "foreground", "insertbackground",
                     "activebackground", "activeforeground", "selectbackground",
                     "selectforeground", "highlightbackground", "highlightcolor",
                     "troughcolor", "bordercolor", "arrowcolor", "fieldbackground",
                     "disabledforeground"):
            try:
                cur = w.cget(attr)
            except Exception:
                continue
            if isinstance(cur, str) and cur.lower() in old2new:
                try:
                    w.configure(**{attr: old2new[cur.lower()]})
                except Exception:
                    pass
        # hover-animation base colours ride along with the theme
        cfg = getattr(w, "_hover_cfg", None)
        if isinstance(cfg, dict):
            for k in ("bg", "fg"):
                v = cfg.get(k)
                if isinstance(v, str) and v.lower() in old2new:
                    cfg[k] = old2new[v.lower()]
        # text-widget tags (terminal colours)
        try:
            if hasattr(w, "tag_names"):
                for tag in w.tag_names():
                    try:
                        fg = w.tag_cget(tag, "foreground")
                    except Exception:
                        fg = ""
                    if isinstance(fg, str) and fg.lower() in old2new:
                        try:
                            w.tag_configure(tag, foreground=old2new[fg.lower()])
                        except Exception:
                            pass
        except Exception:
            pass


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def now() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


def fmt_rate(bytes_per_sec: float) -> str:
    b = float(bytes_per_sec)
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if abs(b) < 1024.0:
            return f"{b:6.2f} {unit}"
        b /= 1024.0
    return f"{b:6.2f} TB/s"


def fmt_bytes(n: float) -> str:
    b = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024.0:
            return f"{b:.2f} {unit}"
        b /= 1024.0
    return f"{b:.2f} PB"


def nice_step(x: float) -> float:
    """Nice axis step for chart scaling."""
    if x <= 0:
        return 1.0
    import math
    exp = math.floor(math.log10(x))
    f = x / (10 ** exp)
    for m in (1, 2, 2.5, 5, 10):
        if f <= m:
            return m * (10 ** exp)
    return 10 ** (exp + 1)


# ----------------------------------------------------------------------------
# Host probes (pure sockets — no admin rights required)
# ----------------------------------------------------------------------------
def dns_resolve(host: str, timeout: float = 5.0):
    """Return (addresses, ms) or raise."""
    t0 = time.perf_counter()
    infos = socket.getaddrinfo(host, None)
    ms = (time.perf_counter() - t0) * 1000.0
    addrs = []
    for i in infos:
        a = i[4][0]
        if a not in addrs:
            addrs.append(a)
    return addrs, ms


def tcp_latency(host: str, port: int = 443, timeout: float = 3.0):
    """TCP connect time in ms (works where ICMP is blocked)."""
    t0 = time.perf_counter()
    s = socket.create_connection((host, port), timeout)
    ms = (time.perf_counter() - t0) * 1000.0
    s.close()
    return ms


def http_probe(url: str, timeout: float = 10.0) -> dict:
    """Timing breakdown: DNS / TCP / TLS / TTFB / total + status code."""
    if not re.match(r"^https?://", url or "", re.I):
        url = "http://" + (url or "")
    u = urlparse(url)
    scheme = u.scheme
    host = u.hostname or ""
    port = u.port or (443 if scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    out = {"url": url, "host": host, "port": port}

    try:
        t0 = time.perf_counter()
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        out["dns_ms"] = (time.perf_counter() - t0) * 1000.0
    except Exception as e:
        out["error"] = f"DNS failed: {e}"
        return out

    t1 = time.perf_counter()
    try:
        sock = socket.create_connection((infos[0][4][0], port), timeout)
    except Exception as e:
        out["error"] = f"TCP connect failed: {e}"
        return out
    out["tcp_ms"] = (time.perf_counter() - t1) * 1000.0

    ssock = None
    try:
        if scheme == "https":
            t2 = time.perf_counter()
            ctx = ssl.create_default_context()
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            out["tls_ms"] = (time.perf_counter() - t2) * 1000.0
        else:
            ssock = sock
        ssock.settimeout(timeout)

        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               f"User-Agent: {APP_NAME}/{VERSION}\r\nAccept: */*\r\n"
               f"Connection: close\r\n\r\n")
        t3 = time.perf_counter()
        ssock.sendall(req.encode("latin-1"))
        buf = b""
        first = None
        while len(buf) < 65536:
            chunk = ssock.recv(8192)
            if not chunk:
                break
            if first is None:
                first = time.perf_counter()
            buf += chunk
            if b"\r\n\r\n" in buf and first is not None:
                # headers received; read a little body then stop
                if len(buf) > 16384:
                    break
        total = (time.perf_counter() - t3) * 1000.0
        if first is not None:
            out["ttfb_ms"] = (first - t3) * 1000.0
        out["total_ms"] = total
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
        m = re.match(r"HTTP/\S+\s+(\d{3})", head)
        if m:
            out["status"] = int(m.group(1))
        for line in head.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                if k.strip().lower() in ("server", "content-type", "via", "cf-ray"):
                    out[k.strip().lower()] = v.strip()
    except Exception as e:
        out["error"] = f"HTTP error: {e}"
    finally:
        try:
            if ssock is not None:
                ssock.close()
            else:
                sock.close()
        except Exception:
            pass
    return out


def speed_test(down_bytes: int = 10_000_000, up_bytes: int = 5_000_000,
               timeout: float = 90.0, emit=None, progress=None) -> dict:
    """
    Bandwidth estimate against Cloudflare's public speed endpoint.
    Measures download, upload, latency and jitter. No data is uploaded
    other than anonymous filler bytes.
    progress(frac, label) — optional animated progress callback.
    """
    res = {}
    def say(t):
        if emit:
            emit(t)

    say("  latency samples (1.1.1.1:443) ...")
    lat = []
    for _ in range(5):
        try:
            lat.append(tcp_latency("1.1.1.1", 443, 3.0))
        except Exception:
            pass
        time.sleep(0.12)
    if lat:
        res["latency_ms"] = sum(lat) / len(lat)
        res["jitter_ms"] = max(lat) - min(lat) if len(lat) > 1 else 0.0
        res["latency_min"] = min(lat)
        res["latency_max"] = max(lat)

    say(f"  download {fmt_bytes(down_bytes)} ...")
    t0 = time.perf_counter()
    try:
        req = urllib.request.Request(
            f"https://speed.cloudflare.com/__down?bytes={down_bytes}",
            headers={"User-Agent": f"{APP_NAME}/{VERSION}", "Cache-Control": "no-cache"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            got = 0
            last_ui = 0.0
            while True:
                chunk = r.read(262144)
                if not chunk:
                    break
                got += len(chunk)
                if progress and (time.perf_counter() - last_ui) > 0.15:
                    last_ui = time.perf_counter()
                    progress(min(1.0, got / max(1, down_bytes)),
                             f"downloaded {fmt_bytes(got)} / {fmt_bytes(down_bytes)}")
        dt = time.perf_counter() - t0
        if progress:
            progress(1.0, f"download complete — {fmt_bytes(got)}")
        res["down_bytes"] = got
        res["down_sec"] = dt
        res["down_mbps"] = got * 8 / dt / 1e6
    except Exception as e:
        res["down_error"] = str(e)

    say(f"  upload {fmt_bytes(up_bytes)} ...")
    if progress:
        progress(0.0, f"uploading {fmt_bytes(up_bytes)} …")
    t0 = time.perf_counter()
    try:
        payload = b"\x00" * up_bytes
        req = urllib.request.Request(
            "https://speed.cloudflare.com/__up", data=payload, method="POST",
            headers={"User-Agent": f"{APP_NAME}/{VERSION}", "Content-Type": "application/octet-stream"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read()
        dt = time.perf_counter() - t0
        res["up_bytes"] = up_bytes
        res["up_sec"] = dt
        res["up_mbps"] = up_bytes * 8 / dt / 1e6
        if progress:
            progress(1.0, f"upload complete — {res['up_mbps']:.2f} Mbps")
    except Exception as e:
        res["up_error"] = str(e)
    return res


def parse_ping_output(text: str):
    """Best-effort parse of ping output (EN/CN Windows, BSD/Linux)."""
    out = {}
    m = re.search(r"min/avg/max/\S+\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)", text)  # rtt / round-trip
    if m:
        out["min"] = float(m.group(1))
        out["avg"] = float(m.group(2))
        out["max"] = float(m.group(3))
    m = re.search(r"Minimum\s*=\s*(\d+)\s*ms|最小\s*=\s*(\d+)\s*ms", text, re.I)
    if m:
        out.setdefault("min", float(m.group(1) or m.group(2)))
    m = re.search(r"Average\s*=\s*(\d+)\s*ms|平均\s*=\s*(\d+)\s*ms", text, re.I)
    if m and "avg" not in out:
        out["avg"] = float(m.group(1) or m.group(2))
    m = re.search(r"(\d+)\s*%\s*(?:packet\s*)?loss|丢失\s*=\s*\s*(\d+)\s*\(", text, re.I)
    if m:
        out["loss"] = float(m.group(1) if m.group(1) is not None else m.group(2))
    return out


def probe_host(host: str, attempts: int = 3) -> dict:
    """Parallel-safe multi-host probe: DNS + TCP latency + optional ICMP."""
    r = {"host": host}
    try:
        addrs, dns_ms = dns_resolve(host)
        r["addrs"] = addrs
        r["dns_ms"] = dns_ms
    except Exception as e:
        r["error"] = f"DNS: {e}"
        return r

    samples = []
    loss = 0
    for _ in range(attempts):
        try:
            samples.append(tcp_latency(host, 443, 2.5))
        except Exception:
            try:
                samples.append(tcp_latency(host, 80, 2.5))
            except Exception:
                loss += 1
        time.sleep(0.08)
    if samples:
        r["tcp_min"] = min(samples)
        r["tcp_avg"] = sum(samples) / len(samples)
        r["tcp_max"] = max(samples)
    r["loss"] = 100.0 * loss / max(1, attempts)
    r["samples"] = samples
    return r


# ----------------------------------------------------------------------------
# Per-interface counters without psutil (Windows PowerShell / macOS netstat / proc)
# ----------------------------------------------------------------------------
IFACE_CACHE = {"data": {}, "ts": 0.0}


def iface_counters() -> dict:
    """Return {iface: (rx_bytes, tx_bytes)} using the best source available."""
    out = {}
    if HAVE_PSUTIL:
        try:
            for name, c in psutil.net_io_counters(pernic=True).items():
                out[name] = (c.bytes_recv, c.bytes_sent)
            if out:
                return out
        except Exception:
            pass
    if IS_WIN:
        try:
            ps = ("Get-NetAdapterStatistics | ForEach-Object { "
                  "'{0}|{1}|{2}' -f $_.Name,$_.ReceivedBytes,$_.SentBytes }")
            r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                               capture_output=True, text=True, timeout=12,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            for line in (r.stdout or "").splitlines():
                p = line.strip().split("|")
                if len(p) == 3:
                    try:
                        out[p[0]] = (int(p[1]), int(p[2]))
                    except ValueError:
                        pass
            if out:
                return out
        except Exception:
            pass
    if IS_MAC:
        try:
            r = subprocess.run(["netstat", "-ib"], capture_output=True, text=True, timeout=12)
            header = None
            for line in (r.stdout or "").splitlines():
                p = line.split()
                if line.startswith("Name"):
                    header = p
                    continue
                if not header or len(p) < len(header):
                    continue
                d = dict(zip(header, p))
                if "Name" in d and "Ibytes" in d and "Obytes" in d:
                    try:
                        rx, tx = int(d["Ibytes"]), int(d["Obytes"])
                    except ValueError:
                        continue
                    orx, otx = out.get(d["Name"], (0, 0))
                    out[d["Name"]] = (max(orx, rx), max(otx, tx))
            if out:
                return out
        except Exception:
            pass
    if IS_NIX:
        try:
            with open("/proc/net/dev") as f:
                for line in f.readlines()[2:]:
                    name, rest = line.split(":", 1)
                    v = rest.split()
                    out[name.strip()] = (int(v[0]), int(v[8]))
            if out:
                return out
        except Exception:
            pass
    return out


def iface_rate_fallback() -> dict:
    """Delta-based rates from iface_counters() — used when psutil is absent."""
    cur = iface_counters()
    ts = time.time()
    prev = IFACE_CACHE["data"]
    pt = IFACE_CACHE["ts"]
    rates = {}
    dt = max(0.001, ts - pt) if pt else 0
    for name, (rx, tx) in cur.items():
        if name in prev and dt:
            lrx, ltx = prev[name]
            rates[name] = (max(0.0, (rx - lrx) / dt), max(0.0, (tx - ltx) / dt))
        else:
            rates[name] = (0.0, 0.0)
    IFACE_CACHE["data"], IFACE_CACHE["ts"] = cur, ts
    return rates


# ----------------------------------------------------------------------------
# mDNS / ARP / DNS / listening-port monitors
# ----------------------------------------------------------------------------
MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353


def _dns_name(data: bytes, off: int):
    labels = []
    jumped = False
    end = off
    guard = 0
    while guard < 64:
        guard += 1
        if off >= len(data):
            break
        l = data[off]
        if l == 0:
            if not jumped:
                end = off + 1
            break
        if l & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                break
            ptr = ((l & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
                jumped = True
            off = ptr
            continue
        labels.append(data[off + 1:off + 1 + l].decode("utf-8", "replace"))
        off += 1 + l
        if not jumped:
            end = off
    return ".".join(labels), end


def build_dns_query(questions, tid: int = 0) -> bytes:
    import struct
    hdr = struct.pack(">HHHHHH", tid & 0xFFFF, 0, len(questions), 0, 0, 0)
    body = b""
    for name, qtype in questions:
        for part in str(name).strip(".").split("."):
            b = part.encode("utf-8", "replace")
            body += bytes([len(b)]) + b
        body += b"\x00" + struct.pack(">HH", qtype, 1)
    return hdr + body


def parse_dns_message(data: bytes) -> dict:
    import struct
    out = {"questions": [], "answers": [], "rcode": None}
    if len(data) < 12:
        return out
    _tid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    out["rcode"] = flags & 0x000F
    off = 12
    for _ in range(qd):
        name, off = _dns_name(data, off)
        if off + 4 > len(data):
            return out
        qtype, _qclass = struct.unpack(">HH", data[off:off + 4])
        off += 4
        out["questions"].append((name, qtype))
    for _ in range(an + ns + ar):
        name, off = _dns_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        rstart = off
        off += rdlen
        val = ""
        try:
            if rtype == 1 and rdlen == 4:
                val = socket.inet_ntoa(rdata)
            elif rtype == 28 and rdlen == 16:
                val = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype in (12, 2, 5, 33):            # PTR / NS / CNAME / SRV target
                val = _dns_name(data, rstart)[0]
            elif rtype == 16:                         # TXT
                chunks, i = [], 0
                while i < len(rdata):
                    ln = rdata[i]
                    chunks.append(rdata[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                    i += 1 + ln
                val = " | ".join(c for c in chunks if c)
            else:
                val = rdata.hex()
        except Exception:
            val = rdata.hex()
        out["answers"].append((name, rtype, ttl, val))
    return out


def _mdns_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
    try:
        sock.bind(("", MDNS_PORT))
    except Exception:
        sock.bind(("", 0))
    try:
        mreq = socket.inet_aton(MDNS_ADDR) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except Exception:
        pass
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    except Exception:
        pass
    sock.settimeout(0.5)
    return sock


MDNS_SERVICES = [
    "_services._dns-sd._udp.local", "_http._tcp.local", "_https._tcp.local",
    "_smb._tcp.local", "_ssh._tcp.local", "_afpovertcp._tcp.local",
    "_airplay._tcp.local", "_raop._tcp.local", "_companion-link._tcp.local",
    "_workstation._tcp.local", "_ipp._tcp.local", "_googlecast._tcp.local",
    "_spotify-connect._tcp.local", "_hap._tcp.local",
]


def mdns_discover(emit, timeout: float = 6.0, listen_only: bool = False,
                  duration: float = 0.0, stop=None) -> dict:
    """Discover / monitor mDNS-Bonjour traffic on the LAN (UDP 5353)."""
    sock = _mdns_socket()
    seen = {}
    end = time.time() + (duration if listen_only else timeout)
    last_query = 0.0
    try:
        while time.time() < end:
            if stop is not None and stop.is_set():
                break
            if not listen_only or time.time() - last_query > 8:
                try:
                    sock.sendto(build_dns_query([(s, 12) for s in MDNS_SERVICES]),
                                (MDNS_ADDR, MDNS_PORT))
                    last_query = time.time()
                except Exception:
                    pass
            try:
                data, addr = sock.recvfrom(9000)
            except socket.timeout:
                continue
            except Exception:
                break
            pkt = parse_dns_message(data)
            for name, rtype, ttl, val in pkt.get("answers", []):
                key = (name, rtype, val)
                if key in seen:
                    continue
                seen[key] = addr[0]
                tname = {1: "A", 12: "PTR", 16: "TXT", 28: "AAAA", 33: "SRV"}.get(rtype, str(rtype))
                emit(f"  {addr[0]:16s} {tname:<4} ttl={ttl:<5} {name}  ->  {val}")
    finally:
        sock.close()
    return seen


def arp_entries() -> dict:
    """Return {ip: (mac, iface)} from the local ARP/neighbour cache."""
    out = {}
    if IS_NIX and os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    p = line.split()
                    if len(p) >= 4 and p[3] != "00:00:00:00:00:00":
                        out[p[0]] = (p[3], p[5] if len(p) > 5 else "")
            return out
        except Exception:
            pass
    try:
        r = subprocess.run(cmd_arp(), capture_output=True, text=True, timeout=12,
                           **{k: v for k, v in popen_kwargs().items() if k == "creationflags"})
        for line in (r.stdout or "").splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{12,17})\s+(\S+)", line)
            if m:
                out[m.group(1)] = (m.group(2), m.group(3))
    except Exception:
        pass
    return out


def arp_watch(emit, duration: float = 60.0, interval: float = 2.0, stop=None) -> dict:
    """Watch the ARP cache — logs new / changed / removed neighbours."""
    base = arp_entries()
    emit(f"  baseline: {len(base)} neighbours")
    for ip, (mac, iface) in sorted(base.items()):
        emit(f"    {ip:16s} {mac:20s} {iface}")
    changes = {"added": [], "removed": [], "changed": []}
    end = time.time() + duration
    while time.time() < end:
        if stop is not None and stop.is_set():
            break
        time.sleep(interval)
        cur = arp_entries()
        for ip, v in cur.items():
            if ip not in base:
                changes["added"].append((ip, v))
                emit(f"  [+{now()}] NEW       {ip:16s} {v[0]:20s} {v[1]}")
            elif base[ip][0] != v[0]:
                changes["changed"].append((ip, v))
                emit(f"  [~{now()}] CHANGED   {ip:16s} {base[ip][0]} -> {v[0]}")
        for ip in base:
            if ip not in cur:
                changes["removed"].append(ip)
                emit(f"  [-{now()}] REMOVED   {ip:16s} {base[ip][0]}")
        base = cur
    return changes


def dns_query(server: str, name: str, qtype: int = 1, timeout: float = 3.0):
    """Direct DNS query to a specific resolver. Returns (ms, parsed_message)."""
    import random
    msg = build_dns_query([(name, qtype)], tid=random.randint(0, 65535))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    data = b""
    try:
        t0 = time.perf_counter()
        s.sendto(msg, (server, 53))
        data, _ = s.recvfrom(4096)
        ms = (time.perf_counter() - t0) * 1000.0
    finally:
        s.close()
    return ms, parse_dns_message(data)


def dns_compare(emit, name: str, resolvers=None) -> list:
    """Compare system resolver vs public resolvers (latency + answers)."""
    resolvers = resolvers or ["1.1.1.1", "8.8.8.8", "9.9.9.9", "223.5.5.5"]
    rows = []
    t0 = time.perf_counter()
    try:
        addrs = socket.getaddrinfo(name, None)
        sys_ms = (time.perf_counter() - t0) * 1000.0
        uniq = []
        for i in addrs:
            if i[4][0] not in uniq:
                uniq.append(i[4][0])
        rows.append(("system", sys_ms, len(uniq), ", ".join(uniq[:3])))
        emit(f"  system resolver : {sys_ms:7.1f} ms   {len(uniq)} answer(s)  {', '.join(uniq[:3])}")
    except Exception as e:
        rows.append(("system", None, 0, str(e)))
        emit(f"  system resolver : FAILED — {e}")
    for srv in resolvers:
        try:
            ms, pkt = dns_query(srv, name)
            ans = [a[3] for a in pkt.get("answers", []) if a[1] in (1, 28)]
            rc = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                  4: "NOTIMP", 5: "REFUSED"}.get(pkt.get("rcode"),
                                                   f"rcode {pkt.get('rcode')}")
            extra = f"  [{rc}]" if not ans else ""
            rows.append((srv, ms, len(ans), ", ".join(ans[:3])))
            emit(f"  {srv:15s} : {ms:7.1f} ms   {len(ans)} answer(s)  "
                 f"{', '.join(ans[:3])}{extra}")
        except Exception as e:
            rows.append((srv, None, 0, str(e)))
            emit(f"  {srv:15s} : FAILED — {e}")
    return rows


def latency_monitor(emit, host: str, seconds: float = 30.0, interval: float = 1.0,
                    port: int = 443, stop=None):
    """Continuous latency monitor with a terminal sparkline."""
    spark = "▁▂▃▄▅▆▇█"
    vals = []
    fails = 0
    end = time.time() + seconds
    emit(f"  monitoring {host}:{port} every {interval:.0f}s for {seconds:.0f}s")
    while time.time() < end:
        if stop is not None and stop.is_set():
            break
        try:
            ms = tcp_latency(host, port, 3.0)
            vals.append(ms)
        except Exception:
            vals.append(None)
            fails += 1
        shown = vals[-50:]
        ok = [v for v in shown if v is not None]
        bar = ""
        if ok:
            hi = max(ok) or 1.0
            for v in shown:
                bar += "·" if v is None else spark[min(7, int(v / hi * 7.999))]
            last_txt = f"{shown[-1]:7.1f}" if shown[-1] is not None else " timeout"
            line = (f"  [{now()}] last {last_txt} ms | "
                    f"avg {sum(ok)/len(ok):6.1f} | min {min(ok):6.1f} | max {max(ok):6.1f} | "
                    f"loss {100.0*fails/len(shown):3.0f}% | {bar}")
        else:
            line = f"  [{now()}] all probes failing (host unreachable or port {port} closed)"
        emit(line)
        time.sleep(interval)
    if vals:
        ok = [v for v in vals if v is not None]
        emit(f"  summary: {len(ok)}/{len(vals)} ok, "
             f"avg {sum(ok)/len(ok) if ok else 0:.1f} ms, "
             f"min {min(ok) if ok else 0:.1f}, max {max(ok) if ok else 0:.1f}, "
             f"loss {100.0*fails/max(1,len(vals)):.0f}%")
    return vals


def listening_ports() -> list:
    """Local listening sockets (own machine config, not a scan)."""
    rows = []
    if HAVE_PSUTIL:
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == "LISTEN" or (c.type.name == "SOCK_DGRAM" and not c.raddr):
                    name = ""
                    try:
                        if c.pid:
                            name = psutil.Process(c.pid).name()
                    except Exception:
                        pass
                    proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
                    rows.append((c.pid or "-", name, proto,
                                 f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "", c.status or "UDP"))
            return rows
        except Exception:
            pass
    try:
        r = subprocess.run(cmd_netstat(), capture_output=True, text=True, timeout=20,
                           **{k: v for k, v in popen_kwargs().items() if k == "creationflags"})
        for line in (r.stdout or "").splitlines():
            p = line.split()
            if len(p) >= 4 and ("LISTEN" in line.upper() or p[0].lower().startswith("udp")):
                rows.append((p[-1] if p[-1].isdigit() else "-", "-", p[0], p[1], p[3] if len(p) > 4 else ""))
    except Exception:
        pass
    return rows


def top_talkers(limit: int = 15) -> list:
    """Processes ranked by number of open/active sockets."""
    if not HAVE_PSUTIL:
        return []
    agg = {}
    try:
        for c in psutil.net_connections(kind="inet"):
            pid = c.pid or 0
            try:
                name = psutil.Process(pid).name() if pid else "system"
            except Exception:
                name = f"pid {pid}"
            key = (pid, name)
            d = agg.setdefault(key, {"n": 0, "est": 0, "remotes": set(), "rx": 0, "tx": 0})
            d["n"] += 1
            if c.status == "ESTABLISHED":
                d["est"] += 1
            if c.raddr:
                d["remotes"].add(c.raddr.ip)
        for (pid, name), d in agg.items():
            try:
                io = psutil.Process(pid).io_counters()
                d["rx"], d["tx"] = io.read_bytes, io.write_bytes
            except Exception:
                pass
    except Exception:
        return []
    rows = sorted(agg.items(), key=lambda kv: kv[1]["n"], reverse=True)[:limit]
    return [(pid, name, d["n"], d["est"], len(d["remotes"]),
             ", ".join(sorted(d["remotes"])[:3])) for (pid, name), d in rows]


def probe_latency(host: str, port=None, timeout: float = 2.5):
    """Latency in ms, or None on failure. Tries 443 then 80 when no port given."""
    ports = [port] if port else [443, 80]
    for p in ports:
        try:
            return tcp_latency(host, p, timeout)
        except Exception:
            continue
    return None


def port_check(host: str, port: int, timeout: float = 5.0) -> dict:
    """Single-port TCP connectivity test (diagnosis of one service — not a scan)."""
    out = {"host": host, "port": port}
    try:
        addrs, dns_ms = dns_resolve(host)
        out["addrs"] = addrs
        out["dns_ms"] = dns_ms
    except Exception as e:
        out["error"] = f"DNS: {e}"
        return out
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((host, port), timeout)
        out["ms"] = (time.perf_counter() - t0) * 1000.0
        out["local"] = f"{s.getsockname()[0]}:{s.getsockname()[1]}"
        out["peer"] = f"{s.getpeername()[0]}:{s.getpeername()[1]}"
        try:
            s.settimeout(1.0)
            out["peer_name"] = s.getpeername()[0]
        except Exception:
            pass
        s.close()
        out["status"] = "OPEN — TCP handshake succeeded"
    except Exception as e:
        out["error"] = f"closed/filtered: {e}"
    return out


def mtu_probe(host: str, low: int = 576, high: int = 1500, timeout: float = 2.0) -> dict:
    """Path MTU estimate via don't-fragment ping binary search."""
    kw = {k: v for k, v in popen_kwargs().items() if k == "creationflags"}

    def ok(size: int) -> bool:
        if IS_WIN:
            cmd = ["ping", "-f", "-l", str(size), "-n", "1", "-w", str(int(timeout * 1000)), host]
        elif IS_MAC:
            cmd = ["ping", "-D", "-s", str(size), "-c", "1", "-W", str(int(timeout * 1000)), host]
        else:
            cmd = ["ping", "-M", "do", "-s", str(size), "-c", "1", "-W", str(int(timeout)), host]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 6, **kw)
            return r.returncode == 0
        except Exception:
            return False

    best = None
    probes = 0
    while low <= high:
        mid = (low + high) // 2
        probes += 1
        if ok(mid):
            best = mid
            low = mid + 1
        else:
            high = mid - 1
    return {"host": host, "max_payload": best,
            "mtu": (best + 28) if best is not None else None, "probes": probes}


def dns_trace(name: str, emit, resolver: str = "1.1.1.1"):
    """Walk the NS delegation chain from the TLD down to the A record."""
    parts = name.strip(".").split(".")
    for i in range(len(parts) - 1, 0, -1):
        zone = ".".join(parts[i:])
        try:
            ms, pkt = dns_query(resolver, zone, qtype=2)
            ns = [a[3] for a in pkt.get("answers", []) if a[1] == 2]
            rc = {0: "", 2: "  [SERVFAIL]", 5: "  [REFUSED]"}.get(pkt.get("rcode"),
                                                                     f"  [rcode {pkt.get('rcode')}]")
            emit(f"  {zone:32s} NS  {ms:7.1f} ms   "
                 f"{', '.join(ns) if ns else ('-' + rc)}")
        except Exception as e:
            emit(f"  {zone:32s} NS  query failed: {e}")
    try:
        ms, pkt = dns_query(resolver, name, qtype=1)
        ips = [a[3] for a in pkt.get("answers", []) if a[1] in (1, 28)]
        emit(f"  {name:32s} A   {ms:7.1f} ms   {', '.join(ips) if ips else '-'}")
    except Exception as e:
        emit(f"  {name:32s} A   query failed: {e}")


def reverse_dns(target: str):
    t0 = time.perf_counter()
    try:
        name = socket.gethostbyaddr(target)[0]
    except Exception:
        infos = socket.getaddrinfo(target, None)
        name = socket.gethostbyaddr(infos[0][4][0])[0]
    return name, (time.perf_counter() - t0) * 1000.0


def public_ip(timeout: float = 8.0) -> str:
    for url in ("https://www.cloudflare.com/cdn-cgi/trace", "https://api.ipify.org"):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                body = r.read(4096).decode("utf-8", "replace")
            m = re.search(r"(?:^|\n)ip=([^\s]+)", body)
            if m:
                return m.group(1)
            if re.match(r"^[\d.:a-f]+$", body.strip()):
                return body.strip()
        except Exception:
            continue
    return "unknown"


def ip_info(target: str, timeout: float = 8.0) -> dict:
    """Geo / ASN / ISP lookup for a host or IP (public ip-api.com endpoint)."""
    out = {"target": target}
    try:
        addrs, _ms = dns_resolve(target)
        out["ip"] = addrs[0]
    except Exception as e:
        out["error"] = f"DNS: {e}"
        return out
    try:
        url = (f"http://ip-api.com/json/{out['ip']}?fields=status,message,country,"
               f"regionName,city,isp,org,as,query,timezone")
        with urllib.request.urlopen(url, timeout=timeout) as r:
            import json
            data = json.loads(r.read(4096).decode("utf-8", "replace"))
        if data.get("status") == "success":
            out.update({k: data.get(k, "") for k in
                        ("country", "regionName", "city", "isp", "org", "as", "timezone")})
        else:
            out["error"] = data.get("message", "lookup failed")
    except Exception as e:
        out["error"] = str(e)
    return out


def icmp_ping_once(host: str, timeout: float = 3.0):
    """One ICMP ping — returns ms or None. Best-effort multilingual parse."""
    try:
        r = subprocess.run(cmd_ping(host, 1), capture_output=True, text=True,
                           timeout=timeout + 5,
                           **{k: v for k, v in popen_kwargs().items() if k == "creationflags"})
        txt = r.stdout or ""
        m = re.search(r"time\s*[=<]\s*([\d.]+)", txt, re.I)
        if not m:
            m = re.search(r"(?:时间|temps|Zeit)\s*[=<]\s*([\d.]+)", txt, re.I)
        if not m:
            m = re.search(r"([\d.]+)\s*ms", txt)
        return float(m.group(1)) if m else None
    except Exception:
        return None


def default_gateway():
    """(gateway_ip, iface) parsed from the routing table."""
    try:
        r = subprocess.run(cmd_routes(), capture_output=True, text=True, timeout=15,
                           **{k: v for k, v in popen_kwargs().items() if k == "creationflags"})
        for line in (r.stdout or "").splitlines():
            p = line.split()
            if not p:
                continue
            if p[0] in ("0.0.0.0", "default", "Default"):
                for tok in p[1:]:
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", tok) and not tok.endswith(".0.0.0"):
                        return tok, (p[-1] if len(p) > 2 else "")
    except Exception:
        pass
    return None, ""


def internet_check(emit, timeout: float = 8.0) -> list:
    """Probe several reachability endpoints — detects captive portals / partial egress."""
    targets = [
        ("http://connectivitycheck.gstatic.com/generate_204", 204),
        ("http://captive.apple.com/hotspot-detect.html", 200),
        ("https://www.cloudflare.com/cdn-cgi/trace", 200),
        ("https://example.com", 200),
    ]
    rows = []
    for url, expect in targets:
        r = http_probe(url, timeout=timeout)
        got = r.get("status")
        ok = (got == expect)
        verdict = "OK" if ok else ("CAPTIVE-PORTAL?" if got in (301, 302, 307) else
                                   ("FAIL" if got is None else "unexpected"))
        rows.append((url, expect, got, r.get("total_ms"), verdict))
        emit(f"  {url[:52]:52s} expect {expect}  got {str(got):>5}  "
             f"{r.get('total_ms', 0) or 0:7.1f} ms  {verdict}")
    return rows


def iface_errors() -> dict:
    """{iface: (errin, errout, dropin, dropout)} counters."""
    out = {}
    if HAVE_PSUTIL:
        try:
            for name, c in psutil.net_io_counters(pernic=True).items():
                out[name] = (c.errin, c.errout, c.dropin, c.dropout)
            if out:
                return out
        except Exception:
            pass
    if IS_WIN:
        try:
            ps = ("Get-NetAdapterStatistics | ForEach-Object { "
                  "'{0}|{1}|{2}|{3}|{4}' -f $_.Name,$_.ReceivedPacketErrors,"
                  "$_.OutboundPacketErrors,$_.ReceivedDiscardedPackets,"
                  "$_.OutboundDiscardedPackets }")
            r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                               capture_output=True, text=True, timeout=12,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            for line in (r.stdout or "").splitlines():
                p = line.strip().split("|")
                if len(p) == 5:
                    try:
                        out[p[0]] = tuple(int(x or 0) for x in p[1:])
                    except ValueError:
                        pass
            if out:
                return out
        except Exception:
            pass
    if IS_MAC:
        try:
            r = subprocess.run(["netstat", "-ib"], capture_output=True, text=True, timeout=12)
            header = None
            for line in (r.stdout or "").splitlines():
                p = line.split()
                if line.startswith("Name"):
                    header = p
                    continue
                if not header or len(p) < len(header):
                    continue
                d = dict(zip(header, p))
                def gi(k):
                    try:
                        return int(d.get(k, 0))
                    except ValueError:
                        return 0
                if "Name" in d:
                    out[d["Name"]] = (gi("Ierrs"), gi("Oerrs"), gi("Idrops"), gi("Odrops"))
            if out:
                return out
        except Exception:
            pass
    if IS_NIX:
        try:
            with open("/proc/net/dev") as f:
                for line in f.readlines()[2:]:
                    name, rest = line.split(":", 1)
                    v = rest.split()
                    out[name.strip()] = (int(v[2]), int(v[10]), int(v[3]), int(v[11]))
        except Exception:
            pass
    return out


def wifi_signal_watch(emit, seconds: float = 30.0, interval: float = 3.0, stop=None):
    """Poll Wi-Fi signal / errors per interface; portable best-effort."""
    emit("  (signal info: Windows netsh / macOS airport / Linux nmcli — falls back to error counters)")
    end = time.time() + seconds
    while time.time() < end:
        if stop is not None and stop.is_set():
            break
        line = ""
        try:
            if IS_WIN:
                r = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                                   capture_output=True, text=True, timeout=8,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                txt = r.stdout or ""
                ssid = re.search(r"SSID\s*:\s*(.+)", txt)
                sig = re.search(r"Signal\s*:\s*(\d+)%", txt)
                rate = re.search(r"Receive rate \(Mbps\)\s*:\s*([\d.]+)", txt)
                chan = re.search(r"Channel\s*:\s*(\d+)", txt)
                line = (f"  [{now()}] SSID {ssid.group(1).strip() if ssid else '-'}  "
                        f"signal {sig.group(1) + '%' if sig else '-'}  "
                        f"rx {rate.group(1) if rate else '-'} Mbps  "
                        f"ch {chan.group(1) if chan else '-'}")
            elif IS_MAC:
                airport = ("/System/Library/PrivateFrameworks/Apple80211.framework/"
                           "Versions/Current/Resources/airport")
                if os.path.exists(airport):
                    r = subprocess.run([airport, "-I"], capture_output=True, text=True, timeout=8)
                    txt = r.stdout or ""
                    ssid = re.search(r"SSID\s*:\s*(.+)", txt)
                    agr = re.search(r"agrCtlRSSI\s*:\s*(-?\d+)", txt)
                    line = f"  [{now()}] SSID {ssid.group(1).strip() if ssid else '-'}  RSSI {agr.group(1) if agr else '-'} dBm"
            else:
                r = subprocess.run(["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL", "dev", "wifi"],
                                   capture_output=True, text=True, timeout=8)
                for row in (r.stdout or "").splitlines():
                    if row.startswith("*"):
                        p = row.split(":")
                        line = f"  [{now()}] SSID {p[1] if len(p) > 1 else '-'}  signal {p[2] if len(p) > 2 else '-'}%"
        except Exception:
            pass
        if not line:
            errs = iface_errors()
            bits = []
            for n, (ei, eo, di, do) in list(errs.items())[:4]:
                if ei or eo or di or do:
                    bits.append(f"{n}: err {ei}/{eo} drop {di}/{do}")
            line = f"  [{now()}] Wi-Fi signal unavailable — errors/drops: {', '.join(bits) or 'clean'}"
        emit(line)
        time.sleep(interval)


def interface_error_watch(emit, seconds: float = 60.0, interval: float = 5.0, stop=None):
    """Watch interface error/drop counters — the classic 'bad cable/roaming' detector."""
    prev = iface_errors()
    emit(f"  baseline: {len(prev)} interfaces")
    end = time.time() + seconds
    while time.time() < end:
        if stop is not None and stop.is_set():
            break
        time.sleep(interval)
        cur = iface_errors()
        for name, v in cur.items():
            if name in prev:
                d = [v[i] - prev[name][i] for i in range(4)]
                if any(x > 0 for x in d):
                    emit(f"  [{now()}] {name}: +errors rx/tx {d[0]}/{d[1]}  +drops rx/tx {d[2]}/{d[3]}")
        prev = cur
    emit(f"  [{now()}] error/drop watch finished")


def http_watch(emit, url: str, seconds: float = 60.0, interval: float = 5.0, stop=None):
    """Watch one HTTP endpoint: status + TTFB/total trend + sparkline."""
    spark = "▁▂▃▄▅▆▇█"
    if not re.match(r"^https?://", url or "", re.I):
        url = "https://" + (url or "")
    vals = []
    fails = 0
    end = time.time() + seconds
    emit(f"  watching {url} every {interval:.0f}s for {seconds:.0f}s")
    while time.time() < end:
        if stop is not None and stop.is_set():
            break
        r = http_probe(url, timeout=8.0)
        if r.get("error"):
            fails += 1
            vals.append(None)
            emit(f"  [{now()}] ERROR {r['error']}")
        else:
            vals.append(r.get("total_ms", 0.0))
            shown = [v for v in vals[-40:] if v is not None]
            hi = max(shown) or 1.0
            bar = "".join("·" if v is None else spark[min(7, int(v / hi * 7.999))] for v in vals[-40:])
            emit(f"  [{now()}] status {r.get('status')}  total {r.get('total_ms', 0):7.1f} ms  "
                 f"ttfb {r.get('ttfb_ms', 0):7.1f} ms  | {bar}")
        time.sleep(interval)
    ok = [v for v in vals if v is not None]
    emit(f"  summary: {len(ok)}/{len(vals)} ok, avg "
         f"{sum(ok)/len(ok) if ok else 0:.1f} ms, fail {fails}")


def route_watch(emit, host: str, rounds: int = 4, interval: float = 25.0, stop=None):
    """Run traceroute periodically and report path changes."""
    prev = None
    for i in range(rounds):
        if stop is not None and stop.is_set():
            break
        emit(f"  ── round {i + 1}/{rounds} at {now()} ──")
        hops = []
        try:
            r = subprocess.run(cmd_trace(host), capture_output=True, text=True, timeout=90,
                               **{k: v for k, v in popen_kwargs().items() if k == "creationflags"})
            for line in (r.stdout or "").splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    hops.append(m.group(1))
            emit(f"  path: {' -> '.join(hops[:12]) if hops else '(no hops parsed)'}")
        except Exception as e:
            emit(f"  traceroute failed: {e}")
        if prev is not None and hops and hops != prev:
            diff = [(a, b) for a, b in zip(prev, hops) if a != b]
            emit(f"  ⚠ PATH CHANGED — {len(diff)} hop difference(s)")
        prev = hops or prev
        if i < rounds - 1:
            time.sleep(interval)


# ----------------------------------------------------------------------------
# Cross-platform command builders
# ----------------------------------------------------------------------------
def popen_kwargs() -> dict:
    kw = dict(stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
              text=True, encoding="utf-8", errors="replace", bufsize=1)
    if IS_WIN:
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return kw


def cmd_ping(host: str, count: int = 4) -> list:
    if IS_WIN:
        return ["ping", "-n", str(count), "-w", "2000", host]
    if IS_MAC:
        return ["ping", "-c", str(count), "-W", "2000", host]
    return ["ping", "-c", str(count), "-W", "2", host]


def cmd_trace(host: str) -> list:
    if IS_WIN:
        return ["tracert", "-d", "-h", "30", "-w", "2000", host]
    return ["traceroute", "-n", "-m", "30", "-q", "1", host]


def cmd_dns(host: str) -> list:
    return ["nslookup", host]


def cmd_interfaces() -> list:
    if IS_WIN:
        return ["ipconfig", "/all"]
    if IS_MAC:
        return ["ifconfig", "-a"]
    return ["ip", "addr"] if shutil_which("ip") else ["ifconfig", "-a"]


def cmd_routes() -> list:
    if IS_WIN:
        return ["route", "print"]
    return ["netstat", "-rn"]


def cmd_arp() -> list:
    return ["arp", "-a"]


def cmd_netstat() -> list:
    return ["netstat", "-ano"] if IS_WIN else ["netstat", "-an"]


def cmd_wifi() -> list:
    if IS_WIN:
        return ["netsh", "wlan", "show", "interfaces"]
    if IS_MAC:
        return ["system_profiler", "SPAirPortDataType"]
    return ["nmcli", "dev", "show"] if shutil_which("nmcli") else ["iwconfig"]


def cmd_wifi_scan() -> list:
    if IS_WIN:
        return ["netsh", "wlan", "show", "networks", "mode=bssid"]
    if IS_MAC:
        return ["system_profiler", "SPAirPortDataType"]
    return ["nmcli", "dev", "wifi", "list"] if shutil_which("nmcli") else ["iwlist", "scan"]


def cmd_flush_dns() -> list:
    if IS_WIN:
        return ["ipconfig", "/flushdns"]
    if IS_MAC:
        return ["dscacheutil", "-flushcache"]
    return ["resolvectl", "flush-caches"] if shutil_which("resolvectl") else ["nscd", "--invalidate=hosts"]


def cmd_dns_cache_info() -> list:
    if IS_WIN:
        return ["ipconfig", "/displaydns"]
    return ["scutil", "--dns"] if IS_MAC else ["resolvectl", "statistics"]


def shutil_which(x: str):
    from shutil import which
    return which(x)


# ----------------------------------------------------------------------------
# Protocol Lab — per-protocol tests grouped by OSI layer
# ----------------------------------------------------------------------------
# Every test has the signature  fn(host, emit, stop) -> (status, summary)
#   status ∈ "PASS" | "WARN" | "FAIL" | "INFO"
#   emit(line, tag) writes a detail line (tag: head/ok/warn/err/info/title)

def _short_host(host: str) -> str:
    h = (host or "").strip()
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", h)
    if m:
        h = h[m.end():]
    h = h.split("/")[0].split("?")[0]
    if h.startswith("["):
        h = h[1:].split("]")[0]
    elif h.count(":") == 1:
        h = h.split(":")[0]
    return h or "8.8.8.8"


def _is_ip(addr: str) -> bool:
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, addr)
            return True
        except OSError:
            pass
    return False


def _local_mac() -> bytes:
    if IS_NIX and os.path.isdir("/sys/class/net"):
        try:
            for name in sorted(os.listdir("/sys/class/net")):
                if name == "lo":
                    continue
                with open(f"/sys/class/net/{name}/address") as f:
                    mac = f.read().strip()
                if mac and mac != "00:00:00:00:00:00":
                    return bytes(int(x, 16) for x in mac.split(":"))
        except Exception:
            pass
    import uuid
    return int(uuid.getnode()).to_bytes(6, "big")


def _run_parallel(fns, timeout=6.0):
    """Run probe callables concurrently — results come back in input order."""
    results = [None] * len(fns)

    def wrap(i, fn):
        try:
            results[i] = fn()
        except Exception as e:
            results[i] = e

    threads = [threading.Thread(target=wrap, args=(i, f), daemon=True)
               for i, f in enumerate(fns)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout)
    return results


# -- Application layer -------------------------------------------------------
def proto_http(host, emit, stop):
    """HTTP / HTTPS — request timing breakdown + TLS certificate inspection."""
    url = host if re.match(r"^https?://", host or "", re.I) else f"https://{host}"
    emit(f"  HTTP request timing — GET {url}", "title")
    r = http_probe(url)
    if r.get("error") and url.startswith("https://"):
        emit(f"  https failed ({r['error']}), retrying plain http", "warn")
        r = http_probe(url.replace("https://", "http://", 1))
    if r.get("error"):
        emit(f"  ✖ {r['error']}", "err")
        return ("FAIL", r["error"][:60])
    emit(f"  DNS resolve   : {r.get('dns_ms', 0):8.1f} ms", "head")
    emit(f"  TCP connect   : {r.get('tcp_ms', 0):8.1f} ms", "head")
    if r.get("tls_ms") is not None:
        emit(f"  TLS handshake : {r.get('tls_ms'):8.1f} ms", "head")
    emit(f"  TTFB          : {r.get('ttfb_ms', 0):8.1f} ms", "head")
    emit(f"  Total         : {r.get('total_ms', 0):8.1f} ms", "ok")
    emit(f"  Status        : {r.get('status', '-')}   Server: {r.get('server', '-')}   "
         f"Via: {r.get('via', '-')}", "head")
    status = r.get("status")
    if url.startswith("https://") and r.get("host"):
        try:
            emit("  TLS certificate:", "title")
            ctx = ssl.create_default_context()
            with socket.create_connection((r["host"], r.get("port") or 443), 5) as sock:
                with ctx.wrap_socket(sock, server_hostname=r["host"]) as ssock:
                    cert = ssock.getpeercert()
                    emit(f"  protocol {ssock.version()}  cipher "
                         f"{ssock.cipher()[0] if ssock.cipher() else '-'}", "head")
            subj = dict(x[0] for x in cert.get("subject", ()))
            iss = dict(x[0] for x in cert.get("issuer", ()))
            emit(f"  subject CN : {subj.get('commonName', '-')}", "head")
            emit(f"  issuer     : {iss.get('organizationName', '-')} "
                 f"{iss.get('commonName', '')}", "head")
            na = cert.get("notAfter", "")
            try:
                exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.datetime.utcnow()).days
                emit(f"  expires    : {na}  ({days} days left)",
                     "ok" if days > 14 else "warn")
            except Exception:
                emit(f"  expires    : {na}", "head")
        except Exception as e:
            emit(f"  certificate inspection failed: {e}", "warn")
    if status and status < 400:
        return ("PASS", f"HTTP {status} in {r.get('total_ms', 0):.0f} ms")
    return ("WARN", f"HTTP {status or '-'} in {r.get('total_ms', 0):.0f} ms")


def proto_dns(host, emit, stop):
    """DNS — system resolver + A/AAAA/MX/NS/TXT/SOA over UDP/53."""
    name = _short_host(host)
    emit(f"  DNS protocol test — {name}", "title")
    ok = 0
    try:
        addrs, ms = dns_resolve(name)
        emit(f"  system resolver : {', '.join(addrs[:4])}  ({ms:.1f} ms)", "ok")
        ok += 1
    except Exception as e:
        emit(f"  system resolver : FAILED — {e}", "err")
    if _is_ip(name):                       # reverse lookup for IP targets
        try:
            ptr, ms = reverse_dns(name)
            emit(f"  PTR {name} -> {ptr}  ({ms:.1f} ms)", "ok")
            ok += 1
        except Exception as e:
            emit(f"  PTR lookup failed: {e}", "warn")
        return ("PASS" if ok else "FAIL", f"{ok}/2 lookups answered")
    qtypes = [(1, "A"), (28, "AAAA"), (15, "MX"), (2, "NS"), (16, "TXT"), (6, "SOA")]
    for server in ("1.1.1.1", "8.8.8.8"):
        server_ok = False
        for qt, qn in qtypes:
            if stop is not None and stop.is_set():
                break
            try:
                ms, pkt = dns_query(server, name, qt, timeout=2.5)
                ans = [a[3] for a in pkt.get("answers", []) if a[1] == qt][:3]
                rc = {0: "", 3: "  [NXDOMAIN]"}.get(pkt.get("rcode"),
                                                    f"  [rcode {pkt.get('rcode')}]")
                emit(f"  {qn:5s} via {server:10s}: {ms:6.1f} ms  "
                     f"{', '.join(ans) if ans else '(no answer)'}{rc}",
                     "ok" if ans else "head")
                server_ok = True
                if ans:
                    ok += 1
            except Exception as e:
                emit(f"  {qn:5s} via {server:10s}: {e}", "err")
                break                       # resolver unreachable — skip it
        if not server_ok:
            continue
    total = 2 + len(qtypes)
    return ("PASS" if ok >= 2 else ("WARN" if ok else "FAIL"),
            f"{ok}/{total} lookups answered")


def proto_dhcp(host, emit, stop):
    """DHCP — broadcast DHCPDISCOVER on UDP 67/68, wait for an OFFER."""
    import struct
    import random
    emit("  DHCP test — broadcast DHCPDISCOVER (UDP 67 → 68)", "title")
    mac = _local_mac()
    xid = random.randint(0, 0xFFFFFFFF)
    pkt = struct.pack("!BBBBIHH", 1, 1, 6, 0, xid, 0, 0x8000)
    pkt += b"\x00" * 16                       # ciaddr yiaddr siaddr giaddr
    pkt += mac + b"\x00" * 10                 # chaddr (16)
    pkt += b"\x00" * (64 + 128)               # sname + file
    pkt += struct.pack("!I", 0x63825363)      # magic cookie
    pkt += bytes([53, 1, 1])                  # option 53: DHCPDISCOVER
    pkt += bytes([55, 4, 1, 3, 6, 15])        # param request: mask, router, dns, domain
    pkt += bytes([255])                       # end
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    ephemeral = False
    try:
        s.bind(("", 68))
    except Exception:
        ephemeral = True
        try:
            s.bind(("", 0))
        except Exception:
            pass
    s.settimeout(3.5)
    emit(f"  chaddr {mac.hex(':')}  xid 0x{xid:08x}  source port "
         f"{'ephemeral' if ephemeral else 68}", "head")
    try:
        s.sendto(pkt, ("255.255.255.255", 67))
        emit("  DISCOVER sent to 255.255.255.255:67", "head")
    except Exception as e:
        s.close()
        emit(f"  ✖ broadcast send failed: {e}", "err")
        return ("FAIL", f"send failed: {e}")
    if ephemeral:
        emit("  note: UDP/68 needs admin/root to bind — replies cannot be seen", "warn")
    offer = None
    t_end = time.time() + 3.5
    while time.time() < t_end and not (stop and stop.is_set()):
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            break
        except Exception:
            break
        if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63":
            continue
        mtype = None
        server_id = ""
        yiaddr = socket.inet_ntoa(data[16:20]) if len(data) >= 20 else ""
        i = 240
        while i + 1 < len(data):
            code = data[i]
            if code == 255:
                break
            if code == 0:
                i += 1
                continue
            ln = data[i + 1]
            val = data[i + 2:i + 2 + ln]
            if code == 53 and val:
                mtype = val[0]
            elif code == 54 and len(val) >= 4:
                server_id = socket.inet_ntoa(val[:4])
            i += 2 + ln
        names = {2: "OFFER", 5: "ACK", 6: "NAK"}
        emit(f"  reply from {addr[0]}: DHCP{names.get(mtype, mtype)}  "
             f"yiaddr {yiaddr}  server {server_id or '-'}",
             "ok" if mtype in (2, 5) else "warn")
        if mtype == 2:
            offer = (yiaddr, server_id)
            break
    s.close()
    if offer:
        return ("PASS", f"DHCP OFFER {offer[0]} from {offer[1] or 'server'}")
    if ephemeral:
        return ("WARN", "DISCOVER sent — needs admin rights to read the OFFER")
    return ("WARN", "no OFFER received (server may filter broadcast)")


def proto_ftp(host, emit, stop):
    """FTP / SFTP — FTP control-channel banner + AUTH TLS, SFTP via SSH banner."""
    h = _short_host(host)
    emit(f"  FTP / SFTP service probes — {h}", "title")

    def ftp_probe():
        s = socket.create_connection((h, 21), 4)
        s.settimeout(4)
        banner = s.recv(512).decode("utf-8", "replace").strip().splitlines()[0]
        auth = ""
        try:
            s.sendall(b"AUTH TLS\r\n")
            auth = s.recv(512).decode("utf-8", "replace").strip().splitlines()[0]
        except Exception:
            auth = "(no reply)"
        try:
            s.sendall(b"QUIT\r\n")
        except Exception:
            pass
        s.close()
        return banner, auth

    def sftp_probe():
        s = socket.create_connection((h, 22), 4)
        s.settimeout(4)
        banner = s.recv(512).decode("utf-8", "replace").strip().splitlines()[0]
        s.close()
        return banner

    banner, auth = None, None
    (r1, r2) = _run_parallel([ftp_probe, sftp_probe], timeout=5.0)
    ok = 0
    if isinstance(r1, tuple):
        banner, auth = r1
        good = banner.startswith("220")
        emit(f"  FTP/21 banner : {banner}", "ok" if good else "warn")
        emit(f"  AUTH TLS      : {auth}",
             "ok" if auth.startswith("234") else "info")
        ok += 1 if good else 0
    else:
        emit(f"  FTP/21        : {r1}", "err")
    if isinstance(r2, str):
        good = r2.startswith("SSH-")
        emit(f"  SFTP/22 banner: {r2}", "ok" if good else "warn")
        emit("  SFTP runs over the SSH transport — banner proves availability",
             "info")
        ok += 1 if good else 0
    else:
        emit(f"  SFTP/22       : {r2}", "err")
    return ("PASS" if ok == 2 else ("WARN" if ok else "FAIL"),
            f"{ok}/2 services answered")


def proto_mail(host, emit, stop):
    """SMTP / POP3 / IMAP — greeting banners on plain and implicit-TLS ports."""
    h = _short_host(host)
    emit(f"  Mail service probes — {h}", "title")
    services = [
        ("SMTP", 25, False, "220"),
        ("SMTP submission", 587, False, "220"),
        ("SMTPS", 465, True, "220"),
        ("POP3", 110, False, "+OK"),
        ("POP3S", 995, True, "+OK"),
        ("IMAP", 143, False, "* OK"),
        ("IMAPS", 993, True, "* OK"),
    ]

    def probe(name, port, tls, expect):
        s = socket.create_connection((h, port), 3.5)
        try:
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=h)
            s.settimeout(3.5)
            banner = s.recv(512).decode("utf-8", "replace").strip().splitlines()[0]
            try:
                s.sendall(b"QUIT\r\n")
            except Exception:
                pass
            return banner, banner.startswith(expect)
        finally:
            try:
                s.close()
            except Exception:
                pass

    fns = [lambda s=srv: probe(*s) for srv in services]
    results = _run_parallel(fns, timeout=5.0)
    ok = 0
    for (name, port, tls, expect), res in zip(services, results):
        if isinstance(res, tuple):
            banner, good = res
            emit(f"  {name:16s} {port:4d}{'/tls' if tls else '    '}: {banner[:66]}",
                 "ok" if good else "warn")
            ok += 1 if good else 0
        else:
            emit(f"  {name:16s} {port:4d}{'/tls' if tls else '    '}: "
                 f"{str(res)[:60]}", "info")
    if ok:
        return ("PASS", f"{ok}/{len(services)} mail services answered")
    return ("FAIL", "no mail service answered")


def proto_ssh(host, emit, stop):
    """SSH — identification string exchange (RFC 4253 §4.2)."""
    h = _short_host(host)
    emit(f"  SSH handshake — {h}:22", "title")
    try:
        t0 = time.perf_counter()
        s = socket.create_connection((h, 22), 5)
        s.settimeout(5)
        banner = s.recv(512).decode("utf-8", "replace").strip().splitlines()[0]
        ms = (time.perf_counter() - t0) * 1000.0
        emit(f"  identification string: {banner}",
             "ok" if banner.startswith("SSH-") else "warn")
        emit(f"  connect + banner      : {ms:.1f} ms", "head")
        try:
            s.sendall(b"SSH-2.0-NetProbe_1.3\r\n")
            kex = s.recv(1024)
            if kex and kex[0] == 20:
                emit(f"  KEXINIT received ({len(kex)} bytes) — key exchange can start",
                     "ok")
            elif kex:
                emit(f"  reply {len(kex)} bytes (msg type {kex[0]})", "head")
        except Exception as e:
            emit(f"  KEXINIT: {e}", "warn")
        s.close()
        if banner.startswith("SSH-"):
            return ("PASS", banner[:48])
        return ("WARN", f"non-SSH banner: {banner[:40]}")
    except Exception as e:
        emit(f"  ✖ {e}", "err")
        return ("FAIL", str(e)[:60])


# -- SNMP (BER encoding by hand) --------------------------------------------
def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return bytes([0x80 | len(b)]) + b


def _ber_int(v: int) -> bytes:
    b = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big", signed=True)
    return b"\x02" + _ber_len(len(b)) + b


def _ber_oid(parts) -> bytes:
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        stack = [p & 0x7F]
        p >>= 7
        while p:
            stack.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(stack))
    return b"\x06" + _ber_len(len(out)) + out


def _snmp_get(community: str, oid_parts, req_id: int = 1) -> bytes:
    varbind = _ber_oid(oid_parts) + b"\x05\x00"            # OID + NULL
    vbl = b"\x30" + _ber_len(len(varbind)) + varbind       # VarBindList
    pdu_body = _ber_int(req_id) + b"\x02\x01\x00\x02\x01\x00" + vbl
    pdu = b"\xa0" + _ber_len(len(pdu_body)) + pdu_body     # GetRequest-PDU
    comm = b"\x04" + _ber_len(len(community)) + community.encode()
    body = b"\x02\x01\x01" + comm + pdu                    # version=1 → SNMPv2c
    return b"\x30" + _ber_len(len(body)) + body


def _snmp_strings(data: bytes):
    """Pull printable OCTET STRINGs out of a BER response (good enough for us)."""
    out, i = [], 0
    while i < len(data) - 2:
        if data[i] == 0x04 and data[i + 1] < 0x80:
            ln = data[i + 1]
            if i + 2 + ln <= len(data):
                s = data[i + 2:i + 2 + ln]
                if ln >= 2 and all(32 <= c < 127 for c in s):
                    out.append(s.decode("ascii"))
                i += 2 + ln
                continue
        i += 1
    return out


def proto_snmp(host, emit, stop):
    """SNMP — SNMPv2c GetRequest for sysDescr.0 / sysName.0 (community public)."""
    emit("  SNMPv2c GetRequest — UDP/161, community 'public'", "title")
    targets = []
    gw, _ = default_gateway()
    if gw:
        targets.append((gw, "default gateway"))
    h = _short_host(host)
    if _is_ip(h) and h not in targets:
        targets.append((h, "target host"))
    if not targets:
        emit("  no SNMP-capable target identified", "warn")
        return ("WARN", "no target")
    oids = [((1, 3, 6, 1, 2, 1, 1, 1, 0), "sysDescr.0"),
            ((1, 3, 6, 1, 2, 1, 1, 5, 0), "sysName.0")]
    for tgt, role in targets:
        emit(f"  target {tgt} ({role})", "head")
        answered = False
        for j, (oid, name) in enumerate(oids):
            if stop is not None and stop.is_set():
                break
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3.0)
            try:
                s.sendto(_snmp_get("public", oid, j + 1), (tgt, 161))
                data, addr = s.recvfrom(4096)
                strs = _snmp_strings(data)
                val = strs[0] if strs else f"{len(data)}-byte response"
                emit(f"    {name:10s} = {val[:70]}", "ok")
                answered = True
            except Exception as e:
                emit(f"    {name:10s} — {e}", "warn")
            finally:
                s.close()
        if answered:
            return ("PASS", f"SNMP answered at {tgt}")
    return ("WARN", "no SNMP response (filtered or community differs)")


# -- Transport layer ---------------------------------------------------------
def proto_tcp(host, emit, stop):
    """TCP — handshake timing against the target's service ports."""
    h = _short_host(host)
    emit(f"  TCP handshake timing — {h}", "title")
    any_ok = False
    for port, samples in ((443, 3), (80, 2)):
        vals = []
        for _ in range(samples):
            if stop is not None and stop.is_set():
                break
            try:
                vals.append(tcp_latency(h, port, 2.5))
            except Exception:
                pass
        if vals:
            emit(f"  :{port:<5d} {len(vals)}/{samples} handshakes  "
                 f"avg {sum(vals) / len(vals):6.1f} ms  min {min(vals):.1f}  "
                 f"max {max(vals):.1f}  jitter {max(vals) - min(vals):.1f} ms", "ok")
            any_ok = True
        else:
            emit(f"  :{port:<5d} handshake failed (filtered or no listener)", "warn")
    return ("PASS" if any_ok else "FAIL",
           "handshake OK" if any_ok else "no port accepted a handshake")


def proto_udp(host, emit, stop):
    """UDP — real round-trip via DNS, plus reachability semantics on the target."""
    h = _short_host(host)
    emit("  UDP datagram test — connectionless: replies prove reachability,", "title")
    emit("  silence means open-or-filtered, ICMP unreachable means closed.", "info")
    ok = 0
    # 1) proven UDP service: DNS round trip
    for resolver in ("1.1.1.1", "8.8.8.8"):
        if stop is not None and stop.is_set():
            break
        try:
            ms, _pkt = dns_query(resolver, "example.com", 1, timeout=2.5)
            emit(f"  DNS/53 via {resolver:10s}: reply in {ms:6.1f} ms  (UDP RTT proven)",
                 "ok")
            ok += 1
            break
        except Exception as e:
            emit(f"  DNS/53 via {resolver:10s}: {e}", "warn")
    # 2) target reachability semantics
    for port in (443, 80):
            if stop is not None and stop.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2.5)
                t0 = time.perf_counter()
                s.sendto(b"netprobe-udp-probe\x00" * 2, (h, port))
                try:
                    data, addr = s.recvfrom(512)
                    ms = (time.perf_counter() - t0) * 1000.0
                    emit(f"  :{port}/udp  reply from {addr[0]} in {ms:.1f} ms "
                         f"({len(data)} bytes)", "ok")
                    ok += 1
                except socket.timeout:
                    emit(f"  :{port}/udp  no reply — open or filtered (UDP is "
                         f"connectionless)", "head")
                except (ConnectionRefusedError, ConnectionResetError):
                    emit(f"  :{port}/udp  ICMP port unreachable — port closed", "warn")
                s.close()
            except Exception as e:
                emit(f"  :{port}/udp  {e}", "err")
    return ("PASS" if ok else "WARN", f"{ok} UDP exchange(s) proven")


def proto_quic(host, emit, stop):
    """QUIC — Version Negotiation probe on UDP/443 (RFC 9000 §6)."""
    import struct
    import random
    h = _short_host(host)
    emit(f"  QUIC Version Negotiation probe — {h}:443/udp", "title")
    emit("  sending an Initial-style long header with a reserved version; a QUIC",
         "info")
    emit("  endpoint must answer with a Version Negotiation packet.", "info")
    try:
        addrs, _ms = dns_resolve(h)
        ip = next((a for a in addrs if ":" not in a), addrs[0])
    except Exception as e:
        emit(f"  ✖ resolve failed: {e}", "err")
        return ("FAIL", f"DNS: {e}")
    ver = b"\x0a\x0a\x0a\x0a"                 # reserved version (greasing)
    dcid = bytes(random.getrandbits(8) for _ in range(8))
    scid = bytes(random.getrandbits(8) for _ in range(8))
    pkt = (bytes([0xCF]) + ver + bytes([len(dcid)]) + dcid
           + bytes([len(scid)]) + scid)
    pkt += b"\x00" * max(0, 1200 - len(pkt))  # pad to a full-size datagram
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4.0)
    try:
        s.sendto(pkt, (ip, 443))
        data, addr = s.recvfrom(1500)
    except socket.timeout:
        s.close()
        emit("  no reply on UDP/443 — filtered, or the service is not QUIC", "warn")
        return ("WARN", "no Version Negotiation reply")
    except Exception as e:
        s.close()
        emit(f"  ✖ {e}", "err")
        return ("FAIL", str(e)[:60])
    s.close()
    if not (data[0] & 0x80) or len(data) < 7:
        emit(f"  unexpected {len(data)}-byte reply (not a long-header packet)", "warn")
        return ("WARN", "unexpected reply")
    version = data[1:5].hex()
    if version != "00000000":
        emit(f"  reply with version 0x{version} — endpoint speaks this version",
             "ok")
        return ("PASS", f"QUIC endpoint (version 0x{version})")
    # Version Negotiation: parse offered versions
    off = 5
    dcid_len = data[off]
    off += 1 + dcid_len
    scid_len = data[off] if off < len(data) else 0
    off += 1 + scid_len
    versions = []
    while off + 4 <= len(data):
        versions.append(data[off:off + 4].hex())
        off += 4
    known = {"00000001": "QUIC v1 (RFC 9000)", "6b3343cf": "QUIC v2 (RFC 9369)",
             "ff00001d": "draft-29", "51303530": "Google QUIC Q050",
             "51303436": "Google QUIC Q046"}
    emit(f"  Version Negotiation received from {addr[0]} — {len(versions)} version(s)",
         "ok")
    for v in versions[:8]:
        emit(f"    0x{v}  {known.get(v, '')}", "head")
    return ("PASS", f"QUIC confirmed — {len(versions)} versions offered")


# -- Network / Internet layer ------------------------------------------------
def proto_ip(host, emit, stop):
    """IPv4 / IPv6 — dual-stack resolution, local addresses, IPv6 reachability."""
    h = _short_host(host)
    emit(f"  IP layer test — {h}", "title")
    v4, v6 = [], []
    try:
        addrs, ms = dns_resolve(h)
        for a in addrs:
            (v6 if ":" in a else v4).append(a)
        emit(f"  resolved: IPv4 {', '.join(v4) or '-'}   IPv6 {', '.join(v6) or '-'}  "
             f"({ms:.1f} ms)", "ok" if (v4 or v6) else "err")
    except Exception as e:
        emit(f"  ✖ resolution failed: {e}", "err")
    try:
        local = []
        for fam, _ty, _pr, _cn, sa in socket.getaddrinfo(socket.gethostname(), None):
            if sa[0] not in local:
                local.append(sa[0])
        emit(f"  local addresses: {', '.join(local[:6]) or '-'}", "head")
    except Exception as e:
        emit(f"  local addresses: {e}", "warn")
    v6_ok = False
    try:
        ms = tcp_latency("2606:4700:4700::1111", 443, 3.0)   # Cloudflare DNS over v6
        emit(f"  IPv6 internet  : reachable (2606:4700:4700::1111 in {ms:.1f} ms)",
             "ok")
        v6_ok = True
    except Exception:
        emit("  IPv6 internet  : not reachable from this host (IPv4-only or filtered)",
             "warn")
    if v4 or v6:
        return ("PASS" if v6_ok else "WARN",
                f"IPv4 {len(v4)} / IPv6 {len(v6)} address(es)" +
                (" + v6 internet" if v6_ok else ""))
    return ("FAIL", "target did not resolve")


def proto_icmp(host, emit, stop):
    """ICMP — echo request/reply statistics (via the system ping)."""
    h = _short_host(host)
    emit(f"  ICMP echo test — {h} (3 pings)", "title")
    vals, misses = [], 0
    for i in range(3):
        if stop is not None and stop.is_set():
            break
        ms = icmp_ping_once(h)
        if ms is None:
            misses += 1
            emit(f"  seq {i + 1}: timeout / unreachable", "warn")
        else:
            vals.append(ms)
            emit(f"  seq {i + 1}: echo reply in {ms:6.1f} ms", "ok")
    if vals:
        emit(f"  summary: sent 3, received {len(vals)}, "
             f"loss {100.0 * misses / 3:.0f}%, avg {sum(vals) / len(vals):.1f} ms, "
             f"jitter {max(vals) - min(vals):.1f} ms", "head")
        return ("PASS", f"avg {sum(vals) / len(vals):.1f} ms, "
                        f"loss {100.0 * misses / 3:.0f}%")
    return ("FAIL", "no echo replies (ICMP may be blocked)")


def proto_ospf(host, emit, stop):
    """OSPF — passive check: scan the routing table for OSPF-learned routes."""
    emit("  OSPF check — link-state IGP: IP protocol 89, multicast 224.0.0.5/224.0.0.6",
         "title")
    emit("  (speaking OSPF needs raw sockets — this is a passive routing-table scan)",
         "info")
    found = []
    try:
        r = subprocess.run(cmd_routes(), capture_output=True, text=True, timeout=15,
                           **{k: v for k, v in popen_kwargs().items()
                              if k == "creationflags"})
        for line in (r.stdout or "").splitlines():
            if re.search(r"\bospf\b|\bzebra\b|\bbird\b|proto 89|proto 110", line, re.I):
                found.append(line.strip())
                emit(f"    {line.strip()}", "ok")
    except Exception as e:
        emit(f"  routing table scan failed: {e}", "warn")
    gw, _iface = default_gateway()
    emit(f"  default gateway: {gw or '?'} — OSPF adjacencies live on routers, "
         f"edge hosts only see their routes", "head")
    if found:
        return ("PASS", f"{len(found)} OSPF-learned route(s) visible")
    return ("INFO", "no OSPF-learned routes visible (normal for an edge host)")


def proto_bgp(host, emit, stop):
    """BGP — TCP/179 liveness + origin ASN of the target."""
    h = _short_host(host)
    emit(f"  BGP check — {h} (TCP/179 + ASN origin)", "title")
    emit("  BGP runs between routers (TCP/179); an edge host shows only its ASN",
         "info")
    asn = ""
    try:
        info = ip_info(h)
        if info.get("error"):
            emit(f"  ASN lookup: {info['error']}", "warn")
        else:
            asn = info.get("as", "")
            emit(f"  target {info.get('ip')}  origin ASN: {asn or '-'}", "ok")
            emit(f"  ISP {info.get('isp', '-')}   org {info.get('org', '-')}", "head")
    except Exception as e:
        emit(f"  ASN lookup failed: {e}", "warn")
    open_179 = False
    if _is_ip(h):
        try:
            ms = tcp_latency(h, 179, 3.0)
            emit(f"  TCP/179 to {h}: open — likely a BGP speaker ({ms:.1f} ms)", "ok")
            open_179 = True
        except Exception:
            emit(f"  TCP/179 to {h}: filtered/closed (expected for non-routers)", "head")
    if open_179:
        return ("PASS", "TCP/179 open — BGP speaker detected")
    if asn:
        return ("WARN", f"{asn} — no direct BGP session (normal on edge hosts)")
    return ("FAIL", "no ASN data and no BGP port")


# -- Data link layer ---------------------------------------------------------
def proto_arp(host, emit, stop):
    """ARP — neighbour cache inspection + gateway MAC resolution."""
    emit("  ARP / neighbour cache", "title")
    table = arp_entries()
    if not table:
        emit("  cache is empty — ping or contact a host on the LAN to populate it",
             "warn")
        return ("WARN", "ARP cache empty")
    gw, _iface = default_gateway()
    for ip, (mac, iface) in sorted(table.items()):
        mark = "  ← default gateway" if ip == gw else ""
        emit(f"    {ip:16s} {mac:20s} {iface}{mark}", "ok" if ip == gw else "head")
    if gw and gw not in table:
        emit(f"  gateway {gw} not in cache — trying a quick ping to populate it", "info")
        icmp_ping_once(gw)
        table = arp_entries()
        if gw in table:
            emit(f"  gateway {gw} -> {table[gw][0]}", "ok")
    return ("PASS", f"{len(table)} neighbours" +
                    (f", gateway {table[gw][0]}" if gw in table else ""))


def proto_eth(host, emit, stop):
    """Ethernet — link state, MTU, speed/duplex and error counters per NIC."""
    emit("  Ethernet link state — per interface", "title")
    ifaces = iface_counters() or {}
    errors = iface_errors()
    up_count = 0
    for name in sorted(ifaces.keys()):
        if name == "lo" or name.startswith("lo"):
            continue
        bits = [name]
        if IS_NIX and os.path.isdir(f"/sys/class/net/{name}"):
            for f, lbl in (("operstate", ""), ("mtu", "mtu"), ("speed", "speed"),
                           ("duplex", "duplex")):
                try:
                    with open(f"/sys/class/net/{name}/{f}") as fh:
                        val = fh.read().strip()
                    if val and val != "-1":
                        bits.append(f"{lbl} {val}" if lbl else val)
                except Exception:
                    pass
        else:
            bits.append(f"mtu ?")
        errs = errors.get(name)
        if errs and any(errs):
            bits.append(f"errors {errs[0]}/{errs[1]} drops {errs[2]}/{errs[3]}")
        line = "   ".join(bits)
        is_up = "down" not in line
        up_count += 1 if is_up else 0
        emit(f"    {line}", "ok" if is_up and not (errs and any(errs)) else "warn")
    if HAVE_PSUTIL:
        try:
            st = psutil.net_if_stats()
            for name, s in sorted(st.items()):
                if name in ifaces and name not in ("lo",):
                    emit(f"    {name}: link {'up' if s.isup else 'down'}  "
                         f"{s.speed or '?'} Mb/s  mtu {s.mtu}",
                         "ok" if s.isup else "warn")
        except Exception:
            pass
    if not ifaces:
        emit("  no interface counters available (install psutil for richer data)",
             "warn")
        return ("WARN", "no interface data")
    return ("PASS" if up_count else "WARN", f"{up_count} interface(s) up")


def proto_wifi(host, emit, stop):
    """Wi-Fi (IEEE 802.11) — adapter status, SSID and signal via the OS."""
    emit("  Wi-Fi / IEEE 802.11 — adapter status via the operating system", "title")
    cmd = cmd_wifi()
    if not shutil_which(cmd[0]):
        emit(f"  '{cmd[0]}' not available on this system — cannot query the adapter",
             "warn")
        return ("WARN", f"needs '{cmd[0]}'")
    try:
        r = subprocess.run(cmd_wifi(), capture_output=True, text=True, timeout=15,
                           **{k: v for k, v in popen_kwargs().items()
                              if k == "creationflags"})
        out = (r.stdout or "").strip()
        if not out:
            emit("  no Wi-Fi information returned (no adapter or missing tools)", "warn")
            return ("WARN", "no Wi-Fi adapter found")
        lines = out.splitlines()[:18]
        for ln in lines:
            emit("    " + ln[:100], "head")
        wifi_hit = bool(re.search(r"ssid|signal|signal|channel|wlan|wi-fi|wifi|802\.11",
                                  out, re.I))
        return ("PASS" if wifi_hit else "WARN",
                "Wi-Fi adapter reported" if wifi_hit else "adapter present, no Wi-Fi data")
    except Exception as e:
        emit(f"  ✖ {e}", "err")
        return ("FAIL", str(e)[:60])


PROTOCOL_TESTS = {
    "http": proto_http, "dns": proto_dns, "dhcp": proto_dhcp, "ftp": proto_ftp,
    "mail": proto_mail, "ssh": proto_ssh, "snmp": proto_snmp,
    "tcp": proto_tcp, "udp": proto_udp, "quic": proto_quic,
    "ip": proto_ip, "icmp": proto_icmp, "ospf": proto_ospf, "bgp": proto_bgp,
    "arp": proto_arp, "eth": proto_eth, "wifi": proto_wifi,
}


# ----------------------------------------------------------------------------
# UI widgets
# ----------------------------------------------------------------------------
class TerminalView(ttk.Frame):
    """One terminal pane: color-tagged output + its own command line + own process."""

    def __init__(self, master, app, name="Term"):
        super().__init__(master)
        self.app = app
        self.name = name
        self.proc = None
        self.stop_flag = threading.Event()
        self._dead = False
        self._spin_job = None
        self._status_text = "idle"

        self.text = tk.Text(self, wrap="none", bg=C["bg"], fg=C["fg"],
                            insertbackground=C["fg"], font=MONO,
                            relief="flat", padx=8, pady=6)
        ys = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        xs = ttk.Scrollbar(self, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")

        bar = tk.Frame(self, bg=C["bg"])
        bar.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(4, 0))
        self.status_var = tk.StringVar(value="idle")
        tk.Label(bar, textvariable=self.status_var, bg=C["bg"], fg=C["dim"],
                 font=UI_FONT, width=11, anchor="w").pack(side="left", padx=(0, 6))
        self.entry_var = tk.StringVar()
        ent = tk.Entry(bar, textvariable=self.entry_var, bg=C["panel2"], fg=C["fg"],
                       insertbackground=C["fg"], relief="flat", font=MONO)
        ent.pack(side="left", fill="x", expand=True, padx=4)
        ent.bind("<Return>", lambda e: self.run_entry())
        for label, fn, col in (("▶ Run", self.run_entry, C["accent"]),
                               ("■ Stop", self.stop, C["err"]),
                               ("Clear", self.clear, C["panel2"]),
                               ("Copy", self._copy, C["panel2"]),
                               ("Save", self.save, C["panel2"])):
            b = tk.Button(bar, text=label, command=fn, bg=col,
                          fg=C["bg"] if col in (C["accent"], C["err"]) else C["fg"],
                          activebackground=C["border"], activeforeground=C["fg"],
                          relief="flat", font=UI_FONT, cursor="hand2", padx=8)
            b.pack(side="left", padx=2)
            attach_hover(b, col, C["bg"] if col in (C["accent"], C["err"]) else C["fg"])

        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self.text.tag_configure("cmd", foreground=C["cmd"], font=(MONO[0], MONO[1], "bold"))
        self.text.tag_configure("ok", foreground=C["ok"])
        self.text.tag_configure("warn", foreground=C["warn"])
        self.text.tag_configure("err", foreground=C["err"], font=(MONO[0], MONO[1], "bold"))
        self.text.tag_configure("info", foreground=C["dim"])
        self.text.tag_configure("title", foreground=C["accent"], font=(MONO[0], MONO[1], "bold"))
        self.text.tag_configure("head", foreground=C["head"])
        self.text.tag_configure("prog", foreground=C["accent"])

        self.text.bind("<Control-c>", self._copy)
        self.text.bind("<Control-a>", self._select_all)

    # -- output -------------------------------------------------------------
    def _alive(self):
        """False once this pane has been closed — all output then becomes a no-op."""
        try:
            return bool(self.winfo_exists())
        except Exception:
            return False

    def set_status(self, s: str):
        self._status_text = s
        if not self._alive():
            return
        if s == "running":
            if self._spin_job is None:
                self._spin()
        else:
            if self._spin_job is not None:
                try:
                    self.after_cancel(self._spin_job)
                except Exception:
                    pass
                self._spin_job = None
            self.status_var.set(s)

    def _spin(self, i=0):
        """Animated spinner shown while this pane's command runs."""
        self._spin_job = None
        if not self._alive() or self._status_text != "running":
            return
        self.status_var.set(f"{SPIN_FRAMES[i % len(SPIN_FRAMES)]} running")
        self._spin_job = self.after(110, self._spin, i + 1)

    def _drop_trailing_prog(self):
        """Progress is transient UI — remove the trailing progress line."""
        try:
            idx = self.text.index("end-1c linestart")
            if "prog" in self.text.tag_names(idx):
                self.text.delete(idx, "end")
        except Exception:
            pass

    def set_progress(self, frac: float, label: str = ""):
        """Animated progress bar line at the bottom of the pane."""
        if not self._alive():
            return
        self._drop_trailing_prog()
        frac = max(0.0, min(1.0, float(frac)))
        line = f"  {render_bar(frac)} {int(frac * 100):3d}%  {label}"
        self.text.insert("end", line + "\n", "prog")
        self.text.see("end")

    def clear_progress(self):
        if self._alive():
            self._drop_trailing_prog()

    def write(self, line: str, tag: str = "head"):
        if not self._alive():
            return
        self._drop_trailing_prog()
        self.text.insert("end", line + "\n", tag)
        self.text.see("end")

    def type_text(self, text: str, tag: str = "head", speed: int = 12,
                  done=None, i: int = 0):
        """Typewriter reveal used by the animated intro."""
        if not self._alive():
            return
        if i < len(text):
            self.text.insert("end", text[i], tag)
            self.text.see("end")
            self.after(speed, lambda: self.type_text(text, tag, speed, done, i + 1))
        else:
            self.text.insert("end", "\n")
            self.text.see("end")
            if done:
                done()

    def banner(self, cmd):
        self.write("─" * 78, "info")
        self.write(f"[{now()}] [{self.name}] $ {' '.join(str(c) for c in cmd)}", "cmd")

    def clear(self):
        if self._alive():
            self.text.delete("1.0", "end")

    def dump(self) -> str:
        if not self._alive():
            return ""
        return self.text.get("1.0", "end")

    # -- own command line ---------------------------------------------------
    def run_entry(self):
        raw = self.entry_var.get().strip()
        if not raw:
            return
        try:
            import shlex
            cmd = shlex.split(raw, posix=not IS_WIN)
        except ValueError:
            cmd = raw.split()
        self.app.run_cmd(cmd, pane=self)

    def stop(self):
        self.stop_flag.set()
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.kill()
            except Exception:
                pass
            self.write("■ stopped by user", "warn")
        self.clear_progress()
        self.set_status("stopped")

    def save(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log", "*.log"), ("Text", "*.txt"), ("All", "*.*")],
            initialfile=f"netprobe-{self.name.replace(' ', '')}-"
                        f"{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.log")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.dump())
        self.app.status(f"saved {path}")

    def _copy(self, _=None):
        try:
            sel = self.text.get("sel.first", "sel.last")
        except Exception:
            sel = self.text.get("1.0", "end")
        self.clipboard_clear()
        self.clipboard_append(sel)
        self.app.status(f"[{self.name}] output copied to clipboard")
        return "break"

    def _select_all(self, _=None):
        self.text.tag_add("sel", "1.0", "end")
        return "break"


class TerminalsPanel(ttk.Frame):
    """Tabbed multi-terminal: each pane runs its own command concurrently."""

    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        top = tk.Frame(self, bg=C["bg"])
        top.pack(fill="x", pady=(0, 4))
        for label, fn in (("＋ New Terminal", self.add_terminal),
                          ("✕ Close Terminal", self.close_terminal),
                          ("Run All: Ping", self.ping_all)):
            b = tk.Button(top, text=label, command=fn, bg=C["panel2"], fg=C["fg"],
                          activebackground=C["accent"], activeforeground=C["bg"],
                          relief="flat", font=UI_FONT, cursor="hand2", padx=10)
            b.pack(side="left", padx=3)
            attach_hover(b, C["panel2"], C["fg"])
        tk.Label(top, text="each tab = one independent output stream + command line",
                 bg=C["bg"], fg=C["dim"], font=UI_FONT).pack(side="right", padx=8)

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True)
        self.views = []
        self.add_terminal("Term 1")

    def add_terminal(self, name=None):
        name = name or f"Term {len(self.views) + 1}"
        v = TerminalView(self.tabs, self.app, name)
        self.tabs.add(v, text=f"  {name}  ")
        self.views.append(v)
        self.tabs.select(v)
        v.banner([f"{name} ready — type a command below or use the sidebar"])
        return v

    def close_terminal(self):
        if len(self.views) <= 1:
            self.app.status("keep at least one terminal")
            return
        v = self.active()
        v.stop()
        v._dead = True
        self.tabs.forget(v)
        if v in self.views:
            self.views.remove(v)
        v.destroy()
        # hand the quick commands a fresh live pane immediately
        self.after(50, self.active)

    def ping_all(self):
        """Fan out one ping per terminal — multi-output comparison."""
        hosts = ["8.8.8.8", "1.1.1.1", "google.com"]
        while len(self.views) < len(hosts):
            self.add_terminal()
        for v, h in zip(self.views, hosts):
            self.app.run_cmd(cmd_ping(h, 10), pane=v)

    def active(self):
        """The pane quick-command output goes to.  Never returns a dead widget —
        closing a terminal used to break every quick command afterwards."""
        try:
            sel = self.tabs.select()
            if sel:
                cur = self.tabs.nametowidget(sel)
                if isinstance(cur, TerminalView) and cur._alive():
                    return cur
        except Exception:
            pass
        self.views = [v for v in self.views if v._alive()]
        for v in self.views:
            return v
        return self.add_terminal("Term 1")

    def all_views(self):
        return list(self.views)


class TrafficPanel(ttk.Frame):
    """Live multi-interface throughput charts (uses psutil when available)."""

    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.history_len = 120
        self.samples = {}      # iface -> deque[(rx, tx)]
        self.totals = {}       # iface -> (rx_total, tx_total) baseline
        self.last = {}         # iface -> (ts, rx, tx) counters
        self.paused = False
        self._pulse = 0.0

        left = ttk.Frame(self)
        left.pack(side="left", fill="y", padx=8, pady=8)
        ttk.Label(left, text="Interfaces (select up to 4)", foreground=C["accent"]).pack(anchor="w")
        self.listbox = tk.Listbox(left, selectmode="extended", exportselection=False,
                                  bg=C["panel2"], fg=C["fg"], selectbackground=C["accent"],
                                  selectforeground=C["bg"], font=UI_FONT, width=28, height=12,
                                  relief="flat", highlightthickness=1,
                                  highlightbackground=C["border"])
        self.listbox.pack(fill="x", pady=4)
        self.listbox.bind("<<ListboxSelect>>", lambda e: self.draw())

        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=4)
        for label, fn in (("Pause", self.toggle_pause), ("Reset", self.reset),
                          ("All", self.select_all), ("None", self.select_none)):
            b = tk.Button(btns, text=label, command=fn, bg=C["panel2"], fg=C["fg"],
                          activebackground=C["accent"], activeforeground=C["bg"],
                          relief="flat", font=UI_FONT, cursor="hand2")
            b.pack(side="left", expand=True, fill="x", padx=2)
            attach_hover(b, C["panel2"], C["fg"])

        self.stats = tk.Text(left, width=28, height=10, bg=C["panel2"], fg=C["fg"],
                             font=MONO, relief="flat", state="disabled",
                             highlightthickness=1, highlightbackground=C["border"])
        self.stats.pack(fill="both", expand=True, pady=4)

        right = ttk.Frame(self)
        right.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        self.canvas = tk.Canvas(right, bg=C["bg"], highlightthickness=1,
                                highlightbackground=C["border"])
        self.canvas.pack(fill="both", expand=True)

        threading.Thread(target=self._sampler, daemon=True).start()
        self.after(1500, self.sample)
        self.after(420, self._anim)

    def _anim(self):
        """Pulse the live-chart markers while this tab is visible."""
        try:
            if self.winfo_exists() and self.app.nb.select() == str(self):
                self._pulse += 0.55
                self.draw()
        except Exception:
            pass
        self.after(420, self._anim)

    # -- sampling -----------------------------------------------------------
    def sample(self):
        # kept for compatibility: sampling now runs in a background thread
        self.draw()
        self.after(2000, self.sample)

    def push(self, name, rxbps, txbps, rx_total=0, tx_total=0):
        """Called from the Tk event loop with data from the sampler thread."""
        try:
            self.samples.setdefault(name, deque(maxlen=self.history_len)).append((rxbps, txbps))
            self.totals[name] = (rx_total, tx_total)
            self._fill_list(list(self.samples.keys()))
            self.draw()
        except Exception:
            pass

    def _sampler(self):
        """Background sampler — never blocks the Tk main loop."""
        last = {}
        while True:
            try:
                if not self.paused:
                    cur = iface_counters()
                    ts = time.time()
                    if not cur:
                        self.app.queue.put(("traffic_hint",
                                            "no interface counters available — install psutil: pip install psutil"))
                    for name, (rx, tx) in cur.items():
                        if name in last:
                            lts, lrx, ltx = last[name]
                            dt = max(0.001, ts - lts)
                            self.app.queue.put(("traffic", name,
                                                max(0.0, (rx - lrx) / dt),
                                                max(0.0, (tx - ltx) / dt), rx, tx))
                        else:
                            self.app.queue.put(("traffic", name, 0.0, 0.0, rx, tx))
                        last[name] = (ts, rx, tx)
            except Exception:
                pass
            time.sleep(1.0)

    def _read_counters(self):
        return iface_counters() or {"total": (0, 0)}

    def _fill_list(self, names):
        cur = set(self.listbox.get(0, "end"))
        new = set(names)
        if cur != new:
            sel = [self.listbox.get(i) for i in self.listbox.curselection()]
            self.listbox.delete(0, "end")
            for n in sorted(new):
                self.listbox.insert("end", n)
            for i, n in enumerate(sorted(new)):
                if n in sel:
                    self.listbox.select_set(i)
            if not self.listbox.curselection() and self.listbox.size():
                self.listbox.select_set(0)

    def selected(self):
        return [self.listbox.get(i) for i in self.listbox.curselection()]

    # -- drawing ------------------------------------------------------------
    def draw(self):
        cv = self.canvas
        cv.delete("all")
        w = max(320, cv.winfo_width())
        h = max(220, cv.winfo_height())
        pad_l, pad_r, pad_t, pad_b = 78, 16, 28, 34
        plot_w, plot_h = w - pad_l - pad_r, h - pad_t - pad_b

        names = self.selected()[:4] or sorted(self.samples.keys())[:1]
        peak = 1.0
        for n in names:
            for rx, tx in self.samples.get(n, []):
                peak = max(peak, rx, tx)
        top = nice_step(peak * 1.15)

        if not any(len(self.samples.get(n, [])) >= 2 for n in names):
            cv.create_text(w // 2, h // 2, text="waiting for traffic samples…\n"
                           "(need 2+ seconds of interface counters)",
                           fill=C["dim"], font=UI_FONT, justify="center")
            self.stats.configure(state="normal")
            self.stats.delete("1.0", "end")
            self.stats.insert("end", "waiting for samples…\ninterfaces seen: "
                              + ", ".join(sorted(self.samples.keys())) )
            self.stats.configure(state="disabled")
            return

        # grid
        for i in range(5):
            y = pad_t + plot_h * i / 4
            cv.create_line(pad_l, y, pad_l + plot_w, y, fill=C["border"])
            val = top * (1 - i / 4)
            cv.create_text(pad_l - 8, y, text=fmt_rate(val).strip(), anchor="e",
                           fill=C["dim"], font=("Consolas" if IS_WIN else "Menlo", 8))
        cv.create_line(pad_l, pad_t, pad_l, pad_t + plot_h, fill=C["border"])
        cv.create_line(pad_l, pad_t + plot_h, pad_l + plot_w, pad_t + plot_h, fill=C["border"])

        cv.create_text(pad_l, 10, anchor="w", fill=C["accent"],
                       font=(UI_FONT[0], UI_FONT[1], "bold"),
                       text="Live throughput  (green = download/RX, orange = upload/TX)")

        stats_lines = []
        for n in names:
            data = list(self.samples.get(n, []))
            if len(data) < 2:
                continue
            for series, color in ((0, C["rx"]), (1, C["tx"])):
                pts = []
                for i, sample in enumerate(data):
                    x = pad_l + plot_w * (self.history_len - len(data) + i) / max(1, self.history_len - 1)
                    v = sample[series]
                    y = pad_t + plot_h * (1 - min(1.0, v / top))
                    pts.extend((x, y))
                if len(pts) >= 4:
                    base_y = pad_t + plot_h
                    # soft area fill + glow under the line
                    cv.create_polygon(*pts, pts[-2], base_y, pts[0], base_y,
                                      fill=blend(color, C["bg"], 0.16), outline="")
                    cv.create_line(*pts, fill=blend(color, C["bg"], 0.55), width=5,
                                   smooth=True)
                    cv.create_line(*pts, fill=color, width=2, smooth=True)
                    # pulsing dot at the leading edge
                    r = 3 + 2.2 * (0.5 + 0.5 * math.sin(self._pulse))
                    cv.create_oval(pts[-2] - r, pts[-1] - r, pts[-2] + r, pts[-1] + r,
                                   fill=color, outline=blend(color, C["bg"], 0.4))
            cur_rx, cur_tx = data[-1]
            stats_lines.append(f"{n}")
            stats_lines.append(f"  ↓ {fmt_rate(cur_rx)}")
            stats_lines.append(f"  ↑ {fmt_rate(cur_tx)}")
            tot = self.totals.get(n)
            if tot and (tot[0] or tot[1]):
                stats_lines.append(f"  total ↓{fmt_bytes(tot[0])} ↑{fmt_bytes(tot[1])}")

        # legend
        lx = pad_l + 8
        ly = pad_t + 6
        for label, col in (("RX/download", C["rx"]), ("TX/upload", C["tx"])):
            cv.create_rectangle(lx, ly - 5, lx + 14, ly + 5, fill=col, outline=col)
            cv.create_text(lx + 20, ly, text=label, anchor="w", fill=C["dim"], font=UI_FONT)
            lx += 130

        # pulsing LIVE badge
        r = 3 + 2.6 * (0.5 + 0.5 * math.sin(self._pulse))
        cv.create_oval(w - 82 - r, 14 - r, w - 82 + r, 14 + r,
                       fill=C["err"], outline="")
        cv.create_text(w - 72, 14, text="LIVE", anchor="w", fill=C["err"], font=UI_FONT)

        self.stats.configure(state="normal")
        self.stats.delete("1.0", "end")
        self.stats.insert("end", "\n".join(stats_lines) or "waiting for samples…")
        self.stats.configure(state="disabled")

    # -- buttons ------------------------------------------------------------
    def toggle_pause(self):
        self.paused = not self.paused
        self.app.status("Traffic sampling paused" if self.paused else "Traffic sampling resumed")

    def reset(self):
        self.samples.clear()
        self.last.clear()
        self.draw()

    def select_all(self):
        self.listbox.select_set(0, "end")
        self.draw()

    def select_none(self):
        self.listbox.select_clear(0, "end")
        self.draw()


class ConnPanel(ttk.Frame):
    """Active sockets / connections analyzer."""

    COLS = ("pid", "process", "proto", "local", "remote", "status")

    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.paused = False

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=8, pady=6)
        ttk.Label(bar, text="Filter:", foreground=C["accent"]).pack(side="left")
        self.filter_var = tk.StringVar()
        ent = tk.Entry(bar, textvariable=self.filter_var, bg=C["panel2"], fg=C["fg"],
                       insertbackground=C["fg"], relief="flat", font=UI_FONT, width=28)
        ent.pack(side="left", padx=6)
        ent.bind("<Return>", lambda e: self.refresh())
        for label, fn in (("Refresh", self.refresh), ("Pause/Resume", self.toggle),
                          ("Export CSV", self.export)):
            tk.Button(bar, text=label, command=fn, bg=C["panel2"], fg=C["fg"],
                      activebackground=C["accent"], activeforeground=C["bg"],
                      relief="flat", font=UI_FONT, cursor="hand2").pack(side="left", padx=3)

        wrap = ttk.Frame(self)
        wrap.pack(fill="both", expand=True, padx=8, pady=4)
        self.tree = ttk.Treeview(wrap, columns=self.COLS, show="headings", selectmode="extended")
        widths = {"pid": 70, "process": 150, "proto": 70, "local": 220, "remote": 220, "status": 100}
        for c in self.COLS:
            self.tree.heading(c, text=c.upper(), command=lambda cc=c: self._sort(cc))
            self.tree.column(c, width=widths[c], anchor="w")
        ys = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")

        self._sort_col = "pid"
        self._sort_rev = False
        self.after(400, self._loop)

    def _loop(self):
        self.refresh()
        self.after(2500, self._loop)

    def toggle(self):
        self.paused = not self.paused

    def refresh(self):
        if not self.paused:
            rows = self._gather()
            f = self.filter_var.get().strip().lower()
            if f:
                rows = [r for r in rows if any(f in str(x).lower() for x in r)]
            rows.sort(key=lambda r: str(r[self.COLS.index(self._sort_col)]),
                      reverse=self._sort_rev)
            self.tree.delete(*self.tree.get_children())
            for r in rows[:4000]:
                self.tree.insert("", "end", values=r)
            self.app.status(f"{len(rows)} connections")

    def _gather(self):
        rows = []
        if HAVE_PSUTIL:
            try:
                for c in psutil.net_connections(kind="inet"):
                    laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                    raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                    name = ""
                    try:
                        if c.pid:
                            name = psutil.Process(c.pid).name()
                    except Exception:
                        name = "?"
                    rows.append((c.pid or "-", name, c.type.name.lower(), laddr, raddr, c.status))
                return rows
            except Exception:
                pass
        # fallback: netstat parse
        try:
            out = subprocess.run(cmd_netstat(), capture_output=True, text=True, timeout=15,
                                 **{k: v for k, v in popen_kwargs().items()
                                    if k in ("creationflags",)}).stdout or ""
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4 and ("tcp" in parts[0].lower() or "udp" in parts[0].lower()):
                    rows.append(("-", "-", parts[0], parts[1], parts[2],
                                 parts[3] if len(parts) > 3 else ""))
        except Exception:
            pass
        return rows

    def _sort(self, col):
        if self._sort_col == col:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col, self._sort_rev = col, False
        self.refresh()

    def export(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")],
                                            initialfile=f"netprobe-connections-{int(time.time())}.csv")
        if not path:
            return
        import csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(self.COLS)
            for item in self.tree.get_children():
                w.writerow(self.tree.item(item, "values"))
        self.app.status(f"Saved {path}")


class MatrixPanel(ttk.Frame):
    """Probe many hosts in parallel — compare DNS / latency / loss."""

    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        top = ttk.Frame(self)
        top.pack(fill="x", padx=8, pady=6)
        ttk.Label(top, text="Hosts (one per line):", foreground=C["accent"]).pack(anchor="w")
        self.hosts = tk.Text(top, height=5, bg=C["panel2"], fg=C["fg"], insertbackground=C["fg"],
                             font=MONO, relief="flat", highlightthickness=1,
                             highlightbackground=C["border"])
        self.hosts.pack(fill="x", pady=4)
        self.hosts.insert("end", "1.1.1.1\n8.8.8.8\ngoogle.com\ngithub.com\ncloudflare.com")
        for label, fn in (("Run Matrix", self.run), ("Stop", self.stop),
                          ("Export CSV", self.export)):
            tk.Button(top, text=label, command=fn, bg=C["panel2"], fg=C["fg"],
                      activebackground=C["accent"], activeforeground=C["bg"],
                      relief="flat", font=UI_FONT, cursor="hand2").pack(side="left", padx=3)

        wrap = ttk.Frame(self)
        wrap.pack(fill="both", expand=True, padx=8, pady=4)
        cols = ("host", "ip", "dns_ms", "tcp_min", "tcp_avg", "tcp_max", "loss", "status")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings")
        widths = {"host": 200, "ip": 160, "dns_ms": 90, "tcp_min": 90,
                  "tcp_avg": 90, "tcp_max": 90, "loss": 80, "status": 160}
        for c in cols:
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=widths[c], anchor="w")
        self.tree.tag_configure("good", foreground=C["ok"])
        self.tree.tag_configure("bad", foreground=C["err"])
        self.tree.tag_configure("warn", foreground=C["warn"])
        ys = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self._stop = threading.Event()
        self._rows = []

    def run(self):
        hosts = [h.strip() for h in self.hosts.get("1.0", "end").splitlines() if h.strip()]
        if not hosts:
            return
        self._stop.clear()
        self.tree.delete(*self.tree.get_children())
        self._rows = []
        self.app.terminal.banner(["matrix-probe"] + hosts)
        threading.Thread(target=self._work, args=(hosts,), daemon=True).start()

    def _work(self, hosts):
        threads = []
        results = {}

        def one(h):
            if self._stop.is_set():
                return
            try:
                results[h] = probe_host(h)
            except Exception as e:
                results[h] = {"host": h, "error": str(e)}

        for h in hosts:
            t = threading.Thread(target=one, args=(h,), daemon=True)
            threads.append(t)
            t.start()
            if len(threads) >= 6:
                for tt in threads:
                    tt.join()
                threads = []
        for tt in threads:
            tt.join()

        for h in hosts:
            r = results.get(h, {"host": h, "error": "skipped"})
            self.app.queue.put(("matrix", r))

    def stop(self):
        self._stop.set()
        self.app.status("Matrix probe stopped")

    def add_row(self, r: dict):
        ip = ", ".join(r.get("addrs", [])[:2]) if r.get("addrs") else "-"
        err = r.get("error")
        if err:
            tag = "bad"
            status = err
        elif r.get("loss", 0) >= 50:
            tag = "bad"
            status = "high loss"
        elif r.get("tcp_avg", 0) > 250 or r.get("loss", 0) > 0:
            tag = "warn"
            status = "degraded"
        else:
            tag = "good"
            status = "ok"
        self.tree.insert("", "end", tags=(tag,), values=(
            r.get("host", ""), ip,
            f"{r['dns_ms']:.1f}" if r.get("dns_ms") is not None else "-",
            f"{r['tcp_min']:.1f}" if r.get("tcp_min") is not None else "-",
            f"{r['tcp_avg']:.1f}" if r.get("tcp_avg") is not None else "-",
            f"{r['tcp_max']:.1f}" if r.get("tcp_max") is not None else "-",
            f"{r.get('loss', 0):.0f}%", status))
        self._rows.append(r)

    def export(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")],
                                            initialfile=f"netprobe-matrix-{int(time.time())}.csv")
        if not path:
            return
        import csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(("host", "ip", "dns_ms", "tcp_min", "tcp_avg", "tcp_max", "loss"))
            for r in self._rows:
                w.writerow((r.get("host"), ", ".join(r.get("addrs", [])), r.get("dns_ms"),
                            r.get("tcp_min"), r.get("tcp_avg"), r.get("tcp_max"), r.get("loss")))
        self.app.status(f"Saved {path}")


class PingGraphPanel(ttk.Frame):
    """Continuous parallel pings to many hosts — overlaid latency graph for comparison."""

    COLORS = ["#37b6ff", "#57d98a", "#f2c14e", "#ff6b6b", "#9b8cff",
              "#26c6da", "#f2994a", "#e2e2e2"]

    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.history = {}      # label -> deque[(ts, ms|None)]
        self.running = False
        self.stop_ev = threading.Event()
        self.window = 180      # points shown
        self._pulse = 0.0

        top = tk.Frame(self, bg=C["bg"])
        top.pack(fill="x", pady=(0, 6))
        tk.Label(top, text="Hosts (host or host:port, comma separated):",
                 bg=C["bg"], fg=C["accent"], font=UI_FONT).pack(anchor="w")
        self.hosts_var = tk.StringVar(
            value="1.1.1.1:443, 8.8.8.8:53, google.com:443, github.com:443")
        tk.Entry(top, textvariable=self.hosts_var, bg=C["panel2"], fg=C["fg"],
                 insertbackground=C["fg"], relief="flat", font=MONO).pack(fill="x", pady=3)

        opts = tk.Frame(self, bg=C["bg"])
        opts.pack(fill="x", pady=(0, 4))
        tk.Label(opts, text="interval(s):", bg=C["bg"], fg=C["dim"], font=UI_FONT).pack(side="left")
        self.interval_var = tk.StringVar(value="1")
        tk.Entry(opts, textvariable=self.interval_var, width=5, bg=C["panel2"], fg=C["fg"],
                 insertbackground=C["fg"], relief="flat", font=MONO).pack(side="left", padx=4)
        tk.Label(opts, text="duration(s):", bg=C["bg"], fg=C["dim"], font=UI_FONT).pack(side="left")
        self.duration_var = tk.StringVar(value="0")
        tk.Entry(opts, textvariable=self.duration_var, width=6, bg=C["panel2"], fg=C["fg"],
                 insertbackground=C["fg"], relief="flat", font=MONO).pack(side="left", padx=4)
        tk.Label(opts, text="(0 = run until stopped)", bg=C["bg"], fg=C["dim"],
                 font=UI_FONT).pack(side="left", padx=6)
        for label, fn, col in (("▶ Start", self.start, C["accent"]),
                               ("■ Stop", self.stop, C["err"]),
                               ("Reset", self.reset, C["panel2"]),
                               ("Export CSV", self.export, C["panel2"])):
            b = tk.Button(opts, text=label, command=fn, bg=col,
                          fg=C["bg"] if col in (C["accent"], C["err"]) else C["fg"],
                          activebackground=C["border"], relief="flat", font=UI_FONT,
                          cursor="hand2", padx=10)
            b.pack(side="left", padx=3)
            attach_hover(b, col, C["bg"] if col in (C["accent"], C["err"]) else C["fg"])

        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(body, bg=C["bg"], highlightthickness=1,
                                highlightbackground=C["border"])
        self.canvas.pack(side="left", fill="both", expand=True)
        self.stats = tk.Text(body, width=32, bg=C["panel2"], fg=C["fg"], font=MONO,
                             relief="flat", state="disabled", highlightthickness=1,
                             highlightbackground=C["border"])
        self.stats.pack(side="right", fill="y", padx=(6, 0))
        self.after(420, self._anim)

    def _anim(self):
        """Pulse the line-end markers while this tab is visible."""
        try:
            if self.winfo_exists() and self.app.nb.select() == str(self):
                self._pulse += 0.55
                self.draw()
        except Exception:
            pass
        self.after(420, self._anim)

    # -- control ------------------------------------------------------------
    def start(self):
        if self.running:
            self.app.status("ping graph already running")
            return
        hosts = []
        for raw in self.hosts_var.get().split(","):
            raw = raw.strip()
            if not raw:
                continue
            if ":" in raw and raw.rsplit(":", 1)[1].isdigit():
                h, p = raw.rsplit(":", 1)
                hosts.append((h, int(p)))
            else:
                hosts.append((raw, None))
        if not hosts:
            return
        try:
            interval = max(0.2, float(self.interval_var.get()))
        except Exception:
            interval = 1.0
        try:
            duration = max(0.0, float(self.duration_var.get()))
        except Exception:
            duration = 0.0
        self.reset()
        self.running = True
        self.stop_ev.clear()
        self.app.status(f"ping graph: {len(hosts)} host(s) × every {interval}s")
        threading.Thread(target=self._work, args=(hosts, interval, duration),
                         daemon=True).start()

    def stop(self):
        self.running = False
        self.stop_ev.set()
        self.app.status("ping graph stopped")

    def reset(self):
        self.history.clear()
        self.draw()

    def _work(self, hosts, interval, duration):
        t_end = time.time() + duration if duration else None
        while self.running and not self.stop_ev.is_set():
            if t_end and time.time() >= t_end:
                break
            t0 = time.time()
            results = {}
            threads = []
            for h, p in hosts:
                label = f"{h}:{p}" if p else h

                def one(lbl=label, hh=h, pp=p):
                    results[lbl] = probe_latency(hh, pp)
                th = threading.Thread(target=one, daemon=True)
                threads.append(th)
                th.start()
            for th in threads:
                th.join(timeout=4)
            ts = time.time()
            for label in [f"{h}:{p}" if p else h for h, p in hosts]:
                self.app.queue.put(("pinggraph", label, ts, results.get(label)))
            time.sleep(max(0.05, interval - (time.time() - t0)))
        self.app.queue.put(("pinggraph_done",))

    # -- data + drawing -----------------------------------------------------
    def push(self, label, ts, ms):
        self.history.setdefault(label, deque(maxlen=3000)).append((ts, ms))
        self.draw()

    def draw(self):
        cv = self.canvas
        cv.delete("all")
        w = max(360, cv.winfo_width())
        h = max(220, cv.winfo_height())
        pad_l, pad_r, pad_t, pad_b = 84, 130, 30, 30
        plot_w, plot_h = w - pad_l - pad_r, h - pad_t - pad_b

        if not self.history:
            cv.create_text(w // 2, h // 2, text="press ▶ Start to compare ping latency\n"
                           "of several hosts on one chart",
                           fill=C["dim"], font=UI_FONT, justify="center")
            return

        peak = 1.0
        for data in self.history.values():
            for _ts, ms in list(data)[-self.window:]:
                if ms is not None:
                    peak = max(peak, ms)
        top_v = nice_step(peak * 1.15)

        for i in range(5):
            y = pad_t + plot_h * i / 4
            cv.create_line(pad_l, y, pad_l + plot_w, y, fill=C["border"])
            cv.create_text(pad_l - 8, y, text=f"{top_v * (1 - i / 4):.0f} ms", anchor="e",
                           fill=C["dim"], font=("Consolas" if IS_WIN else "Menlo", 8))
        cv.create_line(pad_l, pad_t, pad_l, pad_t + plot_h, fill=C["border"])
        cv.create_line(pad_l, pad_t + plot_h, pad_l + plot_w, pad_t + plot_h, fill=C["border"])
        cv.create_text(pad_l, 10, anchor="w", fill=C["accent"],
                       font=(UI_FONT[0], UI_FONT[1], "bold"),
                       text=f"Ping comparison — last {self.window} probes per host  (gaps = packet loss)")

        stats_lines = []
        for idx, (label, data) in enumerate(self.history.items()):
            color = self.COLORS[idx % len(self.COLORS)]
            pts_data = list(data)[-self.window:]
            n = len(pts_data)
            seg, gap = [], []
            for i, (_ts, ms) in enumerate(pts_data):
                x = pad_l + plot_w * (self.window - n + i) / max(1, self.window - 1)
                if ms is None:
                    if len(seg) >= 4:
                        cv.create_line(*seg, fill=color, width=2)
                    seg = []
                    gap.append(x)
                else:
                    y = pad_t + plot_h * (1 - min(1.0, ms / top_v))
                    seg.extend((x, y))
            if len(seg) >= 4:
                cv.create_line(*seg, fill=blend(color, C["bg"], 0.5), width=6)
                cv.create_line(*seg, fill=color, width=2)
            for x in gap:
                cv.create_line(x, pad_t, x, pad_t + plot_h, fill=C["err"], dash=(2, 4))
            # end-of-line label + pulsing dot
            ok = [ms for _ts, ms in pts_data if ms is not None]
            last = ok[-1] if ok else None
            y_end = (pad_t + plot_h * (1 - min(1.0, last / top_v))) if last is not None else pad_t + 8
            if last is not None:
                r = 2.6 + 2.2 * (0.5 + 0.5 * math.sin(self._pulse + idx))
                cv.create_oval(pad_l + plot_w - r, y_end - r,
                               pad_l + plot_w + r, y_end + r,
                               fill=color, outline=blend(color, C["bg"], 0.4))
            cv.create_text(pad_l + plot_w + 6, y_end, text=label[:18], anchor="w",
                           fill=color, font=("Consolas" if IS_WIN else "Menlo", 8))
            loss = 100.0 * (n - len(ok)) / max(1, n)
            stats_lines.append(label[:28])
            stats_lines.append(f"  last {(f'{last:.1f}' if last is not None else 'timeout'):>8} ms")
            stats_lines.append(f"  avg  {(f'{sum(ok)/len(ok):.1f}' if ok else '-'):>8} ms")
            stats_lines.append(f"  min  {(f'{min(ok):.1f}' if ok else '-'):>8} ms")
            stats_lines.append(f"  max  {(f'{max(ok):.1f}' if ok else '-'):>8} ms")
            stats_lines.append(f"  loss {loss:8.1f} %")
            stats_lines.append("")

        self.stats.configure(state="normal")
        self.stats.delete("1.0", "end")
        self.stats.insert("end", "\n".join(stats_lines))
        self.stats.configure(state="disabled")

    def export(self):
        if not self.history:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile=f"netprobe-pinggraph-{int(time.time())}.csv")
        if not path:
            return
        import csv
        labels = list(self.history.keys())
        with open(path, "w", newline="", encoding="utf-8") as f:
            wcsv = csv.writer(f)
            wcsv.writerow(["timestamp"] + labels)
            maxlen = max(len(d) for d in self.history.values())
            for i in range(maxlen):
                row = []
                ts_ref = None
                for lb in labels:
                    d = list(self.history[lb])
                    if i < len(d):
                        ts_ref = ts_ref or d[i][0]
                        row.append("" if d[i][1] is None else f"{d[i][1]:.2f}")
                    else:
                        row.append("")
                wcsv.writerow([datetime.datetime.fromtimestamp(ts_ref).isoformat() if ts_ref else ""] + row)
        self.app.status(f"saved {path}")


# ----------------------------------------------------------------------------
# Protocol Lab panel
# ----------------------------------------------------------------------------
class ProtocolPanel(ttk.Frame):
    """Structured protocol tests grouped by OSI layer, with live results."""

    LAYERS = [
        ("Layer 7 · Application", [
            ("http", "HTTP / HTTPS", "80 / 443"),
            ("dns", "DNS", "53 udp+tcp"),
            ("dhcp", "DHCP", "67 / 68 udp"),
            ("ftp", "FTP / SFTP", "21 / 22"),
            ("mail", "SMTP / POP3 / IMAP", "25/110/143 + TLS"),
            ("ssh", "SSH", "22"),
            ("snmp", "SNMP", "161 udp"),
        ]),
        ("Layer 4 · Transport", [
            ("tcp", "TCP", "handshake"),
            ("udp", "UDP", "datagram"),
            ("quic", "QUIC", "443 udp"),
        ]),
        ("Layer 3 · Network / Internet", [
            ("ip", "IPv4 / IPv6", "dual-stack"),
            ("icmp", "ICMP", "echo"),
            ("ospf", "OSPF", "IP proto 89"),
            ("bgp", "BGP", "tcp 179"),
        ]),
        ("Layer 2 · Data Link", [
            ("arp", "ARP", "neighbour cache"),
            ("eth", "Ethernet", "link state"),
            ("wifi", "Wi-Fi (802.11)", "signal"),
        ]),
    ]
    TESTS = PROTOCOL_TESTS

    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.running = False
        self.stop_ev = threading.Event()
        self.results = {}          # key -> [(tag, line)]
        self.status = {}           # key -> (status, summary)
        self._spin_i = 0
        self._build()
        self.after(140, self._spin)

    # -- layout -------------------------------------------------------------
    def _build(self):
        top = tk.Frame(self, bg=C["bg"])
        top.pack(fill="x", pady=(0, 4))
        for label, fn, col in (("▶ Run Selected", self.run_selected, C["accent"]),
                               ("Run Layer", self.run_layer, C["panel2"]),
                               ("Run All (17)", self.run_all, C["panel2"]),
                               ("■ Stop", self.stop, C["err"]),
                               ("Clear", self.clear, C["panel2"]),
                               ("Export", self.export, C["panel2"])):
            b = tk.Button(top, text=label, command=fn, bg=col,
                          fg=C["bg"] if col in (C["accent"], C["err"]) else C["fg"],
                          activebackground=C["border"], activeforeground=C["fg"],
                          relief="flat", font=UI_FONT, cursor="hand2", padx=10)
            b.pack(side="left", padx=3)
            attach_hover(b, col, C["bg"] if col in (C["accent"], C["err"]) else C["fg"])
        tk.Label(top, text="select a row for full output · target host comes from the "
                           "top bar",
                 bg=C["bg"], fg=C["dim"], font=UI_FONT).pack(side="right", padx=8)

        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True)

        left = tk.Frame(body, bg=C["bg"])
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        self.tree = ttk.Treeview(left, columns=("endpoint", "status", "summary"),
                                 selectmode="browse", height=16)
        self.tree.heading("#0", text="OSI layer / protocol")
        self.tree.heading("endpoint", text="endpoint")
        self.tree.heading("status", text="status")
        self.tree.heading("summary", text="result")
        self.tree.column("#0", width=230, stretch=True)
        self.tree.column("endpoint", width=110, anchor="center", stretch=False)
        self.tree.column("status", width=80, anchor="center", stretch=False)
        self.tree.column("summary", width=230, stretch=True)
        ys = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ys.pack(side="left", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        right = tk.Frame(body, bg=C["bg"], width=430)
        right.pack(side="left", fill="both", expand=True)
        self.detail = tk.Text(right, wrap="none", bg=C["bg"], fg=C["fg"],
                              insertbackground=C["fg"], font=MONO, relief="flat",
                              padx=8, pady=6)
        ds = ttk.Scrollbar(right, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=ds.set)
        self.detail.pack(side="left", fill="both", expand=True)
        ds.pack(side="left", fill="y")
        self.detail.tag_configure("cmd", foreground=C["cmd"],
                                  font=(MONO[0], MONO[1], "bold"))
        self.detail.tag_configure("ok", foreground=C["ok"])
        self.detail.tag_configure("warn", foreground=C["warn"])
        self.detail.tag_configure("err", foreground=C["err"],
                                  font=(MONO[0], MONO[1], "bold"))
        self.detail.tag_configure("info", foreground=C["dim"])
        self.detail.tag_configure("title", foreground=C["accent"],
                                  font=(MONO[0], MONO[1], "bold"))
        self.detail.tag_configure("head", foreground=C["head"])

        for li, (layer, items) in enumerate(self.LAYERS):
            lid = f"layer{li}"
            self.tree.insert("", "end", iid=lid, text=f"  {layer}", open=True,
                             values=("", "", f"{len(items)} tests"))
            for key, label, ep in items:
                self.tree.insert(lid, "end", iid=f"p:{key}", text=f"    {label}",
                                 values=(ep, "—", ""))
                self.status[key] = ("—", "")
                self.results[key] = []

    # -- animated status ----------------------------------------------------
    def _spin(self):
        self._spin_i += 1
        try:
            for key, (st, _s) in self.status.items():
                if st == "running":
                    self.tree.set(f"p:{key}", "status",
                                  SPIN_FRAMES[self._spin_i % len(SPIN_FRAMES)])
        except Exception:
            pass
        self.after(140, self._spin)

    # -- run controls -------------------------------------------------------
    def _keys_of(self, node):
        return [c[2:] for c in self.tree.get_children(node) if c.startswith("p:")]

    def run_selected(self):
        sel = self.tree.selection()
        keys = []
        for s in sel:
            keys.extend(self._keys_of(s) if s.startswith("layer") else
                        ([s[2:]] if s.startswith("p:") else []))
        if not keys:
            self.app.status("protocol lab: select a row first")
            return
        self._start(keys)

    def run_layer(self):
        sel = self.tree.selection()
        if not sel:
            self.app.status("protocol lab: select a layer or protocol row first")
            return
        node = sel[0]
        if node.startswith("p:"):
            node = self.tree.parent(node)
        keys = self._keys_of(node)
        if keys:
            self._start(keys)

    def run_layer_index(self, idx):
        keys = self._keys_of(f"layer{idx}")
        if keys:
            self._start(keys)

    def run_all(self):
        self._start([k for _layer, items in self.LAYERS for k, _lbl, _ep in items])

    def stop(self):
        self.stop_ev.set()
        self.app.status("protocol lab: stopping after the current probe…")

    def _start(self, keys):
        if self.running:
            self.app.status("protocol lab already running — press ■ Stop first")
            return
        self.running = True
        self.stop_ev.clear()
        for k in keys:
            self.status[k] = ("running", "")
            self.results[k] = []
            self.tree.set(f"p:{k}", "summary", "")
        self.app.status(f"protocol lab: running {len(keys)} test(s) against "
                        f"{self.app.host()}")
        threading.Thread(target=self._work, args=(keys, self.app.host()),
                         daemon=True).start()

    def _work(self, keys, host):
        for k in keys:
            if self.stop_ev.is_set():
                break
            fn = self.TESTS.get(k)
            if fn is None:
                continue
            self.app.queue.put(("proto_start", k))

            def emit(t, tag="head", _k=k):
                self.app.queue.put(("proto_line", _k, tag, t))

            try:
                st, summary = fn(host, emit, self.stop_ev)
            except Exception as e:
                st, summary = "FAIL", f"error: {e}"
            self.app.queue.put(("proto_done", k, st, summary))
        self.app.queue.put(("proto_all_done",))

    # -- results ------------------------------------------------------------
    def add_line(self, key, tag, text):
        self.results.setdefault(key, []).append((tag, text))
        try:
            sel = self.tree.selection()
            if sel and sel[0] == f"p:{key}":
                self.detail.insert("end", text + "\n", tag)
                self.detail.see("end")
        except Exception:
            pass

    def set_status(self, key, st, summary):
        self.status[key] = (st, summary)
        try:
            self.tree.set(f"p:{key}", "status", st)
            self.tree.set(f"p:{key}", "summary", summary)
            sel = self.tree.selection()
            if sel and sel[0] == f"p:{key}":
                self._on_select()          # keep the detail header in sync
        except Exception:
            pass

    def finish(self):
        self.running = False
        self.app.status("protocol lab: all requested tests finished")

    def _on_select(self, _evt=None):
        sel = self.tree.selection()
        if not sel or not sel[0].startswith("p:"):
            return
        key = sel[0][2:]
        label = self.tree.item(sel[0], "text").strip()
        st, summary = self.status.get(key, ("—", ""))
        self.detail.delete("1.0", "end")
        self.detail.insert("end", f"{label}  —  {st}", "title")
        if summary:
            self.detail.insert("end", f"   {summary}", "title")
        self.detail.insert("end", "\n" + "─" * 60 + "\n", "info")
        for tag, text in self.results.get(key, []):
            self.detail.insert("end", text + "\n", tag)
        if not self.results.get(key):
            self.detail.insert("end", "  (not run yet — press ▶ Run Selected)", "info")
        self.detail.see("1.0")

    def clear(self):
        for key in self.results:
            self.results[key] = []
            self.status[key] = ("—", "")
            try:
                self.tree.set(f"p:{key}", "status", "—")
                self.tree.set(f"p:{key}", "summary", "")
            except Exception:
                pass
        self.detail.delete("1.0", "end")
        self.app.status("protocol lab: results cleared")

    def export(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log", "*.log"), ("Text", "*.txt"), ("All", "*.*")],
            initialfile=f"netprobe-protocols-"
                        f"{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.log")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"{APP_NAME} v{VERSION} — Protocol Lab\n")
            f.write(f"target: {self.app.host()}   {datetime.datetime.now()}\n")
            for layer, items in self.LAYERS:
                f.write(f"\n== {layer} " + "=" * max(0, 56 - len(layer)) + "\n")
                for key, label, ep in items:
                    st, summary = self.status.get(key, ("—", ""))
                    f.write(f"\n--- {label} ({ep})  [{st}] {summary}\n")
                    for _tag, text in self.results.get(key, []):
                        f.write(text + "\n")
        self.app.status(f"protocol lab: saved {path}")


# ----------------------------------------------------------------------------
# Main application
# ----------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.theme_name = load_theme_name()
        if self.theme_name in THEMES:
            C.update(THEMES[self.theme_name])
        self.title(f"{APP_NAME} v{VERSION} — Portable Network Testing & Traffic Analysis")
        self.geometry("1280x820")
        self.minsize(1024, 680)
        self.configure(bg=C["bg"])
        self.queue = queue.Queue()
        self.proc = None
        self.stop_flag = threading.Event()
        self.monitor_running = False
        self._build_style()
        self._build_ui()
        self._bind_keys()
        self.protocol("WM_DELETE_WINDOW", self._close_animated)
        self.after(100, self._poll)
        self.after(300, self._intro)
        self._fade(0.0, 1.0)          # smooth window fade-in

    # -- styling ------------------------------------------------------------
    def _build_style(self):
        self.option_add("*TButton.padding", 6)
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", background=C["bg"], foreground=C["fg"], font=UI_FONT)
        style.configure("TFrame", background=C["bg"])
        style.configure("TLabelframe", background=C["bg"], foreground=C["accent"])
        style.configure("TLabelframe.Label", background=C["bg"], foreground=C["accent"])
        style.configure("TNotebook", background=C["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=C["panel2"], foreground=C["fg"], padding=(14, 6))
        style.map("TNotebook.Tab", background=[("selected", C["accent"])],
                  foreground=[("selected", C["bg"])])
        style.configure("Treeview", background=C["panel"], fieldbackground=C["panel"],
                        foreground=C["fg"], rowheight=24, font=UI_FONT)
        style.configure("Treeview.Heading", background=C["panel2"], foreground=C["accent"],
                        font=(UI_FONT[0], UI_FONT[1], "bold"))
        style.map("Treeview", background=[("selected", C["accent"])],
                  foreground=[("selected", C["bg"])])
        style.configure("Vertical.TScrollbar", background=C["panel2"], troughcolor=C["bg"],
                        bordercolor=C["bg"], arrowcolor=C["dim"])
        style.configure("Horizontal.TScrollbar", background=C["panel2"], troughcolor=C["bg"],
                        bordercolor=C["bg"], arrowcolor=C["dim"])

    # -- layout -------------------------------------------------------------
    def _build_ui(self):
        # top bar
        top = tk.Frame(self, bg=C["panel"], highlightthickness=1,
                       highlightbackground=C["border"])
        top.pack(fill="x", padx=8, pady=(8, 4))
        tk.Label(top, text="  Target host:", bg=C["panel"], fg=C["accent"], font=UI_FONT).pack(side="left")
        self.host_var = tk.StringVar(value="8.8.8.8")
        self.host_entry = tk.Entry(top, textvariable=self.host_var, width=26,
                                   bg=C["panel2"], fg=C["fg"], insertbackground=C["fg"],
                                   relief="flat", font=MONO)
        self.host_entry.pack(side="left", padx=6, pady=6)
        tk.Label(top, text="Count:", bg=C["panel"], fg=C["dim"], font=UI_FONT).pack(side="left")
        self.count_var = tk.StringVar(value="4")
        tk.Entry(top, textvariable=self.count_var, width=4, bg=C["panel2"], fg=C["fg"],
                 insertbackground=C["fg"], relief="flat", font=MONO).pack(side="left", padx=4)
        self.host_entry.bind("<Return>", lambda e: self.run_selected())

        for label, fn, col in (("▶ Run (F5)", self.run_selected, C["accent"]),
                               ("■ Stop", self.stop_command, C["err"]),
                               ("Clear", self.clear_terminal, C["panel2"]),
                               ("Save Log", self.save_log, C["panel2"]),
                               ("Copy", self.copy_terminal, C["panel2"])):
            self._btn(top, label, fn, col).pack(side="left", padx=4, pady=6)

        # theme picker (background + text colours, applied live)
        tk.Label(top, text="Theme:", bg=C["panel"], fg=C["dim"],
                 font=UI_FONT).pack(side="right", padx=(8, 2))
        self.theme_var = tk.StringVar(value=self.theme_name)
        self.theme_opt = tk.OptionMenu(top, self.theme_var, *THEME_NAMES,
                                       command=self._on_theme_pick)
        self.theme_opt.configure(bg=C["panel2"], fg=C["fg"], activebackground=C["accent"],
                                 activeforeground=C["bg"], highlightthickness=0,
                                 relief="flat", font=UI_FONT, width=15,
                                 indicatoron=False, cursor="hand2")
        self.theme_opt["menu"].configure(bg=C["panel2"], fg=C["fg"],
                                         activebackground=C["accent"],
                                         activeforeground=C["bg"], relief="flat",
                                         font=UI_FONT)
        self.theme_opt.pack(side="right", padx=4, pady=6)
        attach_hover(self.theme_opt, C["panel2"], C["fg"])

        # body: sidebar + notebook
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=8, pady=4)

        side = tk.Frame(body, bg=C["panel"], width=250, highlightthickness=1,
                        highlightbackground=C["border"])
        side.pack(side="left", fill="y", padx=(0, 8))
        side.pack_propagate(False)

        side_cv = tk.Canvas(side, bg=C["panel"], highlightthickness=0)
        side_sb = ttk.Scrollbar(side, orient="vertical", command=side_cv.yview)
        side_cv.configure(yscrollcommand=side_sb.set)
        side_sb.pack(side="right", fill="y")
        side_cv.pack(side="left", fill="both", expand=True)
        side_in = tk.Frame(side_cv, bg=C["panel"])
        side_cv.create_window((0, 0), window=side_in, anchor="nw")
        side_in.bind("<Configure>",
                     lambda e: side_cv.configure(scrollregion=side_cv.bbox("all")))

        def _mousewheel(ev):
            side_cv.yview_scroll(-1 * (ev.delta // 120 if ev.delta else 0), "units")
        side_cv.bind("<Enter>", lambda e: (
            side_cv.bind_all("<MouseWheel>", _mousewheel),
            side_cv.bind_all("<Button-4>", lambda ev: side_cv.yview_scroll(-1, "units")),
            side_cv.bind_all("<Button-5>", lambda ev: side_cv.yview_scroll(1, "units"))))
        side_cv.bind("<Leave>", lambda e: (
            side_cv.unbind_all("<MouseWheel>"),
            side_cv.unbind_all("<Button-4>"),
            side_cv.unbind_all("<Button-5>")))

        self.actions = []

        def section(title):
            tk.Label(side_in, text=title, bg=C["panel"], fg=C["accent"],
                     font=(UI_FONT[0], UI_FONT[1], "bold")).pack(anchor="w", padx=10,
                                                                 pady=(10, 4))

        def action(label, fn):
            b = tk.Button(side_in, text=label, command=fn, anchor="w", bg=C["panel2"],
                          fg=C["fg"], activebackground=C["accent"],
                          activeforeground=C["bg"], relief="flat", font=MONO,
                          cursor="hand2", pady=4)
            b.pack(fill="x", padx=8, pady=1)
            attach_hover(b, C["panel2"], C["fg"], lift=0.10)
            self.actions.append((label, fn))

        section("QUICK TESTS")
        action("Ping                Ctrl+1", lambda: self.run_cmd(cmd_ping(self.host(), self.count())))
        action("Traceroute          Ctrl+2", lambda: self.run_cmd(cmd_trace(self.host())))
        action("DNS Lookup          Ctrl+3", lambda: self.run_cmd(cmd_dns(self.host())))
        action("HTTP Timing         Ctrl+4", self.run_http_probe)
        action("Speed Test          Ctrl+5", self.run_speed_test)
        action("Interfaces          Ctrl+6", lambda: self.run_cmd(cmd_interfaces()))
        action("Routing Table       Ctrl+7", lambda: self.run_cmd(cmd_routes()))
        action("ARP Table           Ctrl+8", lambda: self.run_cmd(cmd_arp()))
        action("Wi-Fi Info          Ctrl+9", lambda: self.run_cmd(cmd_wifi()))
        action("Wi-Fi Scan          Ctrl+W", lambda: self.run_cmd(cmd_wifi_scan()))
        action("Active Connections  Ctrl+K", lambda: self.run_cmd(cmd_netstat()))
        action("Listening Ports     Ctrl+G", self.run_listening_ports)
        action("Protocol Stats      Ctrl+A", self.run_netstat_stats)
        action("IP / Geo / ASN      Ctrl+I", self.run_ip_info)
        action("Reverse DNS (PTR)   Ctrl+V", self.run_reverse_dns)
        action("DNS Trace           Ctrl+Q", self.run_dns_trace)
        action("TCP Port Check      Ctrl+O", self.run_port_check)
        action("Path MTU            Ctrl+H", self.run_mtu)
        action("Gateway Check       Ctrl+Y", self.run_gateway_check)
        action("Internet Check      Ctrl+X", self.run_internet_check)
        action("Flush DNS Cache     Ctrl+F", lambda: self.run_cmd(cmd_flush_dns()))
        action("Full Diagnose       Ctrl+D", self.run_full_diagnose)
        action("SUPER Diagnose      Ctrl+0", self.run_super_diagnose)

        section("TRAFFIC MONITORS")
        action("Ping Graph (compare)Ctrl+E", self.show_pinggraph)
        action("Traffic Charts      Ctrl+T", self.show_traffic)
        action("Host Matrix (multi) Ctrl+M", self.show_matrix)
        action("mDNS Discovery      Ctrl+B", self.run_mdns_browse)
        action("mDNS Monitor 30s    Ctrl+U", self.run_mdns_monitor)
        action("ARP Watch 60s       Ctrl+R", self.run_arp_watch)
        action("Latency Monitor 30s Ctrl+P", self.run_latency_monitor)
        action("ICMP Ping Monitor   Ctrl+Shift+P", self.run_icmp_monitor)
        action("HTTP Endpoint Watch Ctrl+Shift+H", self.run_http_watch)
        action("Route Change Watch  Ctrl+Shift+R", self.run_route_watch)
        action("Wi-Fi Signal Watch  Ctrl+Shift+W", self.run_wifi_watch)
        action("Error/Drop Watch    Ctrl+Shift+E", self.run_error_watch)
        action("DNS Compare         Ctrl+N", self.run_dns_compare)
        action("Top Talkers         Ctrl+J", self.run_top_talkers)

        section("PROTOCOL LAB (OSI)")
        action("Protocol Lab         Ctrl+Shift+L", self.show_protocol)
        action("Run ALL protocols    Ctrl+Shift+K", self.run_all_protocols)
        action("▸ Application layer", lambda: self.run_protocol_layer(0))
        action("▸ Transport layer", lambda: self.run_protocol_layer(1))
        action("▸ Network layer", lambda: self.run_protocol_layer(2))
        action("▸ Data-link layer", lambda: self.run_protocol_layer(3))

        section("CUSTOM COMMAND")
        self.custom_var = tk.StringVar(value="netstat -an")
        tk.Entry(side_in, textvariable=self.custom_var, bg=C["panel2"], fg=C["fg"],
                 insertbackground=C["fg"], relief="flat", font=MONO).pack(fill="x", padx=8)
        port_row = tk.Frame(side_in, bg=C["panel"])
        port_row.pack(fill="x", padx=8, pady=(4, 0))
        tk.Label(port_row, text="port (for Ctrl+O):", bg=C["panel"], fg=C["dim"],
                 font=UI_FONT).pack(side="left")
        self.port_var = tk.StringVar(value="443")
        tk.Entry(port_row, textvariable=self.port_var, width=7, bg=C["panel2"], fg=C["fg"],
                 insertbackground=C["fg"], relief="flat", font=MONO).pack(side="left", padx=6)
        self._btn(side_in, "Run Custom", self.run_custom, C["panel2"]).pack(fill="x", padx=8,
                                                                             pady=4)
        self._btn(side_in, "■ Stop Everything", self.stop_command, C["err"]).pack(fill="x",
                                                                                     padx=8,
                                                                                     pady=(0, 10))

        # notebook
        self.nb = ttk.Notebook(body)
        self.nb.pack(side="left", fill="both", expand=True)

        self.terminals = TerminalsPanel(self.nb, self)
        self.nb.add(self.terminals, text="  Terminals  ")

        self.proto = ProtocolPanel(self.nb, self)
        self.nb.add(self.proto, text="  Protocol Lab  ")

        self.pinggraph = PingGraphPanel(self.nb, self)
        self.nb.add(self.pinggraph, text="  Ping Graph (compare)  ")

        self.traffic = TrafficPanel(self.nb, self)
        self.nb.add(self.traffic, text="  Traffic Monitor  ")

        self.conns = ConnPanel(self.nb, self)
        self.nb.add(self.conns, text="  Connection Analyzer  ")

        self.matrix = MatrixPanel(self.nb, self)
        self.nb.add(self.matrix, text="  Multi-Host Matrix  ")

        # status bar
        self.status_var = tk.StringVar(value="ready")
        bar = tk.Frame(self, bg=C["panel"], highlightthickness=1,
                       highlightbackground=C["border"])
        bar.pack(fill="x", padx=8, pady=(4, 8))
        tk.Label(bar, textvariable=self.status_var, bg=C["panel"], fg=C["dim"],
                 font=UI_FONT, anchor="w").pack(side="left", fill="x", expand=True, padx=10, pady=4)
        self.netstat_label = tk.Label(bar, text="", bg=C["panel"], fg=C["dim"], font=MONO)
        self.netstat_label.pack(side="right", padx=10)
        self.spin_label = tk.Label(bar, text="●", bg=C["panel"], fg=C["dim"], font=MONO)
        self.spin_label.pack(side="right", padx=(0, 2))
        self._tick_status()
        self._spin_tick()

    def _btn(self, parent, text, cmd, color):
        b = tk.Button(parent, text=text, command=cmd, bg=color,
                      fg=C["bg"] if color in (C["accent"], C["err"]) else C["fg"],
                      activebackground=C["border"], activeforeground=C["fg"],
                      relief="flat", font=UI_FONT, cursor="hand2", padx=12, pady=3)
        attach_hover(b, color, C["bg"] if color in (C["accent"], C["err"]) else C["fg"])
        return b

    def _bind_keys(self):
        b = self.bind
        b("<Control-1>", lambda e: self.run_cmd(cmd_ping(self.host(), self.count())))
        b("<Control-2>", lambda e: self.run_cmd(cmd_trace(self.host())))
        b("<Control-3>", lambda e: self.run_cmd(cmd_dns(self.host())))
        b("<Control-4>", lambda e: self.run_http_probe())
        b("<Control-5>", lambda e: self.run_speed_test())
        b("<Control-6>", lambda e: self.run_cmd(cmd_interfaces()))
        b("<Control-7>", lambda e: self.run_cmd(cmd_routes()))
        b("<Control-8>", lambda e: self.run_cmd(cmd_arp()))
        b("<Control-9>", lambda e: self.run_cmd(cmd_wifi()))
        b("<Control-a>", lambda e: self.run_netstat_stats())
        b("<Control-b>", lambda e: self.run_mdns_browse())
        b("<Control-d>", lambda e: self.run_full_diagnose())
        b("<Control-e>", lambda e: self.show_pinggraph())
        b("<Control-f>", lambda e: self.run_cmd(cmd_flush_dns()))
        b("<Control-g>", lambda e: self.run_listening_ports())
        b("<Control-h>", lambda e: self.run_mtu())
        b("<Control-i>", lambda e: self.run_ip_info())
        b("<Control-j>", lambda e: self.run_top_talkers())
        b("<Control-k>", lambda e: self.run_cmd(cmd_netstat()))
        b("<Control-l>", lambda e: self.clear_terminal())
        b("<Control-m>", lambda e: self.show_matrix())
        b("<Control-n>", lambda e: self.run_dns_compare())
        b("<Control-o>", lambda e: self.run_port_check())
        b("<Control-p>", lambda e: self.run_latency_monitor())
        b("<Control-q>", lambda e: self.run_dns_trace())
        b("<Control-r>", lambda e: self.run_arp_watch())
        b("<Control-s>", lambda e: self.save_log())
        b("<Control-t>", lambda e: self.show_traffic())
        b("<Control-u>", lambda e: self.run_mdns_monitor())
        b("<Control-v>", lambda e: self.run_reverse_dns())
        b("<Control-w>", lambda e: self.run_cmd(cmd_wifi_scan()))
        b("<Control-x>", lambda e: self.run_internet_check())
        b("<Control-y>", lambda e: self.run_gateway_check())
        b("<Control-0>", lambda e: self.run_super_diagnose())
        # Ctrl+Shift combos (uppercase keysym)
        b("<Control-P>", lambda e: self.run_icmp_monitor())
        b("<Control-H>", lambda e: self.run_http_watch())
        b("<Control-R>", lambda e: self.run_route_watch())
        b("<Control-W>", lambda e: self.run_wifi_watch())
        b("<Control-E>", lambda e: self.run_error_watch())
        b("<Control-T>", lambda e: self.nb.select(self.terminals))
        b("<Control-N>", lambda e: self.cycle_theme())   # Ctrl+Shift+N: next theme
        b("<Control-L>", lambda e: self.show_protocol())  # Ctrl+Shift+L: protocol lab
        b("<Control-K>", lambda e: self.run_all_protocols())
        b("<F5>", lambda e: self.run_selected())

    # -- helpers ------------------------------------------------------------
    @property
    def terminal(self):
        """The currently visible terminal pane."""
        return self.terminals.active()

    def host(self) -> str:
        return self.host_var.get().strip() or "8.8.8.8"

    def count(self) -> int:
        try:
            return max(1, min(50, int(self.count_var.get())))
        except Exception:
            return 4

    # -- themes -------------------------------------------------------------
    def _on_theme_pick(self, name):
        self.apply_theme(name)

    def cycle_theme(self):
        i = THEME_NAMES.index(self.theme_name) if self.theme_name in THEME_NAMES else 0
        self.apply_theme(THEME_NAMES[(i + 1) % len(THEME_NAMES)])

    def apply_theme(self, name, animate=True):
        """Switch the background/text palette; widgets morph smoothly."""
        if name not in THEMES:
            return
        old = dict(C)
        target = THEMES[name]
        self.theme_name = name
        try:
            self.theme_var.set(name)
        except Exception:
            pass
        save_theme_name(name)
        if not animate:
            C.update(target)
            self._restyle(old, target)
            return
        steps = 8

        def tick(i=0):
            t = i / steps
            t = t * t * (3 - 2 * t)                 # smoothstep easing
            step = {k: lerp_color(old[k], target[k], t) for k in target}
            self._restyle(C, step)                  # C = colours on screen now
            C.update(step)
            if i < steps:
                self.after(18, tick, i + 1)
        tick()

    def _restyle(self, old, new):
        old2new = {str(old[k]).lower(): new[k] for k in new
                   if isinstance(old.get(k), str)}
        try:
            self.configure(bg=new["bg"])
            self._build_style()
            recolor_widget_tree(self, old2new)
        except Exception:
            pass
        for panel in (getattr(self, "traffic", None), getattr(self, "pinggraph", None)):
            try:
                if panel is not None:
                    panel.canvas.configure(bg=new["bg"],
                                           highlightbackground=new["border"])
                    panel.draw()
            except Exception:
                pass
        try:
            self.theme_opt.configure(bg=new["panel2"], fg=new["fg"],
                                     activebackground=new["accent"],
                                     activeforeground=new["bg"])
            self.theme_opt["menu"].configure(bg=new["panel2"], fg=new["fg"],
                                             activebackground=new["accent"],
                                             activeforeground=new["bg"])
        except Exception:
            pass

    # -- window fade / spinner ---------------------------------------------
    def _fade(self, a: float, b: float, steps: int = 8, done=None):
        try:
            self.attributes("-alpha", a)
        except Exception:
            if done:
                done()
            return

        def tick(i=0):
            t = min(1.0, i / steps)
            t = t * t * (3 - 2 * t)
            try:
                if not self.winfo_exists():
                    return
                self.attributes("-alpha", a + (b - a) * t)
            except Exception:
                return
            if i < steps:
                self.after(18, tick, i + 1)
            elif done:
                done()
        tick()

    def _close_animated(self):
        self._fade(1.0, 0.0, steps=8, done=self.destroy)

    def _spin_tick(self, i=0):
        """Animated busy indicator in the status bar."""
        try:
            busy = (self.monitor_running or getattr(self.proto, "running", False)
                    or any(v._status_text == "running"
                           for v in self.terminals.all_views()))
            if busy:
                self.spin_label.configure(text=SPIN_FRAMES[i % len(SPIN_FRAMES)],
                                          fg=C["accent"])
            else:
                self.spin_label.configure(text="●", fg=C["dim"])
        except Exception:
            pass
        self.after(120, self._spin_tick, i + 1)

    def status(self, text: str):
        self.status_var.set(f"[{now()}] {text}")

    def _tick_status(self):
        extra = []
        if HAVE_PSUTIL:
            try:
                c = psutil.net_io_counters()
                extra.append(f"total ↓{fmt_bytes(c.bytes_recv)}  ↑{fmt_bytes(c.bytes_sent)}")
            except Exception:
                pass
        else:
            extra.append("install 'psutil' for full traffic stats")
        self.netstat_label.configure(text="   ".join(extra))
        self.after(3000, self._tick_status)

    _BANNER = [
        "  ███╗   ██╗███████╗████████╗██████╗ ██████╗  ██████╗ ██████╗ ███████╗",
        "  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝",
        "  ██╔██╗ ██║█████╗     ██║   ██████╔╝██████╔╝██║   ██║██████╔╝█████╗  ",
        "  ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  ",
        "  ██║ ╚████║███████╗   ██║   ██║     ██║  ██║╚██████╔╝██║  ██║███████╗",
        "  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝",
    ]

    def _intro(self):
        """Animated startup: banner reveal → typewriter tagline → staggered tips."""
        pane = self.terminal

        def after_typed():
            lines = [
                (f"  host: {platform.node()} | {platform.system()} {platform.release()} "
                 f"| python {platform.python_version()}", "info"),
                (f"  psutil: {'yes' if HAVE_PSUTIL else 'NO (pip install psutil)'}", "info"),
                ("  Shortcuts: Ctrl+1..9 tests · Ctrl+D full diagnose · Ctrl+M matrix · "
                 "Ctrl+T traffic · Ctrl+S save · F5 run", "info"),
                ("  Protocol Lab: Ctrl+Shift+L opens it · Ctrl+Shift+K runs all "
                 "17 protocol tests", "info"),
                ("  Themes: pick one in the top bar, or Ctrl+Shift+N to cycle", "info"),
                ("  Select a test on the left, or press a shortcut key.", "warn"),
                ("─" * 78, "info"),
            ]

            def step(i=0):
                if i < len(lines):
                    pane.write(*lines[i])
                    self.after(110, step, i + 1)
            step()

        def reveal(i=0):
            if i < len(self._BANNER):
                pane.write(self._BANNER[i], "title")
                self.after(45, reveal, i + 1)
            else:
                pane.write("", "info")
                pane.type_text(
                    f"  {APP_NAME} v{VERSION} — portable network testing suite",
                    "cmd", speed=8, done=after_typed)

        reveal()

    # -- queue / terminal ---------------------------------------------------
    def _poll(self):
        # This loop is the app's lifeline — it must survive every bad event
        # (e.g. output for a terminal the user closed), otherwise all quick
        # commands silently stop working.  Re-arm unconditionally.
        try:
            while True:
                try:
                    item = self.queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    self._dispatch(item)
                except Exception:
                    pass
        finally:
            self.after(100, self._poll)

    def _dispatch(self, item):
        kind = item[0]
        if kind == "line":
            _, tag, text = item
            self.terminal.write(text, tag)
        elif kind == "cmd":
            _, cmd = item
            self.terminal.banner(cmd)
        elif kind == "done":
            self.status(item[1])
            self.terminal.write(f"✔ {item[1]}", "ok")
        elif kind == "term":
            _, pane, tag, text = item
            pane.write(text, tag)
        elif kind == "term_cmd":
            _, pane, cmd = item
            pane.banner(cmd)
        elif kind == "term_status":
            _, pane, st = item
            pane.set_status(st)
        elif kind == "term_prog":
            _, pane, frac, label = item
            pane.set_progress(frac, label)
        elif kind == "term_done":
            _, pane, msg = item
            pane.clear_progress()
            pane.write(f"✔ {msg}", "ok")
            pane.set_status("idle")
            self.status(f"[{pane.name}] {msg}")
        elif kind == "matrix":
            self.matrix.add_row(item[1])
        elif kind == "http":
            self._print_http(item[2], item[1])
        elif kind == "speed":
            self._print_speed(item[2], item[1])
        elif kind == "traffic":
            _, name, rxb, txb, rxt, txt = item
            self.traffic.push(name, rxb, txb, rxt, txt)
        elif kind == "traffic_hint":
            self.traffic.draw()
        elif kind == "pinggraph":
            _, label, ts, ms = item
            self.pinggraph.push(label, ts, ms)
        elif kind == "pinggraph_done":
            self.status("ping graph finished")
        elif kind == "proto_line":
            _, key, tag, text = item
            self.proto.add_line(key, tag, text)
        elif kind == "proto_start":
            self.proto.set_status(item[1], "running", "")
        elif kind == "proto_done":
            _, key, st, summary = item
            self.proto.set_status(key, st, summary)
            self.status(f"[protocol] {self.proto.tree.item(f'p:{key}', 'text').strip()}: "
                        f"{st} — {summary}")
        elif kind == "proto_all_done":
            self.proto.finish()
        elif kind == "table":
            for ln in item[1]:
                self.terminal.write(ln, "head")

    def _print_http(self, r: dict, pane=None):
        t = pane or self.terminal
        t.write(f"HTTP timing → {r.get('url')}", "title")
        if r.get("error"):
            t.write(f"  ✖ {r['error']}", "err")
            return
        t.write(f"  DNS resolve   : {r.get('dns_ms', 0):8.1f} ms", "head")
        t.write(f"  TCP connect   : {r.get('tcp_ms', 0):8.1f} ms", "head")
        if r.get("tls_ms") is not None:
            t.write(f"  TLS handshake : {r.get('tls_ms'):8.1f} ms", "head")
        t.write(f"  TTFB          : {r.get('ttfb_ms', 0):8.1f} ms", "head")
        t.write(f"  Total         : {r.get('total_ms', 0):8.1f} ms", "ok")
        t.write(f"  Status        : {r.get('status', '-')}   "
                f"Server: {r.get('server', '-')}   Via: {r.get('via', '-')}", "head")

    def _print_speed(self, r: dict, pane=None):
        t = pane or self.terminal
        t.write("Speed test result", "title")
        if r.get("latency_ms") is not None:
            t.write(f"  Latency  : {r['latency_ms']:7.1f} ms  "
                    f"(min {r.get('latency_min', 0):.1f} / max {r.get('latency_max', 0):.1f} / "
                    f"jitter {r.get('jitter_ms', 0):.1f})", "head")
        if r.get("down_mbps") is not None:
            t.write(f"  Download : {r['down_mbps']:7.2f} Mbps  "
                    f"({fmt_bytes(r.get('down_bytes', 0))} in {r.get('down_sec', 0):.2f}s)", "ok")
        elif r.get("down_error"):
            t.write(f"  Download failed: {r['down_error']}", "err")
        if r.get("up_mbps") is not None:
            t.write(f"  Upload   : {r['up_mbps']:7.2f} Mbps  "
                    f"({fmt_bytes(r.get('up_bytes', 0))} in {r.get('up_sec', 0):.2f}s)", "ok")
        elif r.get("up_error"):
            t.write(f"  Upload failed: {r['up_error']}", "err")

    # -- command execution --------------------------------------------------
    def run_cmd(self, cmd: list, pane=None):
        pane = pane or self.terminal
        if pane is None or not pane._alive():
            self.status("no terminal available")
            return
        if pane.proc and pane.proc.poll() is None:
            self.status(f"[{pane.name}] busy — press ■ Stop first")
            return
        pane.stop_flag.clear()
        self.queue.put(("term_cmd", pane, cmd))
        self.queue.put(("term_status", pane, "running"))
        self.status(f"[{pane.name}] running: {' '.join(str(c) for c in cmd)}")
        threading.Thread(target=self._stream, args=(list(cmd), pane), daemon=True).start()

    def _stream(self, cmd, pane):
        try:
            pane.proc = subprocess.Popen(cmd, **popen_kwargs())
            for line in pane.proc.stdout:
                if pane.stop_flag.is_set():
                    break
                self.queue.put(("term", pane, "head", line.rstrip("\n")))
            try:
                pane.proc.wait(timeout=600)
            except Exception:
                try:
                    pane.proc.kill()
                except Exception:
                    pass
            self.queue.put(("term_done", pane,
                            f"finished (exit {pane.proc.returncode}) — "
                            f"{' '.join(str(c) for c in cmd)}"))
        except FileNotFoundError:
            self.queue.put(("term", pane, "err", f"command not found: {cmd[0]}"))
            self.queue.put(("term_done", pane, "failed"))
        except Exception as e:
            self.queue.put(("term", pane, "err", f"error: {e}"))
            self.queue.put(("term_done", pane, "failed"))
        finally:
            pane.proc = None

    def stop_command(self):
        self.stop_flag.set()
        for v in self.terminals.all_views():
            v.stop()
        if self.monitor_running:
            self.queue.put(("term", self.terminal, "warn", "■ monitor stopped by user"))
        self.pinggraph.stop()
        self.status("stopped")

    def run_selected(self):
        """F5 / Run button → run ping against the target host."""
        self.run_cmd(cmd_ping(self.host(), self.count()))

    def run_custom(self):
        raw = self.custom_var.get().strip()
        if not raw:
            return
        try:
            import shlex
            self.run_cmd(shlex.split(raw, posix=not IS_WIN))
        except ValueError:
            self.run_cmd(raw.split())

    def port_num(self) -> int:
        try:
            return max(1, min(65535, int(self.port_var.get())))
        except Exception:
            return 443

    # -- monitors / probes ---------------------------------------------------
    def _monitor_thread(self, banner_cmd, fn, done_msg, seconds=None):
        """Run a monitor/long probe in a thread; output goes to the launching pane."""
        pane = self.terminal
        if self.monitor_running:
            self.status("a monitor is already running — press ■ Stop first")
            return
        self.stop_flag.clear()
        self.monitor_running = True
        self.queue.put(("term_cmd", pane, banner_cmd))
        if seconds:
            self.queue.put(("term", pane, "info",
                            f"  (auto-stops after {seconds}s — press ■ Stop to end earlier)"))
            t0 = time.time()

            def prog_tick():
                if not self.monitor_running:
                    return
                frac = min(1.0, (time.time() - t0) / max(1.0, seconds))
                self.queue.put(("term_prog", pane, frac,
                                f"{max(0, seconds - (time.time() - t0)):.0f}s left"))
                if frac < 1.0:
                    self.after(400, prog_tick)
            self.after(400, prog_tick)

        def emit(t, tag="head"):
            self.queue.put(("term", pane, tag, t))

        def work():
            try:
                fn(pane, emit)
            except Exception as e:
                self.queue.put(("term", pane, "err", f"monitor error: {e}"))
            finally:
                self.monitor_running = False
                self.queue.put(("term_done", pane, done_msg))
        threading.Thread(target=work, daemon=True).start()

    def run_mdns_browse(self):
        self._monitor_thread(
            ["mDNS/Bonjour discovery — UDP 5353 multicast"],
            lambda pane, e: mdns_discover(e, timeout=8.0, stop=self.stop_flag),
            "mDNS discovery finished")

    def run_mdns_monitor(self):
        self._monitor_thread(
            ["mDNS traffic monitor — passive listen on UDP 5353"],
            lambda pane, e: mdns_discover(e, listen_only=True, duration=30.0,
                                          stop=self.stop_flag),
            "mDNS monitor finished (30s)", seconds=30)

    def run_arp_watch(self):
        self._monitor_thread(
            ["ARP/neighbour watch — NEW / CHANGED / REMOVED devices"],
            lambda pane, e: arp_watch(e, duration=60.0, stop=self.stop_flag),
            "ARP watch finished (60s)", seconds=60)

    def run_latency_monitor(self):
        h = self.host()
        self._monitor_thread(
            [f"latency monitor (TCP) — {h}:443, 1 probe/s"],
            lambda pane, e: latency_monitor(e, h, seconds=30.0, stop=self.stop_flag),
            f"latency monitor finished for {h}", seconds=30)

    def run_icmp_monitor(self):
        h = self.host()

        def job(pane, e):
            e(f"  ICMP ping monitor — {h} — 1 ping/s for 30 s")
            vals, fails, t_end = [], 0, time.time() + 30
            while time.time() < t_end:
                if self.stop_flag.is_set():
                    break
                ms = icmp_ping_once(h)
                vals.append(ms)
                if ms is None:
                    fails += 1
                ok = [v for v in vals if v is not None]
                e(f"  [{now()}] {'timeout ' if ms is None else f'{ms:6.1f} ms'} | "
                  f"sent {len(vals)} | loss {100.0 * fails / max(1, len(vals)):3.0f}% | "
                  f"avg {sum(ok) / len(ok) if ok else 0:5.1f} ms")
                time.sleep(1.0)
            ok = [v for v in vals if v is not None]
            e(f"  summary: sent {len(vals)}, received {len(ok)}, "
              f"loss {100.0 * fails / max(1, len(vals)):.0f}%, "
              f"avg {sum(ok) / len(ok) if ok else 0:.1f} ms")
        self._monitor_thread([f"ICMP ping monitor — {h}"], job,
                             f"ICMP monitor finished for {h}", seconds=30)

    def run_dns_compare(self):
        h = self.host()
        self._monitor_thread(
            [f"DNS resolver comparison — {h}"],
            lambda pane, e: dns_compare(e, h),
            f"DNS comparison finished for {h}")

    def run_dns_trace(self):
        h = self.host()
        self._monitor_thread(
            [f"DNS delegation trace — {h}"],
            lambda pane, e: dns_trace(h, e),
            f"DNS trace finished for {h}")

    def run_reverse_dns(self):
        h = self.host()

        def job(pane, e):
            try:
                name, ms = reverse_dns(h)
                e(f"  {h}  ->  {name}   ({ms:.1f} ms)")
            except Exception as ex:
                e(f"  PTR lookup failed: {ex}")
        self._monitor_thread([f"reverse DNS (PTR) — {h}"], job, "PTR lookup finished")

    def run_ip_info(self):
        h = self.host()

        def job(pane, e):
            e(f"  public IP (this network): {public_ip()}")
            r = ip_info(h)
            if r.get("error"):
                e(f"  lookup failed: {r['error']}")
                return
            e(f"  target {r['target']}  ->  {r.get('ip')}")
            for key, lbl in (("country", "country"), ("regionName", "region"),
                             ("city", "city"), ("isp", "ISP"), ("org", "org"),
                             ("as", "ASN"), ("timezone", "timezone")):
                e(f"  {lbl:9s}: {r.get(key) or '-'}")
        self._monitor_thread([f"IP / geo / ASN info — {h}"], job, "IP info finished")

    def run_port_check(self):
        h = self.host()
        p = self.port_num()

        def job(pane, e):
            e(f"  single-port TCP connectivity test: {h}:{p}")
            r = port_check(h, p)
            if r.get("error"):
                e(f"  ✖ {r['error']}")
                return
            e(f"  DNS : {', '.join(r.get('addrs', []))}  ({r.get('dns_ms', 0):.1f} ms)")
            e(f"  ✔ {r['status']} in {r['ms']:.1f} ms")
            e(f"  local {r['local']}   ->   peer {r['peer']}")
        self._monitor_thread([f"TCP port check — {h}:{p}"], job, "port check finished")

    def run_mtu(self):
        h = self.host()

        def job(pane, e):
            e("  binary search over payload sizes with the DF bit set…")
            r = mtu_probe(h)
            if r.get("mtu"):
                e(f"  max ICMP payload : {r['max_payload']} bytes")
                e(f"  estimated path MTU: {r['mtu']} bytes  (payload + 28 B IP/ICMP header)")
            else:
                e("  no DF ping succeeded — ICMP may be blocked; try another target")
            e(f"  probes used: {r['probes']}")
        self._monitor_thread([f"path MTU discovery — {h}"], job, "MTU probe finished")

    def run_gateway_check(self):
        def job(pane, e):
            gw, iface = default_gateway()
            if not gw:
                e("  could not detect the default gateway from the routing table")
                return
            e(f"  default gateway: {gw}   (interface {iface or '?'})")
            for _ in range(4):
                if self.stop_flag.is_set():
                    break
                ms = icmp_ping_once(gw) or probe_latency(gw)
                e(f"  [{now()}] gateway {'timeout' if ms is None else f'{ms:7.2f} ms'}")
                time.sleep(0.5)
            try:
                e(f"  system DNS resolve google.com: {dns_resolve('google.com')[1]:.1f} ms")
            except Exception as ex:
                e(f"  system DNS failed: {ex}")
        self._monitor_thread(["gateway / first-hop check"], job, "gateway check finished")

    def run_internet_check(self):
        self._monitor_thread(
            ["internet reachability / captive-portal check"],
            lambda pane, e: internet_check(e),
            "internet check finished")

    def run_netstat_stats(self):
        self.run_cmd(["netstat", "-s"])

    def run_http_watch(self):
        url = self.host()
        self._monitor_thread(
            [f"HTTP endpoint watch — {url}"],
            lambda pane, e: http_watch(e, url, seconds=60.0, stop=self.stop_flag),
            f"HTTP watch finished for {url}", seconds=60)

    def run_wifi_watch(self):
        self._monitor_thread(
            ["Wi-Fi signal watch"],
            lambda pane, e: wifi_signal_watch(e, seconds=30.0, stop=self.stop_flag),
            "Wi-Fi watch finished (30s)", seconds=30)

    def run_error_watch(self):
        self._monitor_thread(
            ["interface error / drop watch"],
            lambda pane, e: interface_error_watch(e, seconds=60.0, stop=self.stop_flag),
            "error watch finished (60s)", seconds=60)

    def run_route_watch(self):
        h = self.host()
        self._monitor_thread(
            [f"path / route change watch — {h} (4 traceroutes)"],
            lambda pane, e: route_watch(e, h, rounds=4, interval=25.0, stop=self.stop_flag),
            f"route watch finished for {h}", seconds=120)

    def run_super_diagnose(self):
        h = self.host()

        def job(pane, e):
            e(f"  public IP : {public_ip()}")
            try:
                addrs, ms = dns_resolve(h)
                e(f"  DNS {h} -> {', '.join(addrs)}  ({ms:.1f} ms)")
            except Exception as ex:
                e(f"  DNS failed: {ex}")
            gw, iface = default_gateway()
            e(f"  gateway   : {gw or '?'} ({iface or '?'})")
            gms = probe_latency(gw) if gw else None
            e(f"  gateway RTT: {'timeout' if gms is None else f'{gms:.2f} ms'}")
            for port in (443, 80):
                try:
                    lat = [tcp_latency(h, port, 3.0) for _ in range(3)]
                    e(f"  TCP {port:<5} : avg {sum(lat) / len(lat):6.1f} ms  "
                      f"min {min(lat):.1f}  max {max(lat):.1f}  jitter {max(lat) - min(lat):.1f}")
                except Exception:
                    e(f"  TCP {port:<5} : unreachable")
            r = http_probe(h if re.match(r"^https?://", h, re.I) else f"https://{h}")
            if r.get("error"):
                e(f"  HTTP      : {r['error']}")
            else:
                e(f"  HTTP      : status {r.get('status')}  dns {r.get('dns_ms', 0):.1f}  "
                  f"tcp {r.get('tcp_ms', 0):.1f}  tls {r.get('tls_ms', 0) or 0:.1f}  "
                  f"ttfb {r.get('ttfb_ms', 0):.1f}  total {r.get('total_ms', 0):.1f} ms")
            mtu = mtu_probe(h)
            e(f"  path MTU  : {mtu.get('mtu') or 'unknown'}")
            errs = iface_errors()
            dirty = [f"{n}: err {v[0]}/{v[1]} drop {v[2]}/{v[3]}"
                     for n, v in errs.items() if any(v)]
            e(f"  iface errors: {', '.join(dirty) if dirty else 'clean'}")
        self._monitor_thread([f"SUPER DIAGNOSTIC — {h}"], job, "super diagnostic finished")

    def run_listening_ports(self):
        pane = self.terminal
        self.queue.put(("term_cmd", pane, ["listening ports (local machine)"]))
        self.status("listing listening sockets…")

        def job():
            rows = listening_ports()
            lines = [f"  {'PID':<8}{'PROCESS':<20}{'PROTO':<8}{'LOCAL':<24}STATE"]
            for pid, name, proto, local, state in rows[:200]:
                lines.append(f"  {str(pid):<8}{str(name)[:18]:<20}{str(proto):<8}"
                             f"{str(local):<24}{state}")
            if not rows:
                lines.append("  (no data — install psutil for process names: pip install psutil)")
            for ln in lines:
                self.queue.put(("term", pane, "head", ln))
            self.queue.put(("term_done", pane, f"{len(rows)} listening sockets"))
        threading.Thread(target=job, daemon=True).start()

    def run_top_talkers(self):
        pane = self.terminal
        self.queue.put(("term_cmd", pane, ["top talkers — processes ranked by open sockets"]))
        self.status("analysing per-process connections…")

        def job():
            rows = top_talkers()
            lines = [f"  {'PID':<8}{'PROCESS':<22}{'SOCKETS':<9}{'ESTAB':<8}{'PEERS':<7}REMOTE IPS"]
            for pid, name, n, est, peers, remotes in rows:
                lines.append(f"  {str(pid):<8}{str(name)[:20]:<22}{n:<9}{est:<8}{peers:<7}{remotes}")
            if not rows:
                lines.append("  (requires psutil — pip install psutil)")
            for ln in lines:
                self.queue.put(("term", pane, "head", ln))
            self.queue.put(("term_done", pane, f"{len(rows)} processes with sockets"))
        threading.Thread(target=job, daemon=True).start()

    def run_http_probe(self):
        pane = self.terminal
        target = self.host()
        url = target if re.match(r"^https?://", target, re.I) else f"https://{target}"
        self.queue.put(("term_cmd", pane, ["http-timing", url]))
        self.status(f"probing {url}")

        def work():
            r = http_probe(url)
            self.queue.put(("http", pane, r))
        threading.Thread(target=work, daemon=True).start()

    def run_speed_test(self):
        pane = self.terminal
        self.queue.put(("term_cmd", pane, ["speed-test"]))
        self.queue.put(("term_status", pane, "running"))
        self.status("running speed test (~20–40 s)")

        def work():
            last_ui = [0.0]

            def prog(frac, label):
                ts = time.time()
                if frac < 1.0 and ts - last_ui[0] < 0.15:
                    return
                last_ui[0] = ts
                self.queue.put(("term_prog", pane, frac, label))

            r = speed_test(emit=lambda t: self.queue.put(("term", pane, "info", t)),
                           progress=prog)
            self.queue.put(("speed", pane, r))
            self.queue.put(("term_done", pane, "speed test complete"))
        threading.Thread(target=work, daemon=True).start()

    def run_full_diagnose(self):
        pane = self.terminal
        h = self.host()
        self.queue.put(("term", pane, "title", "=" * 78))
        self.queue.put(("term", pane, "title",
                        f"FULL DIAGNOSTIC — {h} — {datetime.datetime.now()}"))
        self.queue.put(("term", pane, "title", "=" * 78))

        def work():
            try:
                addrs, ms = dns_resolve(h)
                self.queue.put(("term", pane, "ok",
                                f"DNS {h} → {', '.join(addrs)}  ({ms:.1f} ms)"))
            except Exception as e:
                self.queue.put(("term", pane, "err", f"DNS failed: {e}"))
            try:
                lat = [tcp_latency(h, 443, 3.0) for _ in range(5)]
                self.queue.put(("term", pane, "ok",
                                f"TCP 443 latency: avg {sum(lat)/len(lat):.1f} ms "
                                f"min {min(lat):.1f} max {max(lat):.1f} "
                                f"jitter {max(lat)-min(lat):.1f} ms"))
            except Exception as e:
                self.queue.put(("term", pane, "warn", f"TCP 443 unavailable: {e}"))
            r = http_probe(h if re.match(r"^https?://", h, re.I) else f"https://{h}")
            self.queue.put(("http", pane, r))
            for cmd in (cmd_interfaces(), cmd_routes(), cmd_arp()):
                self.queue.put(("term_cmd", pane, cmd))
                try:
                    out = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                                         **{k: v for k, v in popen_kwargs().items() if k == "creationflags"})
                    for ln in (out.stdout or "").splitlines():
                        self.queue.put(("term", pane, "head", ln))
                except Exception as e:
                    self.queue.put(("term", pane, "err", str(e)))
            self.queue.put(("term_done", pane, f"full diagnostic complete for {h}"))
        threading.Thread(target=work, daemon=True).start()

    # -- tabs ---------------------------------------------------------------
    def show_protocol(self):
        self.nb.select(self.proto)

    def run_all_protocols(self):
        self.show_protocol()
        self.proto.run_all()

    def run_protocol_layer(self, idx):
        self.show_protocol()
        self.proto.run_layer_index(idx)

    def show_matrix(self):
        self.nb.select(self.matrix)

    def show_pinggraph(self):
        self.nb.select(self.pinggraph)

    def show_traffic(self):
        self.nb.select(self.traffic)

    def clear_terminal(self):
        self.terminal.clear()
        self.status("terminal cleared")

    def copy_terminal(self):
        self.terminal._copy()

    def save_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log", "*.log"), ("Text", "*.txt"), ("All", "*.*")],
            initialfile=f"netprobe-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.log")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.terminal.dump())
        self.status(f"saved {path}")
        messagebox.showinfo(APP_NAME, f"Log saved to:\n{path}")


def cli_mode(argv):
    """Text-only mode for SSH / headless use:  python netprobe.py --cli [host]"""
    flags = {"--speed", "--matrix"}
    args = [a for a in argv if a not in flags]
    host = args[0] if args else "8.8.8.8"
    print(f"{APP_NAME} v{VERSION} CLI — {platform.system()} {platform.release()} "
          f"| python {platform.python_version()} | psutil: {'yes' if HAVE_PSUTIL else 'no'}")
    print(f"target: {host}\n")

    print("[DNS]")
    try:
        addrs, ms = dns_resolve(host)
        print(f"  {host} -> {', '.join(addrs)}  ({ms:.1f} ms)")
    except Exception as e:
        print(f"  failed: {e}")

    print("[TCP latency :443 x5]")
    try:
        lat = [tcp_latency(host, 443, 3.0) for _ in range(5)]
        print(f"  avg {sum(lat)/len(lat):.1f} ms  min {min(lat):.1f}  max {max(lat):.1f}  "
              f"jitter {max(lat)-min(lat):.1f}")
    except Exception as e:
        print(f"  failed: {e}")

    print("[HTTP timing]")
    r = http_probe(host if re.match(r"^https?://", host, re.I) else f"https://{host}")
    if r.get("error"):
        print(f"  {r['error']}")
    else:
        print(f"  dns {r.get('dns_ms', 0):.1f} ms | tcp {r.get('tcp_ms', 0):.1f} ms | "
              f"tls {r.get('tls_ms', 0) or 0:.1f} ms | ttfb {r.get('ttfb_ms', 0):.1f} ms | "
              f"total {r.get('total_ms', 0):.1f} ms | status {r.get('status', '-')}")

    print("[System commands]")
    for cmd in (cmd_interfaces(), cmd_routes(), cmd_arp()):
        print(f"  $ {' '.join(cmd)}")
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                                 **{k: v for k, v in popen_kwargs().items() if k == "creationflags"})
            for ln in (out.stdout or "").splitlines()[:40]:
                print("    " + ln)
        except Exception as e:
            print(f"    error: {e}")

    if "--speed" in argv:
        print("[Speed test]")
        res = speed_test(emit=lambda t: print(t))
        print(f"  latency {res.get('latency_ms', 0):.1f} ms | "
              f"down {res.get('down_mbps', 0):.2f} Mbps | up {res.get('up_mbps', 0):.2f} Mbps")

    if "--matrix" in argv:
        print("[Host matrix]")
        for h in (args or ["1.1.1.1", "8.8.8.8", "google.com"]):
            rr = probe_host(h)
            print(f"  {h:20s} dns={rr.get('dns_ms', -1):7.1f} ms  "
                  f"tcp_avg={rr.get('tcp_avg', -1) or -1:7.1f} ms  loss={rr.get('loss', 0):.0f}%  "
                  f"{rr.get('error', '')}")


def main():
    if not hasattr(sys, "argv"):
        sys.argv = []
    if "--cli" in sys.argv:
        cli_mode([a for a in sys.argv[1:] if a != "--cli"])
        return
    if not HAVE_TK:
        print("[NetProbe] Tkinter is not available in this Python build.")
        print("  macOS : brew install python-tk   (or install Python from python.org)")
        print("  Linux : sudo apt install python3-tk")
        print("Running in terminal-only mode instead. Use --cli for diagnostics.\n")
        cli_mode([])
        return
    try:
        app = App()
    except tk.TclError as e:
        print("Cannot start GUI:", e)
        print("This tool needs a graphical desktop session (Windows / macOS / Linux with a display).")
        sys.exit(1)
    app.mainloop()


if __name__ == "__main__":
    main()

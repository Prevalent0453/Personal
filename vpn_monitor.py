"""
VPN Monitor with cause identification.

Every tick runs FOUR parallel sensors and cross-references them to
classify each disruption by root cause instead of just logging "down":

  1. Route table    - which interface carries the default IPv4 route.
                      utunN = VPN active, en0 = Wi-Fi direct,
                      pdp_ipN = cellular direct.
  2. TCP probe      - can we open a TCP connection to 1.1.1.1:443 at all?
                      Answers "is there any internet".
  3. DNS probe      - resolve a hostname; distinguishes DNS failure
                      from tunnel failure.
  4. HTTPS probe    - GET a public-IP endpoint; the returned IP is
                      compared against a baseline captured at start,
                      so drops and IP leaks are both detected.

Plus a fifth signal:

  5. Clock skew     - monotonic-time gap between ticks vs configured
                      interval. A gap much larger than the interval
                      means iOS suspended a-Shell in the background,
                      which is an artefact of monitoring, not a real VPN
                      drop, and is marked accordingly.

Verdict is emitted per disruption AND aggregated at the end:

  TUNNEL_KILLED_BY_OS       Route changed from utun* to en0/pdp during
                            the drop - iOS killed the NetworkExtension.
                            Fix: Background App Refresh, disable Low
                            Power Mode, Happ Auto-reconnect.
  SERVER_KILLED_CONNECTION  Route still utun, but HTTPS reset.
                            The remote server (or CDN) actively dropped
                            the connection.
  IDLE_TIMEOUT_SERVER       Same as above but preceded by >=60s silence
                            in traffic - the server rolls idle sessions.
  IDLE_TIMEOUT              Long silence + drop without route change.
                            Carrier NAT or an upstream timeout.
  NETWORK_LOSS              TCP to 1.1.1.1 also failed - the whole
                            connection is gone, not just the tunnel.
  DNS_ISSUE                 TCP works, DNS fails, HTTPS fails.
                            Fix: change DNS in Happ to 1.1.1.1/8.8.8.8.
  IOS_SUSPENSION            monotonic_dt >> configured interval.
                            a-Shell was frozen; ignore for VPN diagnosis.

Usage:
    python3 ~/Documents/vpn_monitor.py
    python3 ~/Documents/vpn_monitor.py --interval 5
    python3 ~/Documents/vpn_monitor.py --log ~/Documents/vpn.csv

Ctrl+C to stop and get the report.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import os
import re
import signal
import socket
import statistics
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

DEFAULT_LOG = os.path.expanduser("~/Documents/vpn_monitor.csv")

HTTPS_ENDPOINT = "https://api.ipify.org?format=json"
TCP_TARGET = ("1.1.1.1", 443)
DNS_HOST = "cloudflare.com"


# ---------- helpers ---------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def fmt_duration(s: float) -> str:
    if s < 60:
        return f"{s:.1f}s"
    total = int(round(s))
    m, sec = divmod(total, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h{m:02d}m{sec:02d}s"
    return f"{m}m{sec:02d}s"


# ---------- sensors ---------------------------------------------------------

_IFACE_RE = re.compile(r"^[a-z][a-z0-9_]{1,15}$")


def get_default_route_iface() -> str | None:
    """Interface carrying the current default IPv4 route, or None."""
    try:
        out = subprocess.run(
            ["netstat", "-rn", "-f", "inet"],
            capture_output=True, text=True, timeout=2.0,
        ).stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return None
    for line in out.splitlines():
        parts = line.split()
        if not parts or parts[0] != "default":
            continue
        # BSD netstat: default <gateway> <flags> [refs] [use] <iface> [...]
        # Take the rightmost column that looks like an iface name.
        for tok in reversed(parts):
            if _IFACE_RE.match(tok):
                return tok
    return None


def tcp_probe(host: str, port: int, timeout: float = 3.0) -> tuple[bool, float]:
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return True, time.monotonic() - t0
    except (OSError, TimeoutError):
        return False, time.monotonic() - t0


def dns_probe(host: str, timeout: float = 3.0) -> tuple[bool, float, str | None]:
    t0 = time.monotonic()
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        ip = socket.gethostbyname(host)
        return True, time.monotonic() - t0, ip
    except OSError:
        return False, time.monotonic() - t0, None
    finally:
        socket.setdefaulttimeout(old)


def https_probe(url: str, timeout: float = 5.0) -> tuple[bool, float, str | None, str | None]:
    t0 = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vpn-monitor/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace").strip()
    except Exception as e:
        return False, time.monotonic() - t0, None, f"{type(e).__name__}: {e}"
    ip = ""
    if body.startswith("{"):
        try:
            ip = json.loads(body).get("ip", "")
        except (ValueError, TypeError):
            ip = body[:64]
    else:
        ip = body.split()[0] if body else ""
    return True, time.monotonic() - t0, ip, None


# ---------- data model ------------------------------------------------------

@dataclass
class Tick:
    wall_ts: str
    mono: float
    mono_dt: float
    frozen: bool
    route: str | None
    tcp_ok: bool
    tcp_ms: float
    dns_ok: bool
    dns_ms: float
    dns_ip: str | None
    https_ok: bool
    https_ms: float
    https_ip: str | None
    https_err: str | None

    def csv_row(self) -> list:
        return [
            self.wall_ts,
            f"{self.mono_dt:.1f}",
            "y" if self.frozen else "",
            self.route or "",
            "ok" if self.tcp_ok else "fail", f"{self.tcp_ms:.0f}",
            "ok" if self.dns_ok else "fail", f"{self.dns_ms:.0f}", self.dns_ip or "",
            "ok" if self.https_ok else "fail", f"{self.https_ms:.0f}",
            self.https_ip or "", self.https_err or "",
        ]


@dataclass
class Disruption:
    kind: str            # tunnel state at drop: DOWN_TUNNEL / DOWN_NETWORK / DNS_ISSUE / LEAK / FROZEN
    cause: str           # root-cause verdict for this specific drop
    start_ts: str
    start_mono: float
    pre_route: str | None
    post_route: str | None
    tcp_ok: bool
    dns_ok: bool
    https_err: str | None
    silence_s: float
    frozen_gap_s: float
    end_mono: float | None = None

    @property
    def duration(self) -> float | None:
        return None if self.end_mono is None else self.end_mono - self.start_mono


# ---------- tick -> state ---------------------------------------------------

def tick_state(t: Tick, baseline_ip: str | None) -> str:
    if t.frozen:
        return "FROZEN"
    if not t.https_ok:
        if not t.tcp_ok and not t.dns_ok:
            return "DOWN_NETWORK"
        if t.tcp_ok and not t.dns_ok:
            return "DNS_ISSUE"
        return "DOWN_TUNNEL"
    if baseline_ip and t.https_ip and t.https_ip != baseline_ip:
        return "LEAK"
    return "UP"


# ---------- monitor ---------------------------------------------------------

class Monitor:
    def __init__(self, log_path: str, interval: float, timeout: float,
                 vpn_prefix: str = "utun") -> None:
        self.log_path = log_path
        self.interval = interval
        self.timeout = timeout
        self.vpn_prefix = vpn_prefix

        self.state = "UNKNOWN"
        self.baseline_ip: str | None = None
        self.state_since = time.monotonic()
        self.started_at = time.monotonic()

        self.last_mono: float | None = None
        self.last_route: str | None = None
        self.last_tick: Tick | None = None
        self.last_good_mono: float | None = None  # last successful probe

        self.disruptions: list[Disruption] = []
        self.rtts_ms: list[float] = []
        self.iface_flaps: list[tuple[str, str | None, str | None]] = []

        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
        if not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0:
            with open(self.log_path, "w", newline="") as f:
                csv.writer(f).writerow([
                    "timestamp", "mono_dt", "frozen", "route",
                    "tcp", "tcp_ms",
                    "dns", "dns_ms", "dns_ip",
                    "https", "https_ms", "https_ip", "https_err",
                ])

    # ---- one probe cycle ----

    def gather(self) -> Tick:
        mono = time.monotonic()
        mono_dt = 0.0 if self.last_mono is None else mono - self.last_mono
        frozen = self.last_mono is not None and mono_dt > (self.interval * 3 + 10)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            f_r = ex.submit(get_default_route_iface)
            f_t = ex.submit(tcp_probe, TCP_TARGET[0], TCP_TARGET[1], 3.0)
            f_d = ex.submit(dns_probe, DNS_HOST, 3.0)
            f_h = ex.submit(https_probe, HTTPS_ENDPOINT, self.timeout)
            route = f_r.result()
            tcp_ok, tcp_s = f_t.result()
            dns_ok, dns_s, dns_ip = f_d.result()
            https_ok, https_s, https_ip, https_err = f_h.result()

        self.last_mono = mono
        return Tick(
            wall_ts=now_iso(), mono=mono, mono_dt=mono_dt, frozen=frozen,
            route=route,
            tcp_ok=tcp_ok, tcp_ms=tcp_s * 1000,
            dns_ok=dns_ok, dns_ms=dns_s * 1000, dns_ip=dns_ip,
            https_ok=https_ok, https_ms=https_s * 1000,
            https_ip=https_ip, https_err=https_err,
        )

    # ---- cause classifier ----

    def classify_cause(self, drop: Tick, prev_route: str | None,
                       silence: float) -> str:
        if drop.frozen:
            return "IOS_SUSPENSION"
        # Route left VPN: iOS or Happ killed the tunnel.
        if (prev_route and prev_route.startswith(self.vpn_prefix)
                and drop.route and not drop.route.startswith(self.vpn_prefix)):
            return "TUNNEL_KILLED_BY_OS"
        # Absolutely no network at all.
        if not drop.tcp_ok and not drop.dns_ok and not drop.https_ok:
            return "NETWORK_LOSS"
        # TCP OK but DNS + HTTPS fail: DNS resolver is broken.
        if drop.tcp_ok and not drop.dns_ok and not drop.https_ok:
            return "DNS_ISSUE"
        # Route still on VPN, HTTPS specifically failed → server side.
        if drop.route and drop.route.startswith(self.vpn_prefix) and not drop.https_ok:
            if silence >= 60:
                return "IDLE_TIMEOUT_SERVER"
            # inspect error text for reset / EOF hints
            err = (drop.https_err or "").lower()
            if any(w in err for w in ("reset", "eof", "closed", "aborted")):
                return "SERVER_KILLED_CONNECTION"
            if "timed out" in err or "timeout" in err:
                return "SERVER_STALLED"
            return "SERVER_KILLED_CONNECTION"
        # Long silence + drop without route change: NAT/upstream timeout.
        if silence >= 60:
            return "IDLE_TIMEOUT"
        return "UNKNOWN"

    # ---- per-tick processing ----

    def process(self, t: Tick) -> None:
        with open(self.log_path, "a", newline="") as f:
            csv.writer(f).writerow(t.csv_row())

        new = tick_state(t, self.baseline_ip)

        # First UP tick → capture baseline.
        if self.baseline_ip is None and new == "UP":
            self.baseline_ip = t.https_ip
            print(f"[{t.wall_ts}] START     iface={t.route}  "
                  f"baseline_ip={t.https_ip}  rtt={t.https_ms:.0f}ms")
            self.state = "UP"
            self.state_since = t.mono
            self.last_route = t.route
            self.last_good_mono = t.mono
            self.rtts_ms.append(t.https_ms)
            self.last_tick = t
            return

        # Route change is always worth noting, even inside UP.
        if t.route != self.last_route:
            print(f"[{t.wall_ts}] ROUTE     {self.last_route} -> {t.route}")
            self.iface_flaps.append((t.wall_ts, self.last_route, t.route))

        # State transitions.
        if new != self.state:
            self._transition(new, t)

        if t.https_ok:
            self.rtts_ms.append(t.https_ms)
            self.last_good_mono = t.mono

        self.last_route = t.route
        self.last_tick = t

    def _transition(self, new: str, t: Tick) -> None:
        prev = self.state
        dur = t.mono - self.state_since
        if prev == "UP" and new != "UP":
            silence = 0.0 if self.last_good_mono is None else t.mono - self.last_good_mono
            cause = self.classify_cause(t, self.last_route, silence)
            frozen_gap = t.mono_dt - self.interval if t.frozen else 0.0
            d = Disruption(
                kind=new, cause=cause,
                start_ts=t.wall_ts, start_mono=t.mono,
                pre_route=self.last_route, post_route=t.route,
                tcp_ok=t.tcp_ok, dns_ok=t.dns_ok,
                https_err=t.https_err,
                silence_s=silence, frozen_gap_s=frozen_gap,
            )
            self.disruptions.append(d)
            print(f"[{t.wall_ts}] DROP      {new:<12} cause={cause}  "
                  f"iface={self.last_route}->{t.route}  "
                  f"tcp={'ok' if t.tcp_ok else 'fail'} "
                  f"dns={'ok' if t.dns_ok else 'fail'} "
                  f"https={'ok' if t.https_ok else 'fail'}  "
                  f"silence={fmt_duration(silence)}")
        elif prev != "UP" and new == "UP":
            if self.disruptions and self.disruptions[-1].end_mono is None:
                self.disruptions[-1].end_mono = t.mono
            print(f"[{t.wall_ts}] RESTORE   iface={t.route}  "
                  f"ip={t.https_ip}  rtt={t.https_ms:.0f}ms  "
                  f"downtime={fmt_duration(dur)}")
        elif prev != new:
            print(f"[{t.wall_ts}] SHIFT     {prev} -> {new}")

        self.state = new
        self.state_since = t.mono

    # ---- main loop ----

    def run(self, should_stop) -> None:
        print(f"# VPN Monitor")
        print(f"# sensors : route + TCP({TCP_TARGET[0]}:{TCP_TARGET[1]}) + "
              f"DNS({DNS_HOST}) + HTTPS(ipify)")
        print(f"# interval: {self.interval}s   timeout: {self.timeout}s")
        print(f"# log     : {self.log_path}")
        print(f"# Ctrl+C to stop and get the report.")
        print()

        while not should_stop():
            try:
                t = self.gather()
                self.process(t)
            except Exception as e:
                print(f"[{now_iso()}] TICK_ERR  {type(e).__name__}: {e}")

            deadline = time.monotonic() + self.interval
            while not should_stop():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.5, remaining))

        # Close open disruption at end of test.
        if self.disruptions and self.disruptions[-1].end_mono is None:
            self.disruptions[-1].end_mono = time.monotonic()

    # ---- report ----

    _EXPLAIN = {
        "TUNNEL_KILLED_BY_OS": (
            "iOS убил NetworkExtension Happ (нехватка памяти / sleep-mode).\n"
            "    Меры: включить Background App Refresh для Happ, выключить Low\n"
            "    Power Mode, включить в Happ Auto-reconnect."
        ),
        "SERVER_KILLED_CONNECTION": (
            "Сервер активно оборвал соединение (RST/EOF).\n"
            "    Меры: сменить exit-ноду или связаться с админом сервера."
        ),
        "SERVER_STALLED": (
            "Сервер не ответил в отведённый таймаут.\n"
            "    Меры: попробовать другую ноду, проверить нагрузку сервера."
        ),
        "IDLE_TIMEOUT_SERVER": (
            "Сессия рвётся после длительного бездействия.\n"
            "    Меры: увеличить connIdle в конфиге Xray, включить keepalive\n"
            "    в транспорте (WS/gRPC pingInterval)."
        ),
        "IDLE_TIMEOUT": (
            "Разрывы совпадают с idle-периодами (carrier NAT или upstream).\n"
            "    Меры: включить keepalive транспорта, использовать TCP-based\n"
            "    транспорт (Reality) вместо mKCP/QUIC."
        ),
        "NETWORK_LOSS": (
            "Пропадала вся сеть, не только VPN.\n"
            "    Меры: диагностика Wi-Fi/LTE, а не туннеля."
        ),
        "DNS_ISSUE": (
            "DNS-резолвер отваливается, TCP работает.\n"
            "    Меры: сменить DNS в Happ на 1.1.1.1 или 8.8.8.8."
        ),
        "IOS_SUSPENSION": (
            "a-Shell замораживался iOS в фоне - это артефакт мониторинга,\n"
            "    не разрыв VPN. Держи a-Shell на переднем плане."
        ),
        "UNKNOWN": (
            "Причина не определена однозначно, см. детали в CSV-логе."
        ),
    }

    def report(self) -> None:
        total = time.monotonic() - self.started_at
        print()
        print("=" * 70)
        print(" VPN Monitor Report")
        print("=" * 70)
        print(f"  Total observed  : {fmt_duration(total)}")
        print(f"  Baseline VPN IP : {self.baseline_ip or '(never captured)'}")
        if self.rtts_ms:
            rtts = sorted(self.rtts_ms)
            median = statistics.median(rtts)
            p95 = rtts[min(len(rtts) - 1, int(len(rtts) * 0.95))]
            jitter = statistics.stdev(rtts) if len(rtts) > 1 else 0
            print(f"  RTT median/p95  : {median:.0f} / {p95:.0f} ms  "
                  f"(jitter stdev {jitter:.0f} ms, n={len(rtts)})")
        print(f"  Interface flaps : {len(self.iface_flaps)}")
        print(f"  Disruptions     : {len(self.disruptions)}")

        if not self.disruptions:
            print()
            print("  Ничего не сломалось за этот прогон.")
            print("=" * 70)
            return

        # Cause breakdown, excluding IOS_SUSPENSION for the main verdict.
        causes: dict[str, int] = {}
        for d in self.disruptions:
            causes[d.cause] = causes.get(d.cause, 0) + 1

        print()
        print("  Причины (все, включая артефакты):")
        for cause, count in sorted(causes.items(), key=lambda x: -x[1]):
            marker = "  (артефакт)" if cause == "IOS_SUSPENSION" else ""
            print(f"    {cause:<28} {count}{marker}")

        # Timeline.
        print()
        print("  Timeline:")
        print(f"    {'time':<27} {'kind':<13} {'dur':<9} {'cause':<26} route")
        for d in self.disruptions:
            dur = fmt_duration(d.duration) if d.duration is not None else "open"
            route = f"{d.pre_route}->{d.post_route}"
            print(f"    {d.start_ts:<27} {d.kind:<13} {dur:<9} {d.cause:<26} {route}")

        # Main verdict: most-common non-artefact cause.
        real = {c: n for c, n in causes.items() if c != "IOS_SUSPENSION"}
        if real:
            top = max(real.items(), key=lambda x: x[1])[0]
            print()
            print(f"  Основной вердикт: {top}")
            print(f"    {self._EXPLAIN.get(top, 'см. лог')}")
        else:
            print()
            print("  Основной вердикт: IOS_SUSPENSION")
            print(f"    {self._EXPLAIN['IOS_SUSPENSION']}")
            print(f"    Реальных обрывов VPN в этом прогоне не зафиксировано.")

        print()
        print(f"  Log: {self.log_path}")
        print("=" * 70)


# ---------- main ------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="VPN monitor with cause identification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--log", default=DEFAULT_LOG, help="CSV log path")
    ap.add_argument("--interval", type=float, default=10.0,
                    help="seconds between ticks (default 10)")
    ap.add_argument("--timeout", type=float, default=5.0,
                    help="HTTPS probe timeout (default 5)")
    ap.add_argument("--vpn-prefix", default="utun",
                    help="expected VPN interface prefix (default 'utun')")
    args = ap.parse_args()

    mon = Monitor(
        log_path=args.log,
        interval=args.interval,
        timeout=args.timeout,
        vpn_prefix=args.vpn_prefix,
    )

    stop = False

    def on_sig(_s, _f):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, on_sig)
    signal.signal(signal.SIGTERM, on_sig)

    try:
        mon.run(lambda: stop)
    finally:
        mon.report()


if __name__ == "__main__":
    main()

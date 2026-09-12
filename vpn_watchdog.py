"""
VPN watchdog: log every disconnect / reconnect of the current tunnel.

Runs in a-Shell (iOS) or on any Python 3.9+ box. Because iOS sandboxes
each app, this script cannot read Happ's internal logs. Instead it acts
as an external monitor: every N seconds it fetches your public IP over
HTTPS and compares it to a "baseline" IP taken at start (the IP you
were seen from while VPN was up). Every state transition is timestamped
and written to a CSV log.

Detected events:
  START    - baseline captured
  UP       - probe succeeded, current public IP matches baseline (VPN up)
  DOWN     - probe failed (timeout, DNS error, no network at all)
  LEAK     - probe succeeded but IP differs from baseline (VPN dropped;
             traffic is now going through your real ISP OR a different
             VPN exit node)
  RESTORE  - state returned to UP after DOWN/LEAK

Usage (in a-Shell):
    python3 ~/Documents/vpn_watchdog.py
    python3 ~/Documents/vpn_watchdog.py --interval 3
    python3 ~/Documents/vpn_watchdog.py --log ~/Documents/vpn.csv
    python3 ~/Documents/vpn_watchdog.py --baseline 203.0.113.7

Stop with Ctrl+C to see the summary.

Privacy note: the default probe endpoint (api.ipify.org) is a public IP
lookup service. Only your public IP is exchanged; no other data. Change
--endpoint if you prefer another.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import signal
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

DEFAULT_ENDPOINT = "https://api.ipify.org?format=json"
DEFAULT_INTERVAL = 5.0
DEFAULT_TIMEOUT = 5.0
DEFAULT_LOG = os.path.expanduser("~/Documents/vpn_watchdog.csv")


def probe(url: str, timeout: float) -> tuple[str, float]:
    """GET the endpoint, return (public_ip, rtt_seconds). Raises on failure."""
    t0 = time.monotonic()
    req = urllib.request.Request(url, headers={"User-Agent": "vpn-watchdog/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode("utf-8", errors="replace").strip()
    rtt = time.monotonic() - t0
    if body.startswith("{"):
        ip = json.loads(body).get("ip", body)
    else:
        ip = body
    return ip, rtt


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def fmt_duration(s: float) -> str:
    if s < 60:
        return f"{s:.1f}s"
    total = int(s)
    m, sec = divmod(total, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h{m:02d}m{sec:02d}s"
    return f"{m}m{sec:02d}s"


class Watchdog:
    def __init__(
        self,
        endpoint: str,
        interval: float,
        timeout: float,
        log_path: str,
        forced_baseline: str | None,
    ) -> None:
        self.endpoint = endpoint
        self.interval = interval
        self.timeout = timeout
        self.log_path = log_path
        self.state = "UNKNOWN"
        self.baseline_ip = forced_baseline
        self.state_since = time.monotonic()
        self.started_at = time.monotonic()
        # Counters.
        self.drops = 0          # UP -> DOWN transitions
        self.leaks = 0          # UP -> LEAK transitions
        self.state_time: dict[str, float] = {"UP": 0.0, "DOWN": 0.0, "LEAK": 0.0}
        self.longest_bad = 0.0  # longest continuous non-UP interval

        # Prepare log file with a CSV header if new.
        need_header = (
            not os.path.exists(self.log_path)
            or os.path.getsize(self.log_path) == 0
        )
        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
        if need_header:
            with open(self.log_path, "w", newline="") as f:
                csv.writer(f).writerow(
                    ["timestamp", "event", "ip", "rtt_ms", "note"]
                )

    def _write(self, event: str, ip: str | None, rtt_ms: float | None, note: str) -> None:
        row = [
            now_iso(),
            event,
            ip or "",
            f"{rtt_ms:.1f}" if rtt_ms is not None else "",
            note,
        ]
        with open(self.log_path, "a", newline="") as f:
            csv.writer(f).writerow(row)
        rtt_s = f" rtt={rtt_ms:.0f}ms" if rtt_ms is not None else ""
        ip_s = f" ip={ip}" if ip else ""
        note_s = f"  ({note})" if note else ""
        print(f"[{row[0]}] {event:<8}{ip_s}{rtt_s}{note_s}")

    def _transition(
        self, new_state: str, ip: str | None, rtt_ms: float | None, note: str = ""
    ) -> None:
        if new_state == self.state:
            return
        # Attribute time in the previous state.
        now = time.monotonic()
        dur = now - self.state_since
        if self.state in self.state_time:
            self.state_time[self.state] += dur
        if self.state in ("DOWN", "LEAK"):
            self.longest_bad = max(self.longest_bad, dur)

        # Log the transition with a descriptive event name.
        if new_state == "UP" and self.state in ("DOWN", "LEAK"):
            event = "RESTORE"
        else:
            event = new_state
        prev_note = f"prev={self.state} for {fmt_duration(dur)}"
        full_note = f"{prev_note}; {note}" if note else prev_note
        self._write(event, ip, rtt_ms, full_note)

        # Count disruptions.
        if self.state == "UP" and new_state == "DOWN":
            self.drops += 1
        elif self.state == "UP" and new_state == "LEAK":
            self.leaks += 1

        self.state = new_state
        self.state_since = now

    def tick(self) -> None:
        try:
            ip, rtt = probe(self.endpoint, self.timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            self._transition(
                "DOWN", None, None,
                note=f"probe failed: {type(e).__name__}: {e}",
            )
            return

        rtt_ms = rtt * 1000
        if self.baseline_ip is None:
            self.baseline_ip = ip
            self.state = "UP"
            self.state_since = time.monotonic()
            self._write("START", ip, rtt_ms, note="baseline captured")
            return
        if ip == self.baseline_ip:
            self._transition("UP", ip, rtt_ms)
        else:
            self._transition(
                "LEAK", ip, rtt_ms,
                note=f"expected {self.baseline_ip}, saw {ip}",
            )

    def summary(self) -> None:
        # Finalise the ongoing state's duration.
        now = time.monotonic()
        dur = now - self.state_since
        if self.state in self.state_time:
            self.state_time[self.state] += dur
        if self.state in ("DOWN", "LEAK"):
            self.longest_bad = max(self.longest_bad, dur)

        total = now - self.started_at
        up = self.state_time.get("UP", 0.0)
        down = self.state_time.get("DOWN", 0.0)
        leak = self.state_time.get("LEAK", 0.0)
        uptime_pct = 100.0 * up / total if total else 0.0
        disruptions = self.drops + self.leaks

        print()
        print("=" * 52)
        print(" VPN Watchdog summary")
        print("=" * 52)
        print(f"  Total observed  : {fmt_duration(total)}")
        print(f"  Baseline VPN IP : {self.baseline_ip or '(never captured)'}")
        print(f"  Disruptions     : {disruptions}  (DOWN: {self.drops}, LEAK: {self.leaks})")
        print(f"  Time UP         : {fmt_duration(up)}   ({uptime_pct:.2f}%)")
        print(f"  Time DOWN       : {fmt_duration(down)}")
        print(f"  Time LEAK       : {fmt_duration(leak)}")
        print(f"  Longest bad run : {fmt_duration(self.longest_bad)}")
        if disruptions:
            mtbf = up / disruptions
            print(f"  Mean uptime     : {fmt_duration(mtbf)} between disruptions")
        print(f"  Log             : {self.log_path}")
        print("=" * 52)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                    help=f"seconds between probes (default {DEFAULT_INTERVAL})")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help=f"HTTPS probe timeout (default {DEFAULT_TIMEOUT})")
    ap.add_argument("--endpoint", default=DEFAULT_ENDPOINT,
                    help="URL that returns your public IP")
    ap.add_argument("--log", default=DEFAULT_LOG,
                    help=f"CSV log path (default {DEFAULT_LOG})")
    ap.add_argument("--baseline", default=None,
                    help="pin an expected VPN IP instead of auto-detect")
    args = ap.parse_args()

    wd = Watchdog(args.endpoint, args.interval, args.timeout, args.log, args.baseline)

    print(f"# VPN Watchdog")
    print(f"# endpoint : {args.endpoint}")
    print(f"# interval : {args.interval}s   timeout : {args.timeout}s")
    print(f"# log      : {args.log}")
    if args.baseline:
        print(f"# baseline : {args.baseline} (pinned)")
    print(f"# Ctrl+C to stop and see the summary.")
    print()

    stop = False

    def on_signal(_sig, _frm):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    try:
        next_tick = time.monotonic()
        while not stop:
            wd.tick()
            next_tick += args.interval
            # Sleep in short slices so Ctrl+C is responsive.
            while not stop:
                remaining = next_tick - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.5, remaining))
    finally:
        wd.summary()


if __name__ == "__main__":
    main()

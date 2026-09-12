"""
Universal VPN diagnostic test.

Runs a long-duration test that combines ACTIVE phases (frequent probes,
tunnel stays warm) and IDLE phases (rare probes, tunnel actually goes
quiet). Records every probe and every state transition, then classifies
the disruption pattern into one of the likely root causes:

  IDLE_TIMEOUT       Drops cluster right after quiet periods (>= 30s
                     silence) - either the server or your carrier's NAT
                     is killing idle sessions.

  SCHEDULED_TIMEOUT  Drops happen at very regular intervals (low
                     coefficient of variation) - a fixed keepalive
                     timeout somewhere in the path.

  NETWORK_TRANSITION Fast recoveries (median < 5 s) - looks like Wi-Fi
                     <-> LTE micro-switches or IP address changes.

  SERVER_SIDE        Drops random, recoveries slow - the remote server
                     or its upstream is the issue.

  NO_DISRUPTIONS     Nothing broke during the test window.

  INSUFFICIENT_DATA  1-2 disruptions - can hint but not conclude.

The verdict is printed on stop; the CSV log is saved for later review
or graphing in Numbers / Excel.

Usage:
    python3 ~/Documents/vpn_diagnose.py
    python3 ~/Documents/vpn_diagnose.py --active-min 5 --idle-min 10
    python3 ~/Documents/vpn_diagnose.py --log ~/Documents/vpn.csv

Ctrl+C to stop and get the report.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import signal
import statistics
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

DEFAULT_ENDPOINT = "https://api.ipify.org?format=json"
DEFAULT_LOG = os.path.expanduser("~/Documents/vpn_diagnose.csv")


def probe(url: str, timeout: float) -> tuple[str, float]:
    """Return (public_ip, rtt_seconds); raise on failure."""
    t0 = time.monotonic()
    req = urllib.request.Request(url, headers={"User-Agent": "vpn-diagnose/1.0"})
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
    total = int(round(s))
    m, sec = divmod(total, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h{m:02d}m{sec:02d}s"
    return f"{m}m{sec:02d}s"


@dataclass
class Disruption:
    kind: str            # "DOWN" or "LEAK"
    start_mono: float
    phase: str           # "active" or "idle"
    silence_secs: float  # gap between last successful probe and detected drop
    end_mono: float | None = None

    @property
    def duration(self) -> float | None:
        if self.end_mono is None:
            return None
        return self.end_mono - self.start_mono


class Diagnostic:
    def __init__(
        self,
        endpoint: str,
        timeout: float,
        log_path: str,
        active_interval: float,
        idle_interval: float,
        active_len_s: float,
        idle_len_s: float,
    ) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        self.log_path = log_path
        self.active_interval = active_interval
        self.idle_interval = idle_interval
        self.active_len_s = active_len_s
        self.idle_len_s = idle_len_s

        self.state = "UNKNOWN"
        self.baseline_ip: str | None = None
        self.state_since = time.monotonic()
        self.started_at = time.monotonic()
        self.last_probe_mono: float | None = None
        self.phase = "active"

        self.disruptions: list[Disruption] = []
        self.rtts_ms: list[float] = []

        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
        new = not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0
        if new:
            with open(self.log_path, "w", newline="") as f:
                csv.writer(f).writerow(
                    ["timestamp", "phase", "event", "ip", "rtt_ms", "note"]
                )

    def _write_csv(self, event: str, ip: str | None, rtt_ms: float | None, note: str) -> None:
        with open(self.log_path, "a", newline="") as f:
            csv.writer(f).writerow([
                now_iso(),
                self.phase,
                event,
                ip or "",
                f"{rtt_ms:.1f}" if rtt_ms is not None else "",
                note,
            ])

    def _print(self, event: str, ip: str | None, rtt_ms: float | None, note: str) -> None:
        rtt_s = f" rtt={rtt_ms:.0f}ms" if rtt_ms is not None else ""
        ip_s = f" ip={ip}" if ip else ""
        note_s = f"  ({note})" if note else ""
        print(f"[{now_iso()}] {self.phase:<6} {event:<8}{ip_s}{rtt_s}{note_s}")

    def _emit(self, event: str, ip: str | None = None, rtt_ms: float | None = None,
              note: str = "", print_it: bool = True) -> None:
        self._write_csv(event, ip, rtt_ms, note)
        if print_it:
            self._print(event, ip, rtt_ms, note)

    def _transition(self, new_state: str, ip: str | None, rtt_ms: float | None) -> None:
        if new_state == self.state:
            return
        now = time.monotonic()
        dur = now - self.state_since
        prev = self.state
        note = f"prev={prev} for {fmt_duration(dur)}"

        if prev == "UP" and new_state in ("DOWN", "LEAK"):
            silence = 0.0
            if self.last_probe_mono is not None:
                silence = now - self.last_probe_mono
            self.disruptions.append(Disruption(
                kind=new_state,
                start_mono=now,
                phase=self.phase,
                silence_secs=silence,
            ))
            note += f"; silence={fmt_duration(silence)}"

        if new_state == "UP" and prev in ("DOWN", "LEAK"):
            event = "RESTORE"
            if self.disruptions and self.disruptions[-1].end_mono is None:
                self.disruptions[-1].end_mono = now
        else:
            event = new_state

        self._emit(event, ip, rtt_ms, note)
        self.state = new_state
        self.state_since = now

    def probe_once(self) -> None:
        try:
            ip, rtt = probe(self.endpoint, self.timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            self._transition("DOWN", None, None)
            self._emit("PROBE_FAIL", note=f"{type(e).__name__}: {e}", print_it=False)
            self.last_probe_mono = time.monotonic()
            return

        rtt_ms = rtt * 1000
        if self.baseline_ip is None:
            self.baseline_ip = ip
            self.state = "UP"
            self.state_since = time.monotonic()
            self._emit("START", ip, rtt_ms, note="baseline captured")
        elif ip == self.baseline_ip:
            was = self.state
            self._transition("UP", ip, rtt_ms)
            if was == "UP":
                # silent per-probe row so we still get an RTT trail
                self._emit("PROBE", ip, rtt_ms, "", print_it=False)
            self.rtts_ms.append(rtt_ms)
        else:
            self._transition("LEAK", ip, rtt_ms)
        self.last_probe_mono = time.monotonic()

    def _switch_phase(self, new_phase: str) -> None:
        if new_phase == self.phase:
            return
        self.phase = new_phase
        interval = self.active_interval if new_phase == "active" else self.idle_interval
        self._emit("PHASE", note=f"entering {new_phase.upper()} (probe every {interval:.0f}s)")

    def run(self, should_stop) -> None:
        self._emit(
            "BEGIN",
            note=(
                f"active_window={self.active_len_s / 60:.0f}m@{self.active_interval:.0f}s, "
                f"idle_window={self.idle_len_s / 60:.0f}m@{self.idle_interval:.0f}s"
            ),
        )
        phase_started = time.monotonic()

        while not should_stop():
            elapsed = time.monotonic() - phase_started
            if self.phase == "active" and elapsed >= self.active_len_s:
                self._switch_phase("idle")
                phase_started = time.monotonic()
            elif self.phase == "idle" and elapsed >= self.idle_len_s:
                self._switch_phase("active")
                phase_started = time.monotonic()

            self.probe_once()

            interval = self.active_interval if self.phase == "active" else self.idle_interval
            deadline = time.monotonic() + interval
            while not should_stop():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.5, remaining))

        # Close any open disruption at end of test.
        if self.disruptions and self.disruptions[-1].end_mono is None:
            self.disruptions[-1].end_mono = time.monotonic()
        self._emit("END")

    # ---------------- classification -----------------

    def classify(self) -> dict:
        n = len(self.disruptions)
        if n == 0:
            return {
                "verdict": "NO_DISRUPTIONS",
                "headline": "За весь тест VPN ни разу не отвалился.",
                "hints": [
                    "Пусти тест подольше или в условиях, в которых обычно рвётся "
                    "(в кармане, ночью, с использованием тяжёлых приложений).",
                ],
                "stats": {"n": 0},
            }

        recoveries = [d.duration for d in self.disruptions if d.duration is not None]
        starts = [d.start_mono for d in self.disruptions]
        intervals = [b - a for a, b in zip(starts, starts[1:])]

        mean_rec = statistics.mean(recoveries) if recoveries else None
        median_rec = statistics.median(recoveries) if recoveries else None
        cv_intervals: float | None = None
        if len(intervals) >= 2:
            m = statistics.mean(intervals)
            s = statistics.stdev(intervals)
            cv_intervals = (s / m) if m > 0 else None

        idle_related = sum(1 for d in self.disruptions if d.silence_secs >= 30)
        idle_ratio = idle_related / n
        leaks = sum(1 for d in self.disruptions if d.kind == "LEAK")
        downs = n - leaks
        pending = sum(1 for d in self.disruptions if d.end_mono is None)

        hints: list[str] = []
        if idle_ratio >= 0.5:
            hints.append(
                f"{int(idle_ratio * 100)}% разрывов случились после тишины >=30 с "
                "→ похоже на IDLE_TIMEOUT (сервер или carrier NAT рвёт idle-сессии)."
            )
        if cv_intervals is not None and cv_intervals < 0.25 and len(intervals) >= 3:
            hints.append(
                f"Интервалы между разрывами регулярные (CV={cv_intervals:.2f}) "
                "→ фиксированный таймаут где-то в тракте."
            )
        if mean_rec is not None:
            if mean_rec < 5:
                hints.append(
                    f"Восстановление быстрое (среднее {mean_rec:.1f} с) "
                    "→ похоже на переключение сети / автопереподключение клиента."
                )
            elif mean_rec > 30:
                hints.append(
                    f"Восстановление долгое (среднее {mean_rec:.1f} с) "
                    "→ похоже на серверную проблему или медленное восстановление iOS NE."
                )
        if leaks:
            hints.append(
                f"{leaks} из {n} — LEAK (интернет остался, VPN отпал). "
                "В Happ не включён/не работает kill-switch."
            )
        else:
            hints.append(
                f"Все {n} разрывов — DOWN. Либо kill-switch работает, "
                "либо пропадает сама сеть целиком."
            )
        if pending:
            hints.append(f"{pending} разрыв(а) ещё не восстановился к моменту остановки теста.")

        if n < 3:
            verdict = "INSUFFICIENT_DATA"
            headline = "Слишком мало разрывов для уверенного диагноза — прогони тест дольше."
        elif idle_ratio >= 0.5 and (cv_intervals is None or cv_intervals < 0.4):
            verdict = "IDLE_TIMEOUT"
            headline = "Диагноз: VPN валится, когда трафик долго не идёт."
        elif cv_intervals is not None and cv_intervals < 0.25:
            verdict = "SCHEDULED_TIMEOUT"
            headline = "Диагноз: где-то в тракте жёсткий фиксированный таймаут сессии."
        elif mean_rec is not None and mean_rec < 5:
            verdict = "NETWORK_TRANSITION"
            headline = "Диагноз: обрывы похожи на переключения сети (Wi-Fi<->LTE)."
        else:
            verdict = "SERVER_SIDE"
            headline = "Диагноз: обрывы случайные, восстановление медленное — похоже на сервер."

        return {
            "verdict": verdict,
            "headline": headline,
            "hints": hints,
            "stats": {
                "n": n,
                "downs": downs,
                "leaks": leaks,
                "pending": pending,
                "mean_recovery_s": mean_rec,
                "median_recovery_s": median_rec,
                "idle_ratio": idle_ratio,
                "cv_intervals": cv_intervals,
                "mean_interval_s": statistics.mean(intervals) if intervals else None,
            },
        }

    def report(self) -> None:
        total = time.monotonic() - self.started_at
        print()
        print("=" * 60)
        print(" VPN Diagnostic Report")
        print("=" * 60)
        print(f"  Total observed  : {fmt_duration(total)}")
        print(f"  Baseline VPN IP : {self.baseline_ip or '(never captured)'}")
        if self.rtts_ms:
            rtts = sorted(self.rtts_ms)
            p95 = rtts[min(len(rtts) - 1, int(len(rtts) * 0.95))]
            print(f"  RTT (median/p95): {statistics.median(rtts):.0f} / {p95:.0f} ms  "
                  f"(n={len(rtts)})")

        c = self.classify()
        s = c["stats"]
        print()
        print(f"  Disruptions     : {s['n']}  (DOWN: {s.get('downs', 0)}, "
              f"LEAK: {s.get('leaks', 0)}, pending: {s.get('pending', 0)})")
        if s.get("mean_recovery_s") is not None:
            print(f"  Recovery time   : mean {fmt_duration(s['mean_recovery_s'])}, "
                  f"median {fmt_duration(s['median_recovery_s'])}")
        if s.get("mean_interval_s") is not None:
            cv = s.get("cv_intervals")
            cv_s = f" (CV={cv:.2f})" if cv is not None else ""
            print(f"  Between drops   : mean {fmt_duration(s['mean_interval_s'])}{cv_s}")
        print(f"  Idle-related    : {int(s.get('idle_ratio', 0) * 100)}%")
        print()
        print(f"  Verdict         : {c['verdict']}")
        print(f"  {c['headline']}")
        for h in c.get("hints", []):
            print(f"    - {h}")
        print()
        print(f"  Log             : {self.log_path}")
        print("=" * 60)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--endpoint", default=DEFAULT_ENDPOINT,
                    help="URL that returns your public IP")
    ap.add_argument("--log", default=DEFAULT_LOG, help="CSV log path")
    ap.add_argument("--timeout", type=float, default=5.0, help="probe timeout (s)")
    ap.add_argument("--active-interval", type=float, default=10.0,
                    help="probe interval during ACTIVE window (s)")
    ap.add_argument("--idle-interval", type=float, default=60.0,
                    help="probe interval during IDLE window (s)")
    ap.add_argument("--active-min", type=float, default=10.0,
                    help="length of ACTIVE window (minutes)")
    ap.add_argument("--idle-min", type=float, default=15.0,
                    help="length of IDLE window (minutes)")
    args = ap.parse_args()

    d = Diagnostic(
        endpoint=args.endpoint,
        timeout=args.timeout,
        log_path=args.log,
        active_interval=args.active_interval,
        idle_interval=args.idle_interval,
        active_len_s=args.active_min * 60,
        idle_len_s=args.idle_min * 60,
    )

    print("# VPN Universal Diagnostic")
    print(f"# endpoint : {args.endpoint}")
    print(f"# active   : {args.active_min:.0f}m windows, probe every {args.active_interval:.0f}s")
    print(f"# idle     : {args.idle_min:.0f}m windows, probe every {args.idle_interval:.0f}s")
    print(f"# log      : {args.log}")
    print(f"# Ctrl+C to stop and get the diagnosis.")
    print()

    stop = False

    def on_signal(_sig, _frm):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    try:
        d.run(lambda: stop)
    finally:
        d.report()


if __name__ == "__main__":
    main()

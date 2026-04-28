"""
baseline.py — Rolling Baseline Tracker
Maintains a 30-minute sliding window of per-second request counts.
Recalculates mean and stddev every 60 seconds.
Keeps per-hour slots and prefers the current hour's data when mature.

Why per-hour slots?
  Traffic at 2 AM looks very different from traffic at 2 PM.
  Blending them without weighting would raise false positives during quiet hours
  and suppress alerts during busy ones. Per-hour slots let the baseline
  "remember" what normal looks like for the current hour of the day.

Sliding window mechanics:
  - self._buckets: dict of int(timestamp) → request_count for that second.
  - On every recalculation we drop buckets older than window_minutes * 60.
  - stddev uses population stddev (ddof=0); min is floor_stddev to avoid
    the zero-stddev edge case on completely flat traffic.
"""

import logging
import math
import threading
import time
from collections import defaultdict
from typing import Optional

log = logging.getLogger("hng.baseline")


class BaselineTracker:
    """
    Thread-safe rolling baseline.
    Call record_request(ts) from the monitor thread.
    Call run() in its own thread to trigger periodic recalculations.
    """

    def __init__(self, cfg: dict):
        self.cfg         = cfg
        bc               = cfg["baseline"]
        self._window_secs  = bc["window_minutes"] * 60          # 1800 s
        self._recalc_iv    = bc["recalc_interval_seconds"]       # 60 s
        self._min_samples  = bc["min_samples"]                   # 10
        self._floor_mean   = bc["floor_mean"]                    # 1.0
        self._floor_stddev = bc["floor_stddev"]                  # 0.5

        self._lock = threading.Lock()

        # Per-second bucket: second_ts (int) → count
        self._buckets: dict[int, int] = defaultdict(int)

        # Per-hour slot: hour_key (YYYY-MM-DD-HH) → {"mean": float, "stddev": float, "n": int}
        self._hourly: dict[str, dict] = {}

        # Current effective baseline (updated every recalc)
        self._effective_mean   = bc["floor_mean"]
        self._effective_stddev = bc["floor_stddev"]

        # Per-IP baseline error rate (approximation — updated alongside global)
        self._global_error_rate_baseline = 0.0

        # History for dashboard graphing (list of (ts, mean, stddev))
        self._history: list[tuple[float, float, float]] = []
        self._history_max = cfg["dashboard"]["metrics_history_minutes"] * 60  # keep ~1 h

        self.last_recalc_ts: float = 0.0

    # ------------------------------------------------------------------
    # Called by monitor thread on every parsed log line
    # ------------------------------------------------------------------

    def record_request(self, ts: float):
        """Increment the per-second bucket for the given timestamp."""
        second = int(ts)
        with self._lock:
            self._buckets[second] += 1

    # ------------------------------------------------------------------
    # Properties (thread-safe reads)
    # ------------------------------------------------------------------

    @property
    def effective_mean(self) -> float:
        with self._lock:
            return self._effective_mean

    @property
    def effective_stddev(self) -> float:
        with self._lock:
            return self._effective_stddev

    def get_baseline_snapshot(self) -> dict:
        with self._lock:
            return {
                "mean":   self._effective_mean,
                "stddev": self._effective_stddev,
                "history": list(self._history[-120:]),  # last 120 recalcs (≈2 h)
            }

    # ------------------------------------------------------------------
    # Background recalculation loop
    # ------------------------------------------------------------------

    def run(self):
        """Recalculate baseline every recalc_interval_seconds. Runs forever."""
        while True:
            time.sleep(self._recalc_iv)
            self._recalculate()

    def _recalculate(self):
        """
        1. Evict buckets older than window_seconds.
        2. Compute mean and stddev from remaining per-second counts.
        3. Update per-hour slot with this calculation.
        4. Choose effective baseline: prefer current-hour slot if mature.
        5. Write audit log entry.
        """
        now    = time.time()
        cutoff = now - self._window_secs
        hour_key = _hour_key(now)

        with self._lock:
            # --- Eviction ---
            stale = [s for s in self._buckets if s < cutoff]
            for s in stale:
                del self._buckets[s]

            counts = list(self._buckets.values())

        n = len(counts)

        if n < self._min_samples:
            log.debug("Baseline recalc skipped — only %d samples (need %d)", n, self._min_samples)
            return

        mean   = sum(counts) / n
        stddev = math.sqrt(sum((x - mean) ** 2 for x in counts) / n)
        mean   = max(mean,   self._floor_mean)
        stddev = max(stddev, self._floor_stddev)

        with self._lock:
            # Update hourly slot
            slot = self._hourly.setdefault(hour_key, {"mean": mean, "stddev": stddev, "n": n})
            # Exponential moving average within the same hour slot
            alpha = 0.3
            slot["mean"]   = alpha * mean   + (1 - alpha) * slot["mean"]
            slot["stddev"] = alpha * stddev + (1 - alpha) * slot["stddev"]
            slot["n"]      = n

            # Choose effective: prefer current-hour if ≥ min_samples, else global window
            if slot["n"] >= self._min_samples:
                eff_mean   = slot["mean"]
                eff_stddev = slot["stddev"]
                source = f"hourly:{hour_key}"
            else:
                eff_mean   = mean
                eff_stddev = stddev
                source = "global_window"

            self._effective_mean   = eff_mean
            self._effective_stddev = eff_stddev

            # Append history point
            self._history.append((now, eff_mean, eff_stddev))
            # Prune history older than history_max seconds
            cutoff_h = now - self._history_max
            self._history = [h for h in self._history if h[0] >= cutoff_h]

        self.last_recalc_ts = now
        log.info(
            "[BASELINE RECALC] source=%s mean=%.3f stddev=%.3f n=%d",
            source, eff_mean, eff_stddev, n
        )
        _write_audit(
            action="BASELINE_RECALC",
            detail=f"source={source} mean={eff_mean:.3f} stddev={eff_stddev:.3f} n={n}",
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hour_key(ts: float) -> str:
    import datetime
    dt = datetime.datetime.utcfromtimestamp(ts)
    return dt.strftime("%Y-%m-%d-%H")


def _write_audit(action: str, ip: str = "-", condition: str = "-",
                 rate: str = "-", baseline: str = "-",
                 duration: str = "-", detail: str = ""):
    """
    Structured audit log format:
    [timestamp] ACTION ip | condition | rate | baseline | duration
    """
    import datetime
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"[{ts}] {action} {ip} | {condition} | {rate} | {baseline} | {duration}"
    if detail:
        line += f" | {detail}"
    audit_path = "/var/log/detector/audit.log"
    try:
        with open(audit_path, "a") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        log.warning("Could not write audit log: %s", exc)

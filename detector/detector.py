"""
detector.py — Anomaly Detector
Evaluates every incoming log record against the rolling baseline.
Fires on two independent conditions — whichever comes first:
  1. Z-score:           (current_rate - mean) / stddev > threshold (default 3.0)
  2. Rate multiplier:   current_rate > N * mean              (default 5×)

Error surge:
  If an IP's 4xx/5xx rate exceeds 3× the baseline error rate, its detection
  thresholds are automatically tightened by error_surge_tighten_factor (0.6).
  This means a "bad" IP will be flagged earlier than a well-behaved one.

Global anomaly:
  Same logic applied to the global (all-IPs) request rate.
  No iptables block — Slack alert only, since we can't block the internet.
"""

import logging
import math
import time
import threading
from typing import Optional

log = logging.getLogger("hng.detector")


class AnomalyDetector:
    """
    Stateless evaluation engine.
    Receives enriched log records from LogMonitor and compares against
    the live baseline from BaselineTracker.
    """

    def __init__(self, cfg: dict, baseline, blocker, notifier):
        self.cfg       = cfg
        self.baseline  = baseline
        self.blocker   = blocker
        self.notifier  = notifier

        dc = cfg["detection"]
        self._zscore_thresh    = dc["zscore_threshold"]          # 3.0
        self._rate_mult_thresh = dc["rate_multiplier_threshold"] # 5.0
        self._error_mult       = dc["error_surge_multiplier"]    # 3.0
        self._tighten          = dc["error_surge_tighten_factor"]# 0.6

        # Monitor injected after construction via set_monitor()
        self._monitor = None

        # Prevent re-alerting the same IP within the same minute
        self._recent_alerts: dict[str, float] = {}
        self._recent_global_alert: float = 0.0
        self._alert_cooldown = 60.0   # seconds
        self._lock = threading.Lock()

        # Track baseline error rate floor
        self._error_rate_baseline = 0.05  # req/s — updated from monitor

    # ------------------------------------------------------------------
    # Main evaluation — called on every parsed log line
    # ------------------------------------------------------------------

    def set_monitor(self, monitor):
        """Inject monitor reference (called from main.py after construction)."""
        self._monitor = monitor

    def evaluate(self, ip: str, record: dict):
        """
        Evaluate one log record. Called from the monitor thread.
        Fast path: skip if IP is already banned.
        """
        if self.blocker.is_banned(ip):
            return

        ip_rate     = self._get_ip_rate(ip)
        global_rate = self._get_global_rate()
        ip_err_rate = self._get_ip_error_rate(ip)

        mean   = self.baseline.effective_mean
        stddev = self.baseline.effective_stddev

        # --- Error surge check: tighten thresholds for misbehaving IPs ---
        zscore_thresh    = self._zscore_thresh
        rate_mult_thresh = self._rate_mult_thresh
        error_surge = False

        if self._error_rate_baseline > 0:
            if ip_err_rate > self._error_mult * self._error_rate_baseline:
                zscore_thresh    *= self._tighten
                rate_mult_thresh *= self._tighten
                error_surge       = True
                log.debug(
                    "Error surge for %s: err_rate=%.3f baseline_err=%.3f — thresholds tightened",
                    ip, ip_err_rate, self._error_rate_baseline
                )

        # --- Per-IP anomaly ---
        fired, condition = self._check_anomaly(
            ip_rate, mean, stddev, zscore_thresh, rate_mult_thresh
        )
        if fired:
            self._handle_ip_anomaly(ip, ip_rate, mean, stddev, condition, error_surge)

        # --- Global anomaly (one cooldown across all IPs) ---
        now = time.time()
        with self._lock:
            global_cooldown_ok = (now - self._recent_global_alert) > self._alert_cooldown

        if global_cooldown_ok:
            g_fired, g_condition = self._check_anomaly(
                global_rate, mean, stddev, self._zscore_thresh, self._rate_mult_thresh
            )
            if g_fired:
                self._handle_global_anomaly(global_rate, mean, stddev, g_condition)

    # ------------------------------------------------------------------
    # Core detection logic
    # ------------------------------------------------------------------

    def _check_anomaly(
        self,
        rate: float,
        mean: float,
        stddev: float,
        zscore_thresh: float,
        rate_mult_thresh: float,
    ) -> tuple[bool, str]:
        """
        Returns (fired, condition_description).
        Checks z-score AND rate multiplier independently — fires on either.
        """
        if stddev > 0:
            zscore = (rate - mean) / stddev
        else:
            zscore = 0.0

        if zscore > zscore_thresh:
            return True, f"zscore={zscore:.2f} > threshold={zscore_thresh}"

        if mean > 0 and rate > rate_mult_thresh * mean:
            return True, f"rate={rate:.2f} > {rate_mult_thresh}x mean={mean:.2f}"

        return False, ""

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    def _handle_ip_anomaly(
        self,
        ip: str,
        rate: float,
        mean: float,
        stddev: float,
        condition: str,
        error_surge: bool,
    ):
        now = time.time()
        with self._lock:
            last = self._recent_alerts.get(ip, 0.0)
            if now - last < self._alert_cooldown:
                return
            self._recent_alerts[ip] = now

        extra = " [error_surge]" if error_surge else ""
        log.warning(
            "ANOMALY: IP %s | rate=%.2f req/s | %s%s",
            ip, rate, condition, extra
        )
        # Block (iptables + Slack) — must complete within 10 seconds
        self.blocker.ban(
            ip=ip,
            rate=rate,
            mean=mean,
            stddev=stddev,
            condition=condition + extra,
        )

    def _handle_global_anomaly(
        self,
        rate: float,
        mean: float,
        stddev: float,
        condition: str,
    ):
        now = time.time()
        with self._lock:
            self._recent_global_alert = now

        log.warning(
            "GLOBAL ANOMALY: rate=%.2f req/s | %s",
            rate, condition
        )
        self.notifier.send_global_alert(
            rate=rate,
            mean=mean,
            stddev=stddev,
            condition=condition,
        )

    # ------------------------------------------------------------------
    # Rate accessors
    # ------------------------------------------------------------------

    def _get_ip_rate(self, ip: str) -> float:
        try:
            return self._monitor.get_ip_rate(ip)
        except AttributeError:
            return 0.0

    def _get_global_rate(self) -> float:
        try:
            return self._monitor.get_global_rate()
        except AttributeError:
            return 0.0

    def _get_ip_error_rate(self, ip: str) -> float:
        try:
            return self._monitor.get_ip_error_rate(ip)
        except AttributeError:
            return 0.0

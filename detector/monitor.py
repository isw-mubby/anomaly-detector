"""
monitor.py — Log Monitor
Continuously tails the Nginx JSON access log, parses each line, and feeds
parsed records to the AnomalyDetector and BaselineTracker.

Design:
  - Uses a blocking readline() loop with seek-to-end on startup.
  - Handles log rotation by re-opening the file if inode changes.
  - Tracks per-IP sliding windows (deque of timestamps, last 60 s).
  - Tracks global sliding window (deque of timestamps, last 60 s).
"""

import json
import logging
import os
import threading
import time
from collections import defaultdict, deque
from typing import Optional

log = logging.getLogger("hng.monitor")


class LogMonitor:
    """
    Tails /var/log/nginx/hng-access.log line-by-line.
    For each parsed line it:
      1. Updates per-IP and global sliding windows (deque, eviction-based).
      2. Hands the enriched record to AnomalyDetector.
      3. Updates BaselineTracker per-second counters.
    """

    def __init__(self, cfg: dict, detector, baseline):
        self.cfg        = cfg
        self.detector   = detector
        self.baseline   = baseline
        self._lock      = threading.Lock()

        window_secs = cfg["sliding_window"]["window_seconds"]  # 60 s

        # --- Per-IP deque: each entry is a float timestamp ---
        # Eviction: pop_left while oldest entry < now - window_secs
        self._ip_windows: dict[str, deque] = defaultdict(
            lambda: deque()
        )

        # --- Global deque: same eviction logic ---
        self._global_window: deque = deque()

        # Per-IP 4xx/5xx deque for error-surge detection
        self._ip_error_windows: dict[str, deque] = defaultdict(
            lambda: deque()
        )
        self._global_error_window: deque = deque()

        self._window_secs = window_secs

        # Expose for dashboard
        self.lines_processed = 0
        self.top_ips: dict[str, int] = defaultdict(int)   # cumulative hit count
        self._top_ips_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public helpers (thread-safe reads for dashboard/detector)
    # ------------------------------------------------------------------

    def get_ip_rate(self, ip: str) -> float:
        """Return requests/second for this IP over the last window_secs."""
        with self._lock:
            return self._evict_and_count(self._ip_windows[ip]) / self._window_secs

    def get_global_rate(self) -> float:
        """Return global requests/second over the last window_secs."""
        with self._lock:
            return self._evict_and_count(self._global_window) / self._window_secs

    def get_ip_error_rate(self, ip: str) -> float:
        with self._lock:
            return self._evict_and_count(self._ip_error_windows[ip]) / self._window_secs

    def get_global_error_rate(self) -> float:
        with self._lock:
            return self._evict_and_count(self._global_error_window) / self._window_secs

    def snapshot_top_ips(self, n: int = 10) -> list[tuple[str, int]]:
        with self._top_ips_lock:
            return sorted(self.top_ips.items(), key=lambda x: x[1], reverse=True)[:n]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict_and_count(self, dq: deque) -> int:
        """
        Remove timestamps older than window_secs from the LEFT of the deque,
        then return the remaining count.
        Deque invariant: entries are appended right in ascending timestamp order,
        so the oldest is always at the left — O(k) eviction where k = evicted count.
        """
        cutoff = time.time() - self._window_secs
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def _record_hit(self, ip: str, ts: float, is_error: bool):
        """
        Append timestamp to the appropriate deques.
        No eviction here — eviction happens lazily on read.
        """
        with self._lock:
            self._ip_windows[ip].append(ts)
            self._global_window.append(ts)
            if is_error:
                self._ip_error_windows[ip].append(ts)
                self._global_error_window.append(ts)

    def _parse_line(self, line: str) -> Optional[dict]:
        """Parse one JSON log line. Returns None on parse failure."""
        line = line.strip()
        if not line:
            return None
        try:
            record = json.loads(line)
            # Normalise field names (our nginx.conf uses these keys)
            return {
                "ip":     record.get("source_ip", record.get("remote_addr", "-")),
                "ts":     float(record.get("timestamp", time.time())),
                "method": record.get("method", "-"),
                "path":   record.get("path", "-"),
                "status": int(record.get("status", 0)),
                "size":   int(record.get("response_size", 0)),
            }
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            log.debug("Failed to parse log line: %s | err: %s", line[:120], exc)
            return None

    # ------------------------------------------------------------------
    # Log rotation detection
    # ------------------------------------------------------------------

    def _open_log(self, path: str):
        """Open log file and seek to end so we only tail new lines."""
        fh = open(path, "r", encoding="utf-8", errors="replace")
        fh.seek(0, 2)   # seek to end
        return fh, os.stat(path).st_ino

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self):
        """Continuously tail the access log. Handles rotation."""
        log_path = self.cfg["log"]["nginx_log_path"]

        # Wait until the log file exists (Nginx might not have written yet)
        while not os.path.exists(log_path):
            log.info("Waiting for log file: %s", log_path)
            time.sleep(2)

        fh, inode = self._open_log(log_path)
        log.info("Tailing %s (inode=%d)", log_path, inode)

        while True:
            line = fh.readline()
            if not line:
                # No new data — check for log rotation
                try:
                    new_inode = os.stat(log_path).st_ino
                except FileNotFoundError:
                    new_inode = None

                if new_inode != inode:
                    log.info("Log rotation detected. Re-opening file.")
                    fh.close()
                    time.sleep(0.5)
                    fh, inode = self._open_log(log_path)
                else:
                    time.sleep(0.05)   # 50 ms poll interval
                continue

            record = self._parse_line(line)
            if record is None:
                continue

            ip = record["ip"]
            ts = record["ts"]
            is_error = record["status"] >= 400

            # 1. Update sliding windows
            self._record_hit(ip, ts, is_error)

            # 2. Update baseline tracker (per-second counter)
            self.baseline.record_request(ts)

            # 3. Update cumulative top-IP counter
            with self._top_ips_lock:
                self.top_ips[ip] += 1

            # 4. Feed to anomaly detector
            self.detector.evaluate(ip, record)

            self.lines_processed += 1

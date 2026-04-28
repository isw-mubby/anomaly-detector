"""
blocker.py — IP Blocker
Manages iptables DROP rules for banned IPs.
Thread-safe. Writes structured audit log entries on every ban.
Designed to complete ban within 10 seconds of detection.
"""

import logging
import subprocess
import threading
import time
from typing import Optional

from baseline import _write_audit

log = logging.getLogger("hng.blocker")


class BanRecord:
    """Tracks the state of a single banned IP."""
    __slots__ = ("ip", "ban_ts", "condition", "rate", "mean", "stddev", "ban_count")

    def __init__(self, ip: str, condition: str, rate: float, mean: float, stddev: float):
        self.ip        = ip
        self.ban_ts    = time.time()
        self.condition = condition
        self.rate      = rate
        self.mean      = mean
        self.stddev    = stddev
        self.ban_count = 1   # increments on re-ban; used by Unbanner for backoff


class Blocker:
    """
    Thread-safe iptables manager.
    Public API:
      ban(ip, ...)  — add DROP rule + audit log
      unban(ip)     — remove DROP rule + audit log
      is_banned(ip) — O(1) lookup
    """

    def __init__(self, cfg: dict, notifier):
        self.cfg      = cfg
        self.notifier = notifier  # SlackNotifier
        self._chain   = cfg["blocking"]["iptables_chain"]

        self._lock    = threading.Lock()
        self._banned: dict[str, BanRecord] = {}

        # Back-reference to monitor — injected after construction
        self._monitor = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def ban(
        self,
        ip: str,
        rate: float,
        mean: float,
        stddev: float,
        condition: str,
    ) -> bool:
        """
        Drop packets from this IP via iptables and record the ban.
        Returns True if newly banned, False if already banned.
        The entire operation (iptables + Slack) must complete within 10 s.
        """
        t_start = time.time()

        with self._lock:
            if ip in self._banned:
                return False
            # Create record first so Unbanner can find it immediately
            record = BanRecord(ip=ip, condition=condition, rate=rate, mean=mean, stddev=stddev)
            self._banned[ip] = record

        # Insert iptables rule (outside lock to avoid holding it during subprocess)
        success = self._iptables_add(ip)

        schedule = self.cfg["blocking"]["unban_schedule_minutes"]
        duration = f"{schedule[0]}min" if schedule else "permanent"

        _write_audit(
            action="BAN",
            ip=ip,
            condition=condition,
            rate=f"{rate:.2f}req/s",
            baseline=f"mean={mean:.2f} stddev={stddev:.2f}",
            duration=duration,
        )

        elapsed = time.time() - t_start
        log.warning("BANNED %s | rule_added=%s | elapsed=%.2fs", ip, success, elapsed)

        # Slack alert — fire and forget (notifier handles timeout)
        threading.Thread(
            target=self.notifier.send_ban_alert,
            kwargs=dict(
                ip=ip, rate=rate, mean=mean, stddev=stddev,
                condition=condition, duration=duration,
            ),
            daemon=True,
        ).start()

        return True

    def unban(self, ip: str, reason: str = "backoff", next_duration: Optional[str] = None):
        """Remove iptables DROP rule and delete ban record."""
        with self._lock:
            record = self._banned.pop(ip, None)

        if record is None:
            return

        self._iptables_remove(ip)

        _write_audit(
            action="UNBAN",
            ip=ip,
            condition=record.condition,
            rate=f"{record.rate:.2f}req/s",
            baseline=f"mean={record.mean:.2f}",
            duration=f"next={next_duration or 'permanent'} reason={reason}",
        )
        log.info("UNBANNED %s | reason=%s | next=%s", ip, reason, next_duration)

        threading.Thread(
            target=self.notifier.send_unban_alert,
            kwargs=dict(
                ip=ip, condition=record.condition,
                rate=record.rate, duration=next_duration or "permanent",
            ),
            daemon=True,
        ).start()

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            return ip in self._banned

    def get_banned_list(self) -> list[dict]:
        """Return snapshot of all currently banned IPs for dashboard."""
        with self._lock:
            now = time.time()
            return [
                {
                    "ip":        r.ip,
                    "banned_at": r.ban_ts,
                    "age_secs":  int(now - r.ban_ts),
                    "condition": r.condition,
                    "rate":      r.rate,
                    "ban_count": r.ban_count,
                }
                for r in self._banned.values()
            ]

    def get_ban_record(self, ip: str) -> Optional[BanRecord]:
        with self._lock:
            return self._banned.get(ip)

    # ------------------------------------------------------------------
    # iptables helpers
    # ------------------------------------------------------------------

    def _iptables_add(self, ip: str) -> bool:
        """Add DROP rule. Returns True on success."""
        cmd = ["iptables", "-I", self._chain, "1", "-s", ip, "-j", "DROP"]
        return self._run_iptables(cmd, f"ADD {ip}")

    def _iptables_remove(self, ip: str) -> bool:
        """Remove DROP rule. Returns True on success."""
        cmd = ["iptables", "-D", self._chain, "-s", ip, "-j", "DROP"]
        return self._run_iptables(cmd, f"REMOVE {ip}")

    def _run_iptables(self, cmd: list[str], label: str) -> bool:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=8,    # Must stay well within the 10-second SLA
            )
            if result.returncode != 0:
                log.error("iptables %s failed: %s", label, result.stderr.strip())
                return False
            return True
        except subprocess.TimeoutExpired:
            log.error("iptables %s timed out!", label)
            return False
        except FileNotFoundError:
            log.error("iptables not found — is this running as root?")
            return False
        except Exception as exc:
            log.error("iptables %s error: %s", label, exc)
            return False

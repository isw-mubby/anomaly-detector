"""
unbanner.py — Auto-Unbanner
Watches banned IPs and releases them on a backoff schedule:
  ban_count=1 → unban after 10 min
  ban_count=2 → unban after 30 min
  ban_count=3 → unban after 2 hours
  ban_count≥4 → permanent (never auto-unbanned)

On each unban, ban_count increments so if the same IP gets re-banned,
its next unban duration will be longer.

A Slack notification is sent on every unban event.
"""

import logging
import time
import threading

log = logging.getLogger("hng.unbanner")


class Unbanner:
    """
    Background daemon that polls the banned IP list every 30 seconds
    and releases IPs whose ban duration has expired.
    """

    def __init__(self, cfg: dict, blocker, notifier):
        self.cfg      = cfg
        self.blocker  = blocker
        self.notifier = notifier

        # Schedule in minutes, indexed by (ban_count - 1)
        self._schedule_minutes = cfg["blocking"]["unban_schedule_minutes"]  # [10, 30, 120]

        # Track per-IP ban count separately (survives unban/re-ban cycles)
        self._ban_counts: dict[str, int] = {}
        self._lock = threading.Lock()

        self._poll_interval = 15   # seconds between checks

    # ------------------------------------------------------------------

    def run(self):
        """Main loop — poll every _poll_interval seconds."""
        while True:
            time.sleep(self._poll_interval)
            self._check_and_release()

    def _check_and_release(self):
        now = time.time()
        banned = self.blocker.get_banned_list()

        for entry in banned:
            ip        = entry["ip"]
            ban_ts    = entry["banned_at"]
            ban_count = entry["ban_count"]

            # Look up duration for this ban number
            idx = ban_count - 1
            if idx >= len(self._schedule_minutes):
                # Permanent ban — never auto-released
                continue

            duration_secs = self._schedule_minutes[idx] * 60
            if now - ban_ts < duration_secs:
                continue

            # Time to unban. Determine the next ban duration (for Slack message)
            next_idx = idx + 1
            if next_idx < len(self._schedule_minutes):
                next_dur = f"{self._schedule_minutes[next_idx]}min"
            else:
                next_dur = "permanent"

            log.info(
                "Auto-unban %s after %d min (ban_count=%d) | next_ban=%s",
                ip, self._schedule_minutes[idx], ban_count, next_dur,
            )

            # Unban via blocker
            self.blocker.unban(ip, reason="backoff_schedule", next_duration=next_dur)

            # Increment internal ban count for future bans
            with self._lock:
                self._ban_counts[ip] = ban_count + 1

    def get_next_duration(self, ip: str) -> str:
        """Return human-readable next-ban duration for this IP."""
        with self._lock:
            count = self._ban_counts.get(ip, 0)
        idx = count
        if idx < len(self._schedule_minutes):
            return f"{self._schedule_minutes[idx]}min"
        return "permanent"

    def on_reban(self, ip: str, record):
        """
        Called by Blocker when an IP is re-banned after being released.
        Restores ban_count so the next unban duration is correctly escalated.
        """
        with self._lock:
            record.ban_count = self._ban_counts.get(ip, 1)

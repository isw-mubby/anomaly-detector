"""
notifier.py — Slack Notifier
Sends Slack alerts via incoming webhook.
All messages include: condition, current rate, baseline, timestamp, ban duration.
Timeout is enforced (default 5 s) so a slow Slack doesn't block detection.
"""

import json
import logging
import time
import datetime
import threading

import requests

log = logging.getLogger("hng.notifier")


class SlackNotifier:
    """
    Sends Slack notifications for ban, unban, and global anomaly events.
    Thread-safe. Non-blocking (caller runs in its own thread).
    """

    def __init__(self, cfg: dict):
        self.cfg        = cfg
        self._webhook   = cfg["slack"]["webhook_url"]
        self._timeout   = cfg["slack"].get("timeout_seconds", 5)
        self._lock      = threading.Lock()

        # Back-reference to monitor for rate info (optional, injected later)
        self._monitor = None

        if not self._webhook:
            log.warning("No Slack webhook URL configured — alerts will be logged only.")

    # ------------------------------------------------------------------

    def send_ban_alert(
        self,
        ip: str,
        rate: float,
        mean: float,
        stddev: float,
        condition: str,
        duration: str,
    ):
        ts = _now()
        text = (
            f":rotating_light: *HNG DDoS ENGINE — IP BANNED*\n"
            f">*IP:*        `{ip}`\n"
            f">*Condition:* {condition}\n"
            f">*Rate:*      `{rate:.2f} req/s`\n"
            f">*Baseline:*  mean=`{mean:.2f}` stddev=`{stddev:.2f}`\n"
            f">*Ban Duration:* `{duration}`\n"
            f">*Timestamp:* `{ts}`"
        )
        self._post(text)

    def send_unban_alert(
        self,
        ip: str,
        condition: str,
        rate: float,
        duration: str,
    ):
        ts = _now()
        text = (
            f":white_check_mark: *HNG DDoS ENGINE — IP UNBANNED*\n"
            f">*IP:*           `{ip}`\n"
            f">*Original Cause:* {condition}\n"
            f">*Rate at Ban:*  `{rate:.2f} req/s`\n"
            f">*Next ban duration:* `{duration}`\n"
            f">*Timestamp:* `{ts}`"
        )
        self._post(text)

    def send_global_alert(
        self,
        rate: float,
        mean: float,
        stddev: float,
        condition: str,
    ):
        ts = _now()
        text = (
            f":warning: *HNG DDoS ENGINE — GLOBAL TRAFFIC SPIKE*\n"
            f">*Condition:* {condition}\n"
            f">*Global Rate:* `{rate:.2f} req/s`\n"
            f">*Baseline:*   mean=`{mean:.2f}` stddev=`{stddev:.2f}`\n"
            f">*Action:*     Monitoring — no IP block for global spikes\n"
            f">*Timestamp:*  `{ts}`"
        )
        self._post(text)

    # ------------------------------------------------------------------

    def _post(self, text: str):
        if not self._webhook:
            log.info("SLACK (no webhook): %s", text.replace("\n", " | "))
            return

        payload = {"text": text}
        try:
            resp = requests.post(
                self._webhook,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=self._timeout,
            )
            if resp.status_code != 200:
                log.error(
                    "Slack returned %d: %s",
                    resp.status_code, resp.text[:200]
                )
        except requests.RequestException as exc:
            log.error("Slack post failed: %s", exc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

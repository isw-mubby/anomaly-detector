"""
HNG Anomaly Detection Engine — main.py
Entry point. Wires together monitoring, detection, blocking, and dashboard threads.
"""

import os
import sys
import time
import logging
import threading
import signal

import yaml

from monitor import LogMonitor
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import SlackNotifier
from dashboard import DashboardServer

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def load_config(path: str = None) -> dict:
    """Load config.yaml, falling back to the file beside this script."""
    if path is None:
        path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(path) as fh:
        cfg = yaml.safe_load(fh)
    # Allow webhook URL to be injected via env (12-factor)
    env_webhook = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if env_webhook:
        cfg["slack"]["webhook_url"] = env_webhook
    return cfg


def setup_logging(cfg: dict) -> logging.Logger:
    level = getattr(logging, cfg["log"].get("log_level", "INFO").upper(), logging.INFO)
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, stream=sys.stdout)
    return logging.getLogger("hng.main")


def ensure_audit_dir(cfg: dict):
    audit_path = cfg["log"]["audit_log_path"]
    os.makedirs(os.path.dirname(audit_path), exist_ok=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    cfg = load_config()
    log = setup_logging(cfg)
    ensure_audit_dir(cfg)

    log.info("=== HNG Anomaly Detection Engine starting ===")

    # Shared state objects
    notifier  = SlackNotifier(cfg)
    blocker   = Blocker(cfg, notifier)
    unbanner  = Unbanner(cfg, blocker, notifier)
    baseline  = BaselineTracker(cfg)
    detector  = AnomalyDetector(cfg, baseline, blocker, notifier)
    monitor   = LogMonitor(cfg, detector, baseline)
    dashboard = DashboardServer(cfg, monitor, baseline, blocker, unbanner)

    # Inject monitor reference into detector (breaks circular dep at construction)
    detector.set_monitor(monitor)

    # Graceful shutdown on SIGTERM / SIGINT
    shutdown_event = threading.Event()

    def _shutdown(signum, frame):
        log.info("Shutdown signal received — stopping daemon.")
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    # Start all threads
    threads = [
        threading.Thread(target=monitor.run,    name="monitor",   daemon=True),
        threading.Thread(target=baseline.run,   name="baseline",  daemon=True),
        threading.Thread(target=unbanner.run,   name="unbanner",  daemon=True),
        threading.Thread(target=dashboard.run,  name="dashboard", daemon=True),
    ]
    for t in threads:
        t.start()
        log.info(f"Thread '{t.name}' started.")

    log.info("All subsystems running. Waiting for shutdown signal...")
    shutdown_event.wait()
    log.info("=== HNG Anomaly Detection Engine stopped ===")


if __name__ == "__main__":
    main()

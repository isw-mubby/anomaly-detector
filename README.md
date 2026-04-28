# HNG Anomaly Detection Engine

> A production-grade DDoS/anomaly detection daemon built for HNG's cloud.ng Nextcloud platform.

---

## Live Deployment

| Resource | URL |
|---|---|
| **Server IP** | `` |
| **Metrics Dashboard** | `` |
| **Nextcloud** | `` |

---

## Language Choice: Python

Python was chosen for:
- **Rapid iteration** — the collections.deque and statistics modules give us sliding-window and stddev primitives without reinventing them.
- **Subprocess control** — iptables interaction via subprocess is clean and auditable.
- **Flask** — zero-configuration HTTP dashboard in ~30 lines.
- **Ecosystem** — psutil, requests, and PyYAML are battle-tested.

Go would offer lower CPU overhead, but for a detection daemon at this traffic scale Python's GIL is not a bottleneck — the hot path is I/O-bound (log tailing) not CPU-bound.

---

## Architecture

```
Internet → Nginx (JSON logs) → Nextcloud (Nextcloud app)
                ↓ volume HNG-nginx-logs
          Detector Daemon
           ├── monitor.py     (tails log, fills sliding windows)
           ├── baseline.py    (rolling mean/stddev, per-hour slots)
           ├── detector.py    (z-score + rate multiplier evaluation)
           ├── blocker.py     (iptables DROP + audit)
           ├── unbanner.py    (backoff schedule)
           ├── notifier.py    (Slack webhooks)
           └── dashboard.py   (Flask live metrics UI)
```

See `docs/architecture.png` for the full diagram.

---

## How the Sliding Window Works

Two `collections.deque` objects are maintained:
- `_ip_windows[ip]`  — per-IP deque of float timestamps
- `_global_window`   — global deque of all request timestamps

**Insertion (append-right):**
Every parsed log line calls `_record_hit(ip, ts)`. The timestamp is appended
to the right of each deque. Because log lines arrive in chronological order,
the deque is always sorted ascending — oldest on the left, newest on the right.

**Eviction (popleft):**
When a rate is needed, `_evict_and_count()` is called:
```python
cutoff = time.time() - window_secs   # default: 60 seconds ago
while dq and dq[0] < cutoff:
    dq.popleft()
return len(dq)
```
We remove from the left while the oldest entry is outside the window.
This is O(k) where k = number of evicted entries, amortized O(1) per insertion.
The window always contains exactly the requests from the last 60 seconds.

**Rate calculation:**
```python
rate = count_in_window / window_seconds
```

This is a true sliding window — not a per-minute bucket or a fixed-interval counter.

---

## How the Baseline Works

**Window:** 30 minutes (1800 seconds) of per-second request counts.

**Storage:** `self._buckets[int(timestamp)] = count`  
Each log line increments the bucket for its second. Buckets older than 1800 s are
evicted during each recalculation.

**Recalculation (every 60 s):**
1. Evict stale buckets.
2. Compute population mean and stddev from remaining bucket values.
3. Apply floor values (`floor_mean=1.0`, `floor_stddev=0.5`) to prevent
   division-by-zero on brand-new installs or quiet hours.
4. Update the **per-hour slot** (keyed `YYYY-MM-DD-HH`) using an exponential
   moving average (α=0.3) so the slot smoothly tracks the current hour.
5. Choose the **effective baseline**:
   - If the current-hour slot has ≥ 10 samples → use it (preferred).
   - Otherwise → use the global 30-min window result.

**Per-hour slots rationale:**  
Traffic at 2 AM looks completely different from 2 PM. Blending them into a single
mean would raise false positives during quiet hours. Per-hour slots let the
baseline remember what *this hour* normally looks like.

**Audit log on every recalc:**
```
[2024-01-15T14:00:01Z] BASELINE_RECALC - | - | - | - | source=hourly:2024-01-15-14 mean=42.31 stddev=8.12 n=1800
```

---

## Detection Logic

Two conditions are evaluated independently — **whichever fires first** triggers the response:

### 1. Z-score
```python
zscore = (current_rate - mean) / stddev
if zscore > 3.0:
    fire!
```
A z-score > 3.0 means the rate is more than 3 standard deviations above normal.
Statistically, this happens by chance only 0.13% of the time in a normal distribution.

### 2. Rate Multiplier
```python
if current_rate > 5.0 * mean:
    fire!
```
Catches attacks that arrive so fast the z-score math hasn't stabilized
(e.g., during the first minute after startup when stddev is still small).

### Error Surge Tightening
If an IP's 4xx/5xx rate > 3× the baseline error rate, both thresholds
are multiplied by 0.6 (tightened). The IP will be flagged at z=1.8 and 3× mean
instead of z=3.0 and 5× mean — much earlier.

### Global vs Per-IP
- **Per-IP anomaly** → iptables DROP + Slack ban alert
- **Global anomaly** → Slack alert only (can't block the whole internet)

---

## iptables Blocking

When an IP is flagged:
```python
subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], timeout=8)
```

- Inserted at position 1 (highest priority) in the INPUT chain.
- Drops all packets from that IP at the kernel level — before they reach Nginx.
- The entire detect→block→Slack cycle completes within 10 seconds.

On unban:
```python
subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
```

Backoff schedule (ban_count → duration):
| Ban # | Duration |
|---|---|
| 1 | 10 minutes |
| 2 | 30 minutes |
| 3 | 2 hours |
| 4+ | Permanent |

---

## Setup: Fresh VPS → Fully Running Stack

### Prerequisites
- Ubuntu 22.04 LTS VPS (min 2 vCPU / 2 GB RAM)
- A domain/subdomain pointed at your VPS IP (for the dashboard)
- Slack incoming webhook URL

### Deployment
- Use deployment script

---

## Repository Structure

```
hng-anomaly-detector/
├── detector/
│   ├── main.py          # Entry point — wires all threads
│   ├── monitor.py       # Log tailing + sliding windows
│   ├── baseline.py      # 30-min rolling baseline + per-hour slots
│   ├── detector.py      # Z-score + rate multiplier detection
│   ├── blocker.py       # iptables DROP + audit log
│   ├── unbanner.py      # Backoff auto-unban
│   ├── notifier.py      # Slack webhook alerts
│   ├── dashboard.py     # Flask live metrics UI
│   ├── config.yaml      # All thresholds — nothing hardcoded
│   ├── requirements.txt
│   └── Dockerfile
├── nginx/
│   └── nginx.conf       # JSON logs, X-Forwarded-For, Nextcloud proxy
├── docs/
│   └── architecture.png
├── screenshots/
│   ├── Tool-running.png
│   ├── Ban-slack.png
│   ├── Unban-slack.png
│   ├── Global-alert-slack.png
│   ├── Iptables-banned.png
│   ├── Audit-log.png
│   └── Baseline-graph.png
├── deployment/
│   └── deploy.sh
├── docker-compose.yml
└── README.md
```

---

## Audit Log Format

```
[TIMESTAMP] ACTION IP | CONDITION | RATE | BASELINE | DURATION
```

Examples:
```
[2024-01-15T14:23:01Z] BAN 203.0.113.42 | zscore=8.32 > threshold=3.0 | 87.40req/s | mean=12.10 stddev=3.20 | 10min
[2024-01-15T14:33:05Z] UNBAN 203.0.113.42 | zscore=8.32 > threshold=3.0 | 87.40req/s | mean=12.10 | next=30min reason=backoff_schedule
[2024-01-15T14:00:01Z] BASELINE_RECALC - | - | - | - | source=hourly:2024-01-15-14 mean=42.31 stddev=8.12 n=1800
```

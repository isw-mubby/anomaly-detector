"""
dashboard.py — Live Metrics Web Dashboard
Serves a real-time dashboard via Flask, refreshing every 3 seconds.
Shows: banned IPs, global req/s, top 10 source IPs, CPU/memory, 
       baseline mean/stddev, uptime.

Served at 0.0.0.0:8080 by default. Use Nginx to reverse-proxy to a domain.
"""

import datetime
import logging
import os
import threading
import time

import psutil
from flask import Flask, jsonify, render_template_string
from flask_cors import CORS

log = logging.getLogger("hng.dashboard")

# ---------------------------------------------------------------------------
# HTML/JS template (single-file, self-contained)
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HNG Anomaly Detection Engine</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

  :root {
    --bg:      #05080f;
    --surface: #0b1120;
    --border:  #1a2a40;
    --accent:  #00e5ff;
    --red:     #ff3b5c;
    --green:   #00ff99;
    --yellow:  #ffd600;
    --text:    #c8d8e8;
    --muted:   #4a6070;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Rajdhani', sans-serif;
    font-size: 15px;
    min-height: 100vh;
  }

  /* Scanline overlay */
  body::before {
    content: '';
    position: fixed; inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,0,0,0.07) 2px,
      rgba(0,0,0,0.07) 4px
    );
    pointer-events: none;
    z-index: 100;
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 32px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    position: sticky; top: 0; z-index: 10;
  }

  .logo {
    font-family: 'Share Tech Mono', monospace;
    font-size: 20px;
    color: var(--accent);
    letter-spacing: 2px;
    text-shadow: 0 0 16px var(--accent);
  }

  .logo span { color: var(--red); }

  .status-bar {
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    color: var(--muted);
  }

  .pulse {
    display: inline-block;
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--green);
    margin-right: 6px;
    box-shadow: 0 0 8px var(--green);
    animation: pulse 1.5s ease-in-out infinite;
  }

  @keyframes pulse {
    0%,100% { opacity: 1; }
    50%      { opacity: 0.3; }
  }

  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 18px;
    padding: 24px 32px;
  }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 20px;
    position: relative;
    overflow: hidden;
  }

  .card::after {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: var(--accent);
    box-shadow: 0 0 12px var(--accent);
  }

  .card.danger::after  { background: var(--red);    box-shadow: 0 0 12px var(--red); }
  .card.warn::after    { background: var(--yellow);  box-shadow: 0 0 12px var(--yellow); }
  .card.success::after { background: var(--green);   box-shadow: 0 0 12px var(--green); }

  .card-title {
    font-size: 11px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 12px;
  }

  .big-num {
    font-family: 'Share Tech Mono', monospace;
    font-size: 42px;
    color: var(--accent);
    text-shadow: 0 0 20px var(--accent);
    line-height: 1;
  }

  .big-num.red    { color: var(--red);    text-shadow: 0 0 20px var(--red); }
  .big-num.green  { color: var(--green);  text-shadow: 0 0 20px var(--green); }
  .big-num.yellow { color: var(--yellow); text-shadow: 0 0 20px var(--yellow); }

  .sub { font-size: 12px; color: var(--muted); margin-top: 4px; }

  /* Wide card */
  .card.wide { grid-column: span 2; }

  table {
    width: 100%;
    border-collapse: collapse;
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
  }

  th {
    text-align: left;
    color: var(--muted);
    padding: 4px 8px;
    border-bottom: 1px solid var(--border);
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
  }

  td {
    padding: 6px 8px;
    border-bottom: 1px solid rgba(26,42,64,0.5);
    color: var(--text);
  }

  tr:hover td { background: rgba(0,229,255,0.04); }

  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 2px;
    font-size: 11px;
    font-weight: 600;
  }
  .badge.banned { background: rgba(255,59,92,0.2); color: var(--red); border: 1px solid var(--red); }
  .badge.ok     { background: rgba(0,255,153,0.1); color: var(--green); }

  .bar-wrap { background: var(--border); border-radius: 2px; height: 6px; margin-top: 8px; }
  .bar-fill  { height: 6px; border-radius: 2px; background: var(--accent); transition: width 0.8s ease; }
  .bar-fill.red { background: var(--red); }

  footer {
    text-align: center;
    padding: 16px;
    font-size: 11px;
    color: var(--muted);
    letter-spacing: 1px;
    border-top: 1px solid var(--border);
  }

  #last-update {
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
  }
</style>
</head>
<body>

<header>
  <div class="logo">HNG <span>//</span> ANOMALY DETECTION ENGINE</div>
  <div class="status-bar">
    <span class="pulse"></span>
    LIVE &nbsp;|&nbsp; <span id="last-update">—</span> &nbsp;|&nbsp; REFRESHES EVERY 3s
  </div>
</header>

<div class="grid">

  <div class="card" id="card-rate">
    <div class="card-title">Global Req / s</div>
    <div class="big-num" id="global-rate">—</div>
    <div class="sub" id="baseline-info">mean — stddev —</div>
    <div class="bar-wrap"><div class="bar-fill" id="rate-bar" style="width:0%"></div></div>
  </div>

  <div class="card danger" id="card-banned">
    <div class="card-title">Banned IPs</div>
    <div class="big-num red" id="banned-count">—</div>
    <div class="sub">Currently blocked by iptables</div>
  </div>

  <div class="card">
    <div class="card-title">CPU Usage</div>
    <div class="big-num" id="cpu-pct">—</div>
    <div class="sub">% utilization</div>
    <div class="bar-wrap"><div class="bar-fill" id="cpu-bar" style="width:0%"></div></div>
  </div>

  <div class="card">
    <div class="card-title">Memory Usage</div>
    <div class="big-num" id="mem-pct">—</div>
    <div class="sub" id="mem-detail">—</div>
    <div class="bar-wrap"><div class="bar-fill" id="mem-bar" style="width:0%"></div></div>
  </div>

  <div class="card">
    <div class="card-title">Uptime</div>
    <div class="big-num" id="uptime" style="font-size:28px">—</div>
    <div class="sub">Detector running since start</div>
  </div>

  <div class="card">
    <div class="card-title">Lines Processed</div>
    <div class="big-num green" id="lines-processed">—</div>
    <div class="sub">Log entries parsed</div>
  </div>

  <!-- Top IPs table - wide -->
  <div class="card wide">
    <div class="card-title">Top 10 Source IPs (cumulative)</div>
    <table>
      <thead><tr><th>#</th><th>IP Address</th><th>Requests</th><th>Status</th></tr></thead>
      <tbody id="top-ips-body">
        <tr><td colspan="4" style="color:var(--muted);text-align:center">Loading…</td></tr>
      </tbody>
    </table>
  </div>

  <!-- Banned IPs table - wide -->
  <div class="card wide danger">
    <div class="card-title">Active Bans</div>
    <table>
      <thead><tr><th>IP Address</th><th>Rate at Ban</th><th>Condition</th><th>Age</th><th>Ban #</th></tr></thead>
      <tbody id="banned-body">
        <tr><td colspan="5" style="color:var(--muted);text-align:center">No active bans</td></tr>
      </tbody>
    </table>
  </div>

</div>

<footer>HNG Anomaly Detection Engine &nbsp;|&nbsp; cloud.ng &nbsp;|&nbsp; All times UTC</footer>

<script>
const API = '/api/metrics';

async function refresh() {
  try {
    const r   = await fetch(API);
    const d   = await r.json();
    const now = new Date().toISOString().replace('T',' ').slice(0,19) + ' UTC';

    document.getElementById('last-update').textContent = now;

    // Global rate
    const rate = d.global_rate.toFixed(2);
    const mean = d.baseline.mean.toFixed(2);
    const std  = d.baseline.stddev.toFixed(2);
    document.getElementById('global-rate').textContent = rate;
    document.getElementById('baseline-info').textContent =
      `mean ${mean}  stddev ${std}`;

    // Color rate bar
    const ratePct = Math.min(100, (d.global_rate / (d.baseline.mean * 6 || 10)) * 100);
    const rateBar = document.getElementById('rate-bar');
    rateBar.style.width = ratePct + '%';
    rateBar.classList.toggle('red', ratePct > 80);

    // Banned
    document.getElementById('banned-count').textContent = d.banned_count;

    // CPU / Memory
    const cpu = d.system.cpu_pct.toFixed(1);
    document.getElementById('cpu-pct').textContent = cpu + '%';
    document.getElementById('cpu-bar').style.width = cpu + '%';

    const mem = d.system.mem_pct.toFixed(1);
    document.getElementById('mem-pct').textContent = mem + '%';
    document.getElementById('mem-detail').textContent =
      `${(d.system.mem_used_mb/1024).toFixed(2)} GB / ${(d.system.mem_total_mb/1024).toFixed(2)} GB`;
    document.getElementById('mem-bar').style.width = mem + '%';

    // Uptime
    const up = d.uptime_secs;
    const h  = Math.floor(up / 3600);
    const m  = Math.floor((up % 3600) / 60);
    const s  = up % 60;
    document.getElementById('uptime').textContent =
      `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;

    // Lines
    document.getElementById('lines-processed').textContent =
      d.lines_processed.toLocaleString();

    // Top IPs
    const tbody = document.getElementById('top-ips-body');
    if (d.top_ips.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="color:var(--muted);text-align:center">No data yet</td></tr>';
    } else {
      const banned_set = new Set(d.banned_ips.map(b => b.ip));
      tbody.innerHTML = d.top_ips.map(([ip, cnt], i) => `
        <tr>
          <td style="color:var(--muted)">${i+1}</td>
          <td>${ip}</td>
          <td>${cnt.toLocaleString()}</td>
          <td>${banned_set.has(ip)
            ? '<span class="badge banned">BANNED</span>'
            : '<span class="badge ok">OK</span>'}</td>
        </tr>`).join('');
    }

    // Banned IPs detail
    const bannedBody = document.getElementById('banned-body');
    if (d.banned_ips.length === 0) {
      bannedBody.innerHTML = '<tr><td colspan="5" style="color:var(--muted);text-align:center">No active bans ✓</td></tr>';
    } else {
      bannedBody.innerHTML = d.banned_ips.map(b => `
        <tr>
          <td style="color:var(--red)">${b.ip}</td>
          <td>${b.rate.toFixed(2)} req/s</td>
          <td style="font-size:11px">${b.condition}</td>
          <td>${fmtAge(b.age_secs)}</td>
          <td>${b.ban_count}</td>
        </tr>`).join('');
    }

  } catch(e) {
    console.error('Dashboard refresh error:', e);
  }
}

function fmtAge(s) {
  if (s < 60)   return s + 's';
  if (s < 3600) return Math.floor(s/60) + 'm ' + (s%60) + 's';
  return Math.floor(s/3600) + 'h ' + Math.floor((s%3600)/60) + 'm';
}

refresh();
setInterval(refresh, 3000);
</script>

</body>
</html>
"""


class DashboardServer:
    """
    Thin Flask wrapper. Exposes:
      GET /           — HTML dashboard
      GET /api/metrics — JSON metrics for the JS frontend
    """

    def __init__(self, cfg: dict, monitor, baseline, blocker, unbanner):
        self.cfg      = cfg
        self.monitor  = monitor
        self.baseline = baseline
        self.blocker  = blocker
        self.unbanner = unbanner
        self._start_ts = time.time()

        self._app = Flask(__name__)
        CORS(self._app)
        self._setup_routes()

    def _setup_routes(self):
        app = self._app

        @app.route("/")
        def index():
            return render_template_string(DASHBOARD_HTML)

        @app.route("/api/metrics")
        def metrics():
            return jsonify(self._build_metrics())

        @app.route("/health")
        def health():
            return jsonify({"status": "ok", "uptime": int(time.time() - self._start_ts)})

    def _build_metrics(self) -> dict:
        snap     = self.baseline.get_baseline_snapshot()
        banned   = self.blocker.get_banned_list()
        top_n    = self.cfg["dashboard"]["top_ips_count"]

        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()

        return {
            "global_rate":      round(self.monitor.get_global_rate(), 3),
            "banned_count":     len(banned),
            "banned_ips":       banned,
            "top_ips":          self.monitor.snapshot_top_ips(top_n),
            "lines_processed":  self.monitor.lines_processed,
            "baseline": {
                "mean":   round(snap["mean"],   3),
                "stddev": round(snap["stddev"], 3),
            },
            "system": {
                "cpu_pct":      cpu,
                "mem_pct":      mem.percent,
                "mem_used_mb":  mem.used // (1024 * 1024),
                "mem_total_mb": mem.total // (1024 * 1024),
            },
            "uptime_secs": int(time.time() - self._start_ts),
        }

    def run(self):
        host = self.cfg["server"]["dashboard_host"]
        port = self.cfg["server"]["dashboard_port"]
        log.info("Dashboard starting at http://%s:%d", host, port)
        # Use werkzeug's built-in server with threading
        self._app.run(
            host=host,
            port=port,
            debug=False,
            use_reloader=False,
            threaded=True,
        )

"""Web dashboard API and frontend for Cyber-Volt SOC Bot."""
import html
import json
import logging
import os
import threading
from datetime import datetime

import flask

from services.alert_store import get_alerts, get_history
from services.system import format_bandwidth, format_compliance, format_status, format_top
from watchers import suricata_alerts, suricata_lock

log = logging.getLogger("cyber_volt.web")

app = flask.Flask("cyber_volt_dashboard")
_secret = os.getenv("DASHBOARD_SECRET", "")
_port = int(os.getenv("DASHBOARD_PORT", "8080"))


def _check_auth():
    auth = flask.request.headers.get("Authorization", "")
    if not _secret:
        return True
    return auth == f"Bearer {_secret}"


def _require_auth():
    if not _check_auth():
        flask.abort(401)


# ── API endpoints ──

@app.route("/api/status")
def api_status():
    _require_auth()
    status = format_status()
    return {"status": "ok", "data": status}


@app.route("/api/top")
def api_top():
    _require_auth()
    sort = flask.request.args.get("sort", "cpu")
    return {"status": "ok", "data": format_top(sort)}


@app.route("/api/alerts")
def api_alerts():
    _require_auth()
    with suricata_lock:
        recent = [{"time": a["time"].isoformat() if hasattr(a["time"], "isoformat") else str(a["time"]), "line": a["line"]} for a in reversed(suricata_alerts[-30:])]
    stored = get_alerts(20)
    return {"status": "ok", "suricata": recent, "stored": stored}


@app.route("/api/history")
def api_history():
    _require_auth()
    entries = get_history(30)
    return {"status": "ok", "data": entries}


@app.route("/api/bandwidth")
def api_bandwidth():
    _require_auth()
    return {"status": "ok", "data": format_bandwidth()}


@app.route("/api/compliance")
def api_compliance():
    _require_auth()
    return {"status": "ok", "data": format_compliance()}


@app.route("/api/health")
def api_health():
    return {"status": "ok", "uptime": datetime.now().isoformat()}


# ── Frontend pages ──

_LAYOUT = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cyber-Volt SOC Dashboard</title>
<script src="https://unpkg.com/htmx.org@2.0.4"></script>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }}
  h1 {{ color: #58a6ff; margin-bottom: 20px; }}
  nav {{ margin-bottom: 30px; }}
  nav a {{ color: #58a6ff; text-decoration: none; margin-right: 20px; padding: 6px 14px; border-radius: 6px; }}
  nav a:hover, nav a.active {{ background: #21262d; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
  .card h2 {{ color: #58a6ff; margin-bottom: 12px; font-size: 16px; }}
  pre {{ white-space: pre-wrap; font-size: 13px; line-height: 1.5; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #21262d; }}
  th {{ color: #8b949e; font-weight: 600; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; }}
  .badge-green {{ background: #1b4522; color: #3fb950; }}
  .badge-yellow {{ background: #4d3d00; color: #d29922; }}
  .badge-red {{ background: #5c1517; color: #f85149; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  @media (max-width: 768px) {{ .grid {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<h1>⚡ Cyber-Volt SOC Dashboard</h1>
<nav>
  <a href="/" class="active">Dashboard</a>
  <a href="/alerts">Alerts</a>
  <a href="/history">History</a>
</nav>
<div id="content">{{ CONTENT }}</div>
</body>
</html>"""


@app.route("/")
def index():
    return _LAYOUT.replace("{{ CONTENT }}", """
<div class="grid" hx-get="/partials/dashboard" hx-trigger="load every:10s" hx-swap="innerHTML">
  <div class="card"><h2>⬇ Loading...</h2></div>
</div>
""")


@app.route("/alerts")
def alerts_page():
    return _LAYOUT.replace("{{ CONTENT }}", """
<div hx-get="/partials/alerts" hx-trigger="load every:5s" hx-swap="innerHTML">
  <div class="card"><h2>⬇ Loading...</h2></div>
</div>
""")


@app.route("/history")
def history_page():
    return _LAYOUT.replace("{{ CONTENT }}", """
<div hx-get="/partials/history" hx-trigger="load" hx-swap="innerHTML">
  <div class="card"><h2>⬇ Loading...</h2></div>
</div>
""")


@app.route("/partials/dashboard")
def partial_dashboard():
    status = format_status()
    bw = format_bandwidth()
    top = format_top("cpu")
    return f"""
    <div class="card">
      <h2>🖥 System Status</h2>
      <pre>{html.escape(status)}</pre>
    </div>
    <div class="card">
      <h2>🌐 Bandwidth</h2>
      <pre>{html.escape(bw)}</pre>
    </div>
    <div class="card">
      <h2>🔥 Top Processes (CPU)</h2>
      <pre>{html.escape(top[:2000])}</pre>
    </div>
    """


@app.route("/partials/alerts")
def partial_alerts():
    with suricata_lock:
        items = list(reversed(suricata_alerts[-30:]))
    if not items:
        return '<div class="card"><h2>🚨 Suricata Alerts</h2><p>No alerts yet.</p></div>'
    rows = ""
    for a in items:
        ts = a["time"].strftime("%H:%M:%S") if hasattr(a["time"], "strftime") else str(a["time"])[11:19]
        line = html.escape(a["line"][:120])
        badge = "badge badge-red" if any(k in a["line"].upper() for k in ("MALWARE", "TROJAN", "EXPLOIT", "CNC", "RCE")) else "badge badge-yellow"
        rows += f"<tr><td><span class=\"{badge}\">{ts}</span></td><td><code>{line}</code></td></tr>"
    return f"""
    <div class="card">
      <h2>🚨 Suricata Alerts <span class="badge badge-red">{len(items)}</span></h2>
      <table><thead><tr><th>Time</th><th>Signature</th></tr></thead><tbody>{rows}</tbody></table>
    </div>
    """


@app.route("/partials/history")
def partial_history():
    entries = get_history(30)
    if not entries:
        return '<div class="card"><h2>📋 Command History</h2><p>No commands recorded yet.</p></div>'
    rows = ""
    for e in entries:
        ts = e.get("time", "")[11:19] if e.get("time") else "?"
        user = html.escape(e.get("username", "?")[:15])
        cmd = html.escape(e.get("cmd", "?"))
        args = html.escape(e.get("args", "")[:40])
        rows += f"<tr><td><code>{ts}</code></td><td><strong>{cmd}</strong> {args}</td><td>{user}</td></tr>"
    return f"""
    <div class="card">
      <h2>📋 Command History <span class="badge badge-green">{len(entries)}</span></h2>
      <table><thead><tr><th>Time</th><th>Command</th><th>User</th></tr></thead><tbody>{rows}</tbody></table>
    </div>
    """


def start_dashboard():
    """Start Flask dashboard server in the calling thread."""
    app.run(host="0.0.0.0", port=_port, debug=False, use_reloader=False)

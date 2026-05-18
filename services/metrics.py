"""Prometheus metrics for the SOC bot."""
import threading
from prometheus_client import Counter, Gauge, Histogram, start_http_server

commands_total = Counter("bot_commands_total", "Total commands processed", ["command"])
alerts_total = Counter("bot_alerts_total", "Total Suricata alerts triggered", ["severity"])
errors_total = Counter("bot_errors_total", "Total errors", ["type"])
callback_total = Counter("bot_callbacks_total", "Total callback queries", ["action"])
uptime_gauge = Gauge("bot_uptime_seconds", "Bot uptime in seconds")
cmd_duration = Histogram("bot_command_duration_seconds", "Command processing duration", ["command"])

_started = False
_lock = threading.Lock()


def start_metrics_server(port: int = 9099) -> None:
    global _started
    with _lock:
        if _started:
            return
        start_http_server(port)
        _started = True

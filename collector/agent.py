"""
SENTRIX Collector Agent
-----------------------
Runs locally inside the customer's environment.  Every POLL_INTERVAL seconds
it collects system metrics via psutil and tails local log files, then:

  1. Redacts all sensitive data (emails, IPs, tokens, etc.)
  2. Assembles an approved payload of numeric metrics + redacted events
  3. Sends ONLY that payload to the central SENTRIX server
  4. Logs exactly what left this machine (the "privacy proof" line)

Raw logs NEVER leave this machine.

Usage:
    python -m collector.agent --host-name web-prod-01 --server http://localhost:8000
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

import psutil
import requests

# Add project root to path so sibling imports work when run directly
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from collector.redactor import redact
from collector.log_watcher import LogWatcher


# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

POLL_INTERVAL = 5                      # seconds between collection cycles
DEFAULT_SERVER = 'http://localhost:8000'
DEFAULT_HOST_NAME = 'host-01'

# Default log directory (sample_logs/ in project root)
DEFAULT_LOG_DIR = os.path.join(PROJECT_ROOT, 'sample_logs')


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [COLLECTOR %(name)s] %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger('sentrix.collector')


# ---------------------------------------------------------------------------
# Network speed tracking (needs previous sample to compute rate)
# ---------------------------------------------------------------------------

_prev_net = None
_prev_time = None


# ---------------------------------------------------------------------------
# Metric collection
# ---------------------------------------------------------------------------

def collect_metrics(host_name: str) -> dict:
    """
    Gather system metrics from psutil.
    Returns a flat dict ready for JSON serialisation and POST to the server.
    All values are numeric — no sensitive strings.
    """
    global _prev_net, _prev_time

    now = time.time()

    # CPU — interval=1 means psutil blocks 1 s to measure real usage
    cpu_percent = psutil.cpu_percent(interval=1)

    # Memory
    mem = psutil.virtual_memory()

    # Disk — use the OS-appropriate root path
    disk_path = 'C:\\' if os.name == 'nt' else '/'
    disk = psutil.disk_usage(disk_path)

    # Network throughput (bytes/sec since last sample)
    net = psutil.net_io_counters()
    net_sent_bps = 0.0
    net_recv_bps = 0.0
    if _prev_net is not None and _prev_time is not None:
        dt = now - _prev_time
        if dt > 0:
            net_sent_bps = (net.bytes_sent - _prev_net.bytes_sent) / dt
            net_recv_bps = (net.bytes_recv - _prev_net.bytes_recv) / dt
    _prev_net = net
    _prev_time = now

    # CPU temperature — optional, not available on all platforms
    cpu_temp = None
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            for _sensor_name, entries in temps.items():
                if entries:
                    cpu_temp = entries[0].current
                    break
    except (AttributeError, OSError, RuntimeError):
        pass  # sensors_temperatures() may not exist or may fail on Windows

    return {
        'host_name': host_name,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'cpu_percent': round(cpu_percent, 1),
        'memory_percent': round(mem.percent, 1),
        'disk_percent': round(disk.percent, 1),
        'net_sent_bps': round(net_sent_bps, 1),
        'net_recv_bps': round(net_recv_bps, 1),
        'cpu_temp': round(cpu_temp, 1) if cpu_temp is not None else None,
    }


# ---------------------------------------------------------------------------
# Server communication
# ---------------------------------------------------------------------------

def send_to_server(endpoint: str, payload: dict, server_url: str,
                   api_key: str) -> bool:
    """
    POST a JSON payload to the central server.
    Returns True on success, False on failure (logged but not fatal).
    """
    url = f'{server_url}{endpoint}'
    headers = {
        'Content-Type': 'application/json',
        'X-API-Key': api_key,
    }
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=5)
        resp.raise_for_status()
        return True
    except requests.RequestException as e:
        log.warning('Failed to send to %s: %s', endpoint, e)
        return False


# ---------------------------------------------------------------------------
# Main collection loop
# ---------------------------------------------------------------------------

def run(host_name: str, server_url: str, api_key: str, log_dir: str):
    """
    Main loop: collect → redact → send, forever.
    Ctrl+C to stop.
    """
    # Set up the log file watcher
    log_files = [
        os.path.join(log_dir, 'app.log'),
        os.path.join(log_dir, 'auth.log'),
    ]
    watcher = LogWatcher(log_files)

    log.info('=== SENTRIX Collector Agent Started ===')
    log.info('  Host name:     %s', host_name)
    log.info('  Server:        %s', server_url)
    log.info('  Log files:     %s', ', '.join(log_files))
    log.info('  Poll interval: %d s', POLL_INTERVAL)
    log.info('  Privacy mode:  ON — raw logs never leave this machine')
    log.info('==========================================')

    while True:
        try:
            # --- 1. Collect system metrics (all numeric, no PII) ---
            metrics = collect_metrics(host_name)

            # --- 2. Collect new events from log files ---
            raw_events = watcher.poll()

            # --- 3. Redact sensitive data from event messages ---
            redacted_events = []
            for ev in raw_events:
                redacted_events.append({
                    'host_name': host_name,
                    'timestamp': ev.timestamp,
                    'event_type': ev.event_type,
                    'message': redact(ev.message),    # ← REDACTED here
                    'source_file': ev.source_file,
                    'severity': ev.severity,
                })

            # --- 4. Privacy proof: log exactly what leaves this machine ---
            log.info('──── WHAT LEFT THIS MACHINE (metrics) ────')
            log.info('%s', json.dumps(metrics, indent=2))
            if redacted_events:
                log.info('──── WHAT LEFT THIS MACHINE (%d events) ────',
                         len(redacted_events))
                for ev in redacted_events:
                    log.info('  %s', json.dumps(ev))
            else:
                log.info('──── No new events this cycle ────')

            # --- 5. Send approved data to central server ---
            send_to_server('/ingest/metrics', metrics, server_url, api_key)
            if redacted_events:
                send_to_server(
                    '/ingest/events',
                    {'events': redacted_events},
                    server_url,
                    api_key,
                )

        except KeyboardInterrupt:
            log.info('Collector stopped by user.')
            break
        except Exception as exc:
            log.error('Error in collection cycle: %s', exc)

        time.sleep(POLL_INTERVAL)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='SENTRIX Collector Agent — runs locally, sends only '
                    'redacted operational data to the central server.'
    )
    parser.add_argument(
        '--host-name', default=DEFAULT_HOST_NAME,
        help='Identifier for this host (default: %(default)s)',
    )
    parser.add_argument(
        '--server', default=DEFAULT_SERVER,
        help='Central SENTRIX server URL (default: %(default)s)',
    )
    parser.add_argument(
        '--log-dir', default=DEFAULT_LOG_DIR,
        help='Directory containing log files to watch (default: %(default)s)',
    )
    args = parser.parse_args()
    api_key = os.getenv('SENTRIX_API_KEY', '').strip()
    if not api_key:
        parser.error('SENTRIX_API_KEY environment variable must be set')
    run(args.host_name, args.server, api_key, args.log_dir)


if __name__ == '__main__':
    main()

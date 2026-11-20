"""
SENTRIX Incident Simulator
--------------------------
Simulates realistic failure scenarios to demonstrate AI correlation
and root-cause identification during live demos.

Scenarios:
  1. overheating:       Server temperature spike (89°C) and CPU saturation (95%)
                        causing downstream slow website response warnings.
  2. brute-force:       Multiple rapid failed login attempts for admin accounts
                        from a suspicious source IP (redacted locally before sending).
  3. deployment-spike:  Surge in NullReferenceError and database timeouts immediately
                        following a release on the application server.

Usage:
  python -m simulator.incidents overheating --server http://localhost:8000
  python -m simulator.incidents brute-force --server http://localhost:8000
  python -m simulator.incidents deployment-spike --server http://localhost:8000
  python -m simulator.incidents --all
"""

import argparse
import os
import sys
import time
from datetime import datetime, timezone

import requests

from collector.redactor import redact

DEFAULT_SERVER = "http://localhost:8000"


def send_metric(server: str, key: str, host: str, cpu: float, mem: float, temp: float = None, temp_simulated: bool = False):
    url = f"{server}/ingest/metrics"
    headers = {"Content-Type": "application/json", "X-API-Key": key}
    payload = {
        "host_name": host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": cpu,
        "memory_percent": mem,
        "disk_percent": 45.0,
        "net_sent_bps": 204800.0,
        "net_recv_bps": 512000.0,
        "cpu_temp": temp,
        "temp_simulated": temp_simulated
    }
    resp = requests.post(url, json=payload, headers=headers, timeout=5)
    resp.raise_for_status()


def send_events(server: str, key: str, raw_events: list):
    url = f"{server}/ingest/events"
    headers = {"Content-Type": "application/json", "X-API-Key": key}

    # CRITICAL: Redact raw events before transmitting to server (matches agent privacy layer)
    redacted_items = []
    for ev in raw_events:
        redacted_items.append({
            "host_name": ev["host_name"],
            "timestamp": ev.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "event_type": ev["event_type"],
            "message": redact(ev["raw_message"]),  # Strip PII locally
            "source_file": ev.get("source_file", "app.log"),
            "severity": ev.get("severity", "warning")
        })

    resp = requests.post(url, json={"events": redacted_items}, headers=headers, timeout=5)
    resp.raise_for_status()


# ---------------------------------------------------------------------------
# Scenario 1: Overheating Server Causing Slow Website
# ---------------------------------------------------------------------------
def simulate_overheating(server: str, key: str):
    print("\n[SCENARIO 1] Simulating Overheating Server & Slow Website...")
    host = "web-prod-01"

    print("  -> Injecting CPU spike & thermal warning on web-prod-01 (CPU 96%, Temp 89.4°C [SIMULATED PROTOTYPE DATA])...")
    send_metric(server, key, host, cpu=96.2, mem=84.5, temp=89.4, temp_simulated=True)
    time.sleep(1)

    print("  -> Emitting downstream slow response events from web-server...")
    raw_events = [
        {
            "host_name": host,
            "event_type": "slow_response",
            "raw_message": "Slow response: GET /dashboard took 4250ms (threshold: 1000ms)",
            "source_file": "app.log",
            "severity": "warning"
        },
        {
            "host_name": host,
            "event_type": "slow_response",
            "raw_message": "Slow response: POST /api/checkout took 5120ms (threshold: 1000ms)",
            "source_file": "app.log",
            "severity": "warning"
        }
    ]
    send_events(server, key, raw_events)
    print("  ✓ Scenario 1 injected. SENTRIX will correlate temperature spike with latency increase.")


# ---------------------------------------------------------------------------
# Scenario 2: Repeated Failed Logins (Brute-Force Attack)
# ---------------------------------------------------------------------------
def simulate_bruteforce(server: str, key: str):
    print("\n[SCENARIO 2] Simulating Repeated Failed Logins...")
    host = "auth-prod-01"

    raw_events = [
        {
            "host_name": host,
            "event_type": "failed_login",
            "raw_message": "Failed login attempt for user=admin@corp.com from 192.168.1.105 - invalid password",
            "source_file": "auth.log",
            "severity": "warning"
        },
        {
            "host_name": host,
            "event_type": "failed_login",
            "raw_message": "Failed login attempt for user=root from 192.168.1.105 - password=P@ssw0rd123 rejected",
            "source_file": "auth.log",
            "severity": "warning"
        },
        {
            "host_name": host,
            "event_type": "failed_login",
            "raw_message": "Failed login attempt for user=admin from 192.168.1.105 - invalid password",
            "source_file": "auth.log",
            "severity": "warning"
        },
        {
            "host_name": host,
            "event_type": "failed_login",
            "raw_message": "Failed authentication for user=operator@corp.net from 192.168.1.105 - account locked",
            "source_file": "auth.log",
            "severity": "critical"
        }
    ]

    print("  -> Emitting 4 failed login attempts with sensitive credentials & IP...")
    print("  -> Notice: Local agent strips passwords, emails, and IPs before egress!")
    send_events(server, key, raw_events)
    print("  ✓ Scenario 2 injected. SENTRIX will flag automated credential attack.")


# ---------------------------------------------------------------------------
# Scenario 3: Application Error Surge After Deployment
# ---------------------------------------------------------------------------
def simulate_deployment_spike(server: str, key: str):
    print("\n[SCENARIO 3] Simulating Error Spike After Release...")
    host = "web-prod-01"

    raw_events = [
        {
            "host_name": host,
            "event_type": "error",
            "raw_message": "Unhandled exception in /api/v2/orders: NullReferenceError at OrderController.cs:142",
            "source_file": "app.log",
            "severity": "critical"
        },
        {
            "host_name": host,
            "event_type": "error",
            "raw_message": "Database connection pool exhausted after v2.4.1 release - timeout connecting to db-prod-01",
            "source_file": "app.log",
            "severity": "critical"
        },
        {
            "host_name": host,
            "event_type": "error",
            "raw_message": "Payment processing failed for user=customer@buyer.com - gateway response code 500",
            "source_file": "app.log",
            "severity": "warning"
        }
    ]

    print("  -> Emitting 3 application exceptions following v2.4.1 release...")
    send_events(server, key, raw_events)
    print("  ✓ Scenario 3 injected. SENTRIX will group errors and propose rollback action.")


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="SENTRIX Demo Incident Simulator")
    parser.add_argument(
        "scenario",
        nargs="?",
        choices=["overheating", "brute-force", "deployment-spike", "all"],
        default="all",
        help="Which scenario to trigger (default: all)"
    )
    parser.add_argument("--server", default=DEFAULT_SERVER, help="SENTRIX server URL")

    args = parser.parse_args()
    api_key = os.getenv("SENTRIX_API_KEY", "").strip()
    if not api_key:
        parser.error("SENTRIX_API_KEY environment variable must be set")

    try:
        # Check server reachability
        requests.get(f"{args.server}/api/health", timeout=3)
    except Exception as e:
        print(f"Error: Cannot reach SENTRIX server at {args.server}. Make sure the server is running!")
        sys.exit(1)

    if args.scenario == "overheating" or args.scenario == "all":
        simulate_overheating(args.server, api_key)
        if args.scenario == "all":
            time.sleep(2)

    if args.scenario == "brute-force" or args.scenario == "all":
        simulate_bruteforce(args.server, api_key)
        if args.scenario == "all":
            time.sleep(2)

    if args.scenario == "deployment-spike" or args.scenario == "all":
        simulate_deployment_spike(args.server, api_key)

    print("\n✓ Simulation complete! Check the live dashboard at http://localhost:8000")


if __name__ == "__main__":
    main()

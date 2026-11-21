"""
SENTRIX Demo Runner
-------------------
One command to run the full end-to-end SENTRIX MVP demonstration:
  1. Starts the central FastAPI server on http://localhost:8000
  2. Resets the database and stale hosts if --reset is passed (or on first run)
  3. Launches Collector Agent 1 (host: web-prod-01)
  4. Launches Collector Agent 2 (host: db-prod-01)
  5. Injects the demo incident scenarios via simulator/incidents.py
  6. Keeps everything running until Ctrl+C, then terminates child processes cleanly.

Usage:
  python run_demo.py
  python run_demo.py --reset
"""

import argparse
import os
import secrets
import signal
import subprocess
import sys
import time

try:
    import requests
except ImportError:
    print("Error: 'requests' package not found. Run: pip install -r requirements.txt")
    sys.exit(1)

SERVER_PORT = 8000
SERVER_URL = f"http://localhost:{SERVER_PORT}"
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

processes = []


def cleanup():
    print("\nStopping SENTRIX demo processes...")
    for p in processes:
        try:
            p.terminate()
            p.wait(timeout=2)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    print("All processes stopped. Thank you for testing SENTRIX!")


def wait_for_server(url: str, timeout: int = 15):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{url}/api/health", timeout=1)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def main():
    parser = argparse.ArgumentParser(description="SENTRIX Demo Runner")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Wipe previous database and stale hosts (e.g. test-web-01) before starting"
    )
    args = parser.parse_args()

    print("=" * 65)
    print("  SENTRIX — AI Observability & Security Platform MVP")
    print("  Prototype for CICADA 2026")
    print("=" * 65)

    demo_env = os.environ.copy()
    demo_env["SENTRIX_API_KEY"] = (
        demo_env.get("SENTRIX_API_KEY", "").strip() or secrets.token_urlsafe(32)
    )

    # 1. Start Server
    print("\n[1/4] Starting SENTRIX Central Server on port 8000...")
    server_cmd = [
        sys.executable, "-m", "uvicorn", "server.main:app",
        "--host", "0.0.0.0",
        "--port", str(SERVER_PORT),
        "--log-level", "warning"
    ]
    p_server = subprocess.Popen(server_cmd, cwd=PROJECT_ROOT, env=demo_env)
    processes.append(p_server)

    if not wait_for_server(SERVER_URL):
        print("Error: Server failed to start within timeout.")
        cleanup()
        sys.exit(1)
    print(f"  ✓ Server is healthy at {SERVER_URL}")

    # Handle --reset flag
    if args.reset:
        print("\n  -> Resetting database and clearing stale hosts (--reset passed)...")
        try:
            headers = {"X-API-Key": demo_env["SENTRIX_API_KEY"]}
            r = requests.post(f"{SERVER_URL}/api/reset", headers=headers, timeout=3)
            if r.status_code == 200:
                print("  ✓ Database cleared. Stale hosts removed.")
            else:
                print(f"  Warning: Reset call returned status {r.status_code}: {r.text}")
        except Exception as e:
            print(f"  Warning: Reset call failed: {e}")

    # 2. Start Agent 1 (web-prod-01)
    print("\n[2/4] Starting Collector Agent #1 (web-prod-01)...")
    p_agent1 = subprocess.Popen([
        sys.executable, "-m", "collector.agent",
        "--host-name", "web-prod-01",
        "--server", SERVER_URL
    ], cwd=PROJECT_ROOT, env=demo_env)
    processes.append(p_agent1)

    # 3. Start Agent 2 (db-prod-01)
    print("\n[3/4] Starting Collector Agent #2 (db-prod-01)...")
    p_agent2 = subprocess.Popen([
        sys.executable, "-m", "collector.agent",
        "--host-name", "db-prod-01",
        "--server", SERVER_URL
    ], cwd=PROJECT_ROOT, env=demo_env)
    processes.append(p_agent2)

    # Give agents 2 seconds to send initial telemetry
    time.sleep(2)

    # 4. Run Incident Simulator
    print("\n[4/4] Injecting realistic demo incidents...")
    subprocess.run([
        sys.executable, "-m", "simulator.incidents", "all",
        "--server", SERVER_URL
    ], cwd=PROJECT_ROOT, env=demo_env)

    print("\n" + "=" * 65)
    print("  SENTRIX DEMO IS LIVE AND RUNNING!")
    print(f"  Open Dashboard in your browser:  {SERVER_URL}")
    print("=" * 65)
    print("\nDemo features active:")
    print("  • Real-time node metrics & canvas charts (web-prod-01, db-prod-01)")
    print("  • AI-correlated incidents with root cause & suggested actions")
    print("  • Local Privacy Guarantee proof panel showing redacted payloads")
    print("  • Incident detail modals with correlated timelines")
    print("\nTo trigger individual scenarios again in another terminal:")
    print("  python -m simulator.incidents overheating")
    print("  python -m simulator.incidents brute-force")
    print("  python -m simulator.incidents deployment-spike")
    print("\nPress Ctrl+C to shut down the demo...")

    try:
        while True:
            time.sleep(1)
            if p_server.poll() is not None:
                print("\nServer process terminated.")
                break
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()


if __name__ == "__main__":
    main()

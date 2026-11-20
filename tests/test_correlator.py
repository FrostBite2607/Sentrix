"""
SENTRIX Correlator & Anomaly Detection Unit Tests
-------------------------------------------------
Verifies:
  1. Anomaly detection on CPU thresholds and spikes (including simulated temp).
  2. Failed login correlation into brute-force incident.
  3. Overheating and slow response cross-correlation.
  4. Root cause explainer outputs.
  5. Merging duplicate incidents for same type & overlapping hosts.
  6. Strict count consistency across title, likely cause, and system stats.
"""

import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import db
from server.correlator import process_metric_telemetry, correlate_and_evaluate_incidents, _METRIC_HISTORY
from server.explainer import explain_incident


@pytest.fixture(autouse=True)
def setup_isolated_db(monkeypatch):
    """Create a temporary SQLite database for each test."""
    temp_dir = tempfile.mkdtemp()
    temp_db = os.path.join(temp_dir, "test_sentrix.db")
    db.init_db(temp_db)
    monkeypatch.setattr(db, "DB_FILE", temp_db)
    _METRIC_HISTORY.clear()
    yield
    try:
        if os.path.exists(temp_db):
            os.remove(temp_db)
    except OSError:
        pass


def test_cpu_anomaly_detection():
    """Detects CPU threshold breach above 85%."""
    metric = {
        "host_name": "test-host-01",
        "timestamp": "2026-11-20T14:00:00Z",
        "cpu_percent": 91.5,
        "memory_percent": 45.0,
        "disk_percent": 30.0,
        "net_sent_bps": 1000.0,
        "net_recv_bps": 2000.0,
        "cpu_temp": 82.0
    }
    event = process_metric_telemetry(metric)
    assert event is not None
    assert event["event_type"] == "metric_anomaly"
    assert "CPU critical threshold" in event["message"]


def test_simulated_temperature_anomaly():
    """Verifies simulated temperature flag is acknowledged in anomaly warning."""
    metric = {
        "host_name": "web-prod-01",
        "timestamp": "2026-11-20T14:00:00Z",
        "cpu_percent": 95.0,
        "memory_percent": 60.0,
        "disk_percent": 40.0,
        "cpu_temp": 89.4,
        "temp_simulated": True
    }
    event = process_metric_telemetry(metric)
    assert event is not None
    assert "simulated prototype data" in event["message"]


def test_failed_login_correlation():
    """Three failed logins within time window are grouped into an incident."""
    events = [
        {
            "host_name": "auth-srv-01",
            "timestamp": f"2026-11-20T14:10:0{i}Z",
            "event_type": "failed_login",
            "message": f"Failed login attempt for user=[USERNAME] from [IP] #{i}",
            "source_file": "auth.log",
            "severity": "warning"
        }
        for i in range(4)
    ]
    db.insert_events(events)

    inc_ids = correlate_and_evaluate_incidents()
    assert len(inc_ids) >= 1

    incidents = db.get_incidents(status="active")
    assert len(incidents) >= 1
    inc = incidents[0]
    assert "Authentication Failures" in inc["title"]
    assert "auth-srv-01" in inc["affected_hosts"]
    assert "brute-force" in inc["likely_cause"].lower() or "credential" in inc["likely_cause"].lower()
    assert len(inc["timeline"]) == 4


def test_overheating_slow_response_correlation():
    """Correlates high CPU/thermal anomaly with slow response times."""
    anomaly_event = {
        "host_name": "web-srv-01",
        "timestamp": "2026-11-20T14:20:00Z",
        "event_type": "metric_anomaly",
        "message": "CPU thermal overheating warning (simulated prototype data): 89.4°C; CPU critical threshold reached: 95.0%",
        "source_file": "collector.psutil",
        "severity": "critical"
    }
    slow_event = {
        "host_name": "web-srv-01",
        "timestamp": "2026-11-20T14:20:05Z",
        "event_type": "slow_response",
        "message": "Slow response: GET /checkout took 4500ms (threshold: 1000ms)",
        "source_file": "app.log",
        "severity": "warning"
    }
    db.insert_events([anomaly_event, slow_event])

    inc_ids = correlate_and_evaluate_incidents()
    assert len(inc_ids) >= 1

    incidents = db.get_incidents(status="active")
    overheating_inc = next((i for i in incidents if "Overheating" in i["title"]), None)
    assert overheating_inc is not None
    assert overheating_inc["severity"] == "critical"
    assert "throttling" in overheating_inc["likely_cause"].lower() or "thermal" in overheating_inc["likely_cause"].lower()
    assert "cooling" in overheating_inc["suggested_action"].lower() or "processes" in overheating_inc["suggested_action"].lower()


def test_merge_duplicate_incidents_overlapping_hosts():
    """
    Subsequent related events on overlapping hosts must be merged into
    the existing active incident, growing the timeline and count,
    instead of creating duplicate incident rows.
    """
    # 1. Initial 3 failed logins on auth-01
    batch_1 = [
        {
            "host_name": "auth-01",
            "timestamp": f"2026-11-20T14:30:0{i}Z",
            "event_type": "failed_login",
            "message": f"Auth failure attempt {i} from [IP]",
            "source_file": "auth.log",
            "severity": "warning"
        }
        for i in range(3)
    ]
    db.insert_events(batch_1)
    correlate_and_evaluate_incidents()

    active_incidents = db.get_incidents(status="active")
    assert len(active_incidents) == 1
    assert "(3 attempts)" in active_incidents[0]["title"]
    assert len(active_incidents[0]["timeline"]) == 3

    # 2. Ingest 2 more failed logins on same host auth-01
    batch_2 = [
        {
            "host_name": "auth-01",
            "timestamp": f"2026-11-20T14:30:1{i}Z",
            "event_type": "failed_login",
            "message": f"Auth failure attempt {i+3} from [IP]",
            "source_file": "auth.log",
            "severity": "warning"
        }
        for i in range(2)
    ]
    db.insert_events(batch_2)
    correlate_and_evaluate_incidents()

    # MUST NOT create a second incident: count of active incidents remains exactly 1!
    active_incidents_after = db.get_incidents(status="active")
    assert len(active_incidents_after) == 1, "Expected duplicate incident to be merged, not duplicated"

    merged_inc = active_incidents_after[0]
    assert "(5 attempts)" in merged_inc["title"]
    assert "(5 failed attempts)" in merged_inc["likely_cause"]
    assert len(merged_inc["timeline"]) == 5


def test_incident_counts_consistency():
    """
    Verifies that the incident title, the Likely Cause text, and the system
    stats / dashboard tiles all use the exact same computed count.
    """
    events = [
        {
            "host_name": "auth-prod-01",
            "timestamp": f"2026-11-20T14:40:0{i}Z",
            "event_type": "failed_login",
            "message": f"Login failure #{i} for user=[USERNAME] from [IP]",
            "source_file": "auth.log",
            "severity": "warning"
        }
        for i in range(4)
    ]
    db.insert_events(events)
    correlate_and_evaluate_incidents()

    # Query system stats (which dashboard tiles poll)
    stats = db.get_system_stats()
    expected_count = stats["failed_logins"]
    assert expected_count == 4

    # Query incident
    incidents = db.get_incidents(status="active")
    assert len(incidents) == 1
    inc = incidents[0]

    # Verify title has the exact same count
    assert f"({expected_count} attempts)" in inc["title"]

    # Verify likely cause text has the exact same count
    assert f"({expected_count} failed attempts)" in inc["likely_cause"]

    # Verify timeline length matches
    assert len(inc["timeline"]) == expected_count


def test_explainer_rules():
    """Explainer yields actionable root cause and remediation."""
    cause, action = explain_incident(
        title="Application Error Surge (5 exceptions detected)",
        severity="critical",
        affected_hosts=["api-host-01"],
        timeline=[
            {"timestamp": "2026-11-20T14:30:00Z", "event_type": "error", "message": "Unhandled NullReferenceError in /api/v2/orders"}
        ]
    )
    assert len(cause) > 20
    assert len(action) > 20
    assert "rollback" in action.lower() or "traces" in action.lower()

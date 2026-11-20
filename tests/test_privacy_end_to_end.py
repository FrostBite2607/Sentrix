"""
SENTRIX End-to-End Privacy Verification Tests
---------------------------------------------
Critical privacy verification:
  1. Verifies that raw logs are redacted locally before ingestion.
  2. Asserts that NO unredacted email, IP address, password, or token
     ever reaches SQLite or API responses.
  3. Verifies API key authentication enforcement.
  4. Verifies the privacy-proof endpoint includes both metrics and redacted event streams.
  5. Verifies the reset endpoint clears all stale nodes and database records.
"""

import os
import sys
import tempfile
import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector.redactor import redact, contains_sensitive
from server import db
from server import main
from server.main import MetricPayload, EventsPayload, EventItem

TEST_API_KEY = "test-only-sentrix-api-key"


@pytest.fixture(autouse=True)
def setup_isolated_env(monkeypatch):
    """Isolate SQLite database for every test run."""
    monkeypatch.setattr(main, "API_KEY", TEST_API_KEY)
    temp_dir = tempfile.mkdtemp()
    temp_db = os.path.join(temp_dir, "test_privacy.db")
    db.init_db(temp_db)
    monkeypatch.setattr(db, "DB_FILE", temp_db)
    main._PRIVACY_PROOF_PAYLOADS.clear()
    yield
    try:
        if os.path.exists(temp_db):
            os.remove(temp_db)
    except OSError:
        pass


def test_end_to_end_privacy_no_raw_pii_reaches_server():
    """
    Simulates local collector reading raw production logs with sensitive data,
    redacting them locally, sending them to the central server, and asserting
    that ZERO raw emails, IPs, or passwords exist in SQLite or the API.
    """
    raw_lines = [
        "2026-11-20 14:00:01 ERROR [auth-service] Failed login for user=admin@corporate-security.com from 192.168.1.199 - password=SecretVault99!",
        "2026-11-20 14:00:05 ERROR [payment-gateway] Transaction failed for card 4111222233334444 user=finance-exec@fintech.io via 10.200.1.45",
        "2026-11-20 14:00:10 ERROR [api-proxy] Access denied with api_key=AKIAIOSFODNN7EXAMPLE for user=operator from 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "2026-11-20 14:00:15 ERROR [ingress] Invalid Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ]

    # 1. Local collector redacts each message before transmission
    redacted_event_items = []
    for line in raw_lines:
        redacted_event_items.append(
            EventItem(
                host_name="node-prod-alpha",
                timestamp="2026-11-20T14:00:00Z",
                event_type="failed_login" if "login" in line else "error",
                message=redact(line),
                source_file="app.log",
                severity="critical" if "failed" in line else "warning"
            )
        )

    # Verify collector sanitization locally
    for ev in redacted_event_items:
        msg = ev.message
        assert "@corporate-security.com" not in msg
        assert "@fintech.io" not in msg
        assert "192.168.1.199" not in msg
        assert "10.200.1.45" not in msg
        assert "SecretVault99!" not in msg
        assert "AKIAIOSFODNN7EXAMPLE" not in msg
        assert "4111222233334444" not in msg

    # 2. Ingest into central server
    payload = EventsPayload(events=redacted_event_items)
    res = main.ingest_events(payload, _auth=TEST_API_KEY)
    assert res["status"] == "ok"
    assert res["count"] == len(raw_lines)

    # 3. Direct SQLite Database Inspection
    events_in_db = db.get_recent_events(limit=50)
    assert len(events_in_db) == len(raw_lines)

    for row in events_in_db:
        text = row["message"]
        # STRICT PRIVACY ASSERTIONS: Fail test if ANY raw PII leaked into DB
        assert "@corporate-security.com" not in text, f"Email leaked into DB: {text}"
        assert "@fintech.io" not in text, f"Email leaked into DB: {text}"
        assert "192.168.1.199" not in text, f"IPv4 leaked into DB: {text}"
        assert "10.200.1.45" not in text, f"IPv4 leaked into DB: {text}"
        assert "SecretVault99!" not in text, f"Password leaked into DB: {text}"
        assert "AKIAIOSFODNN7EXAMPLE" not in text, f"API key leaked into DB: {text}"
        assert "4111222233334444" not in text, f"Card number leaked into DB: {text}"

    # 4. API Endpoint Inspection (get_events)
    api_events = main.get_events()
    for ev in api_events["events"]:
        msg = ev["message"]
        assert "@corporate-security.com" not in msg
        assert "192.168.1.199" not in msg
        assert "SecretVault99!" not in msg

    # 5. Privacy Proof Endpoint Inspection (get_privacy_proof)
    proof = main.get_privacy_proof()
    proof_str = str(proof["recent_payloads"])
    assert "@corporate-security.com" not in proof_str
    assert "192.168.1.199" not in proof_str
    assert "[EMAIL]" in proof_str
    assert "[IP]" in proof_str
    assert "[PASSWORD]" in proof_str


def test_server_rejects_unauthorized_collector():
    """Server raises 401 when invalid or missing API key is provided."""
    # Missing key
    with pytest.raises(HTTPException) as exc1:
        main.verify_api_key(None)
    assert exc1.value.status_code == 401

    # Wrong key
    with pytest.raises(HTTPException) as exc2:
        main.verify_api_key("wrong-secret-key-123")
    assert exc2.value.status_code == 401

    # Valid key
    assert main.verify_api_key(TEST_API_KEY) == TEST_API_KEY


def test_server_rejects_requests_when_api_key_is_unconfigured(monkeypatch):
    """Ingestion remains closed when no environment key is configured."""
    monkeypatch.setattr(main, "API_KEY", "")
    with pytest.raises(HTTPException) as exc:
        main.verify_api_key(TEST_API_KEY)
    assert exc.value.status_code == 401


def test_privacy_proof_endpoint_contains_both_metrics_and_events():
    """Privacy proof stream stores both metrics and events for inspection."""
    # 1. Ingest metric
    m = MetricPayload(
        host_name="web-node-01",
        cpu_percent=74.0,
        memory_percent=62.0,
        disk_percent=41.0,
        cpu_temp=82.5,
        temp_simulated=True
    )
    main.ingest_metrics(m, _auth=TEST_API_KEY)

    # 2. Ingest redacted event
    ev = EventItem(
        host_name="web-node-01",
        event_type="failed_login",
        message="Failed login for user=[USERNAME] from [IP]",
        source_file="auth.log",
        severity="warning"
    )
    main.ingest_events(EventsPayload(events=[ev]), _auth=TEST_API_KEY)

    proof = main.get_privacy_proof()
    payloads = proof.get("recent_payloads", [])

    types = [p.get("type") for p in payloads]
    assert "metrics" in types, "Metrics payload must be present in privacy proof"
    assert "event" in types, "Event payload must be present in privacy proof"


def test_reset_endpoint_clears_database_and_stale_hosts():
    """POST /api/reset wipes all hosts, metrics, events, and incidents."""
    # Populate with stale host and data
    m = MetricPayload(
        host_name="stale-host-test",
        cpu_percent=99.0,
        memory_percent=99.0,
        disk_percent=99.0
    )
    main.ingest_metrics(m, _auth=TEST_API_KEY)

    # Confirm host exists
    hosts_before = main.get_hosts()["hosts"]
    assert any(h["host_name"] == "stale-host-test" for h in hosts_before)

    # Call reset
    reset_res = main.reset_system()
    assert reset_res["status"] == "ok"

    # Verify all state is empty
    hosts_after = main.get_hosts()["hosts"]
    assert len(hosts_after) == 0

    stats_after = main.get_stats()
    assert stats_after["hosts_online"] == 0
    assert stats_after["active_incidents"] == 0
    assert stats_after["failed_logins"] == 0

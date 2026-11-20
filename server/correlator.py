"""
SENTRIX Event & Metric Correlator
---------------------------------
Analyzes incoming telemetry streams:
  1. Detects metric anomalies (CPU/Memory thresholds + rolling z-score).
  2. Aggregates related events occurring within temporal windows (e.g. 2 minutes).
  3. Detects security incidents (brute-force failed logins).
  4. Cross-correlates causes & effects (e.g. CPU spike on host A causing slow responses).
  5. Generates root-cause explanations using explainer.py.
  6. Merges duplicate active incidents with overlapping hosts into growing timelines.
"""

import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from server import db
from server.explainer import explain_incident

log = logging.getLogger("sentrix.correlator")

# In-memory rolling metric buffer for statistical anomaly detection
# host_name -> {"cpu": [...], "memory": [...], "temp": [...]}
_METRIC_HISTORY: Dict[str, Dict[str, List[float]]] = {}
HISTORY_WINDOW = 20


def process_metric_telemetry(metric_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Check single metric point for threshold breach or statistical anomaly.
    Returns anomaly event dict if triggered, otherwise None.
    Supports real or clearly flagged simulated temperatures.
    """
    host = metric_data.get("host_name", "unknown")
    cpu = float(metric_data.get("cpu_percent", 0.0))
    mem = float(metric_data.get("memory_percent", 0.0))
    temp = metric_data.get("cpu_temp")
    temp_val = float(temp) if temp is not None else None
    temp_simulated = bool(metric_data.get("temp_simulated"))

    if host not in _METRIC_HISTORY:
        _METRIC_HISTORY[host] = {"cpu": [], "memory": [], "temp": []}

    hist = _METRIC_HISTORY[host]
    hist["cpu"].append(cpu)
    if len(hist["cpu"]) > HISTORY_WINDOW:
        hist["cpu"].pop(0)

    hist["memory"].append(mem)
    if len(hist["memory"]) > HISTORY_WINDOW:
        hist["memory"].pop(0)

    if temp_val is not None:
        hist["temp"].append(temp_val)
        if len(hist["temp"]) > HISTORY_WINDOW:
            hist["temp"].pop(0)

    # Anomaly checks
    anomalies = []

    # 1. CPU Threshold or sudden spike
    if cpu >= 85.0:
        anomalies.append(f"CPU critical threshold reached: {cpu:.1f}%")
    elif len(hist["cpu"]) >= 5:
        mean_cpu = sum(hist["cpu"][:-1]) / (len(hist["cpu"]) - 1)
        variance = sum((x - mean_cpu) ** 2 for x in hist["cpu"][:-1]) / max(1, len(hist["cpu"]) - 2)
        std_cpu = math.sqrt(variance)
        if std_cpu > 3.0 and (cpu - mean_cpu) > 2.5 * std_cpu and cpu > 65.0:
            anomalies.append(f"CPU sudden spike detected: {cpu:.1f}% (baseline: {mean_cpu:.1f}%)")

    # 2. Temperature check (supports simulated temperature flag)
    if temp_val is not None and temp_val >= 78.0:
        sim_note = " (simulated prototype data)" if temp_simulated else ""
        anomalies.append(f"CPU thermal overheating warning{sim_note}: {temp_val:.1f}°C")

    # 3. Memory saturation
    if mem >= 92.0:
        anomalies.append(f"Memory exhaustion risk: {mem:.1f}%")

    if anomalies:
        anomaly_msg = "; ".join(anomalies)
        ts = metric_data.get("timestamp", datetime.now(timezone.utc).isoformat())
        severity = "critical" if (cpu >= 90.0 or (temp_val and temp_val >= 85.0)) else "warning"

        event = {
            "host_name": host,
            "timestamp": ts,
            "event_type": "metric_anomaly",
            "message": anomaly_msg,
            "source_file": "collector.psutil",
            "severity": severity
        }
        # Save event to DB and correlate
        db.insert_events([event])
        correlate_and_evaluate_incidents()
        return event

    return None


def correlate_and_evaluate_incidents() -> List[int]:
    """
    Scans recent events from all hosts within the last 5 minutes,
    clusters them into distinct incidents, merges duplicates with overlapping hosts,
    and ensures all count representations remain strictly consistent.
    """
    events = db.get_recent_events(limit=50)
    if not events:
        return []

    created_incident_ids = []

    # Group 1: Failed Logins / Security cluster (brute_force)
    failed_logins = [e for e in events if e.get("event_type") == "failed_login"]
    if len(failed_logins) >= 3:
        hosts = sorted(list(set(e["host_name"] for e in failed_logins)))
        count = len(failed_logins)
        title = f"Repeated Authentication Failures ({count} attempts)"
        severity = "critical" if count >= 5 else "warning"
        timeline = [
            {"timestamp": e["timestamp"], "host": e["host_name"], "event_type": e["event_type"], "message": e["message"]}
            for e in failed_logins
        ]
        cause, action = explain_incident(title, severity, hosts, timeline)
        inc_id = db.create_or_update_incident(
            incident_type="brute_force",
            title=title,
            severity=severity,
            affected_hosts=hosts,
            timeline=timeline,
            likely_cause=cause,
            suggested_action=action
        )
        created_incident_ids.append(inc_id)

    # Group 2: Overheating & Slow Response Correlation (overheating)
    anomalies = [e for e in events if e.get("event_type") == "metric_anomaly" and ("cpu" in e["message"].lower() or "overheating" in e["message"].lower())]
    slow_resp = [e for e in events if e.get("event_type") == "slow_response"]
    if anomalies and slow_resp:
        all_related = anomalies + slow_resp
        hosts = sorted(list(set(e["host_name"] for e in all_related)))
        title = "Server Overheating Correlated with High Website Latency"
        severity = "critical"
        timeline = [
            {"timestamp": e["timestamp"], "host": e["host_name"], "event_type": e["event_type"], "message": e["message"]}
            for e in all_related
        ]
        cause, action = explain_incident(title, severity, hosts, timeline)
        inc_id = db.create_or_update_incident(
            incident_type="overheating",
            title=title,
            severity=severity,
            affected_hosts=hosts,
            timeline=timeline,
            likely_cause=cause,
            suggested_action=action
        )
        created_incident_ids.append(inc_id)

    # Group 3: Application Error Spike (error_spike)
    app_errors = [e for e in events if e.get("event_type") == "error"]
    if len(app_errors) >= 3:
        hosts = sorted(list(set(e["host_name"] for e in app_errors)))
        count = len(app_errors)
        title = f"Application Error Surge ({count} exceptions detected)"
        severity = "critical" if (count >= 5 or any(e.get("severity") == "critical" for e in app_errors)) else "warning"
        timeline = [
            {"timestamp": e["timestamp"], "host": e["host_name"], "event_type": e["event_type"], "message": e["message"]}
            for e in app_errors
        ]
        cause, action = explain_incident(title, severity, hosts, timeline)
        inc_id = db.create_or_update_incident(
            incident_type="error_spike",
            title=title,
            severity=severity,
            affected_hosts=hosts,
            timeline=timeline,
            likely_cause=cause,
            suggested_action=action
        )
        created_incident_ids.append(inc_id)

    return created_incident_ids

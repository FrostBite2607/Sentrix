"""
SENTRIX Database Layer
----------------------
SQLite storage for hosts, metrics, events, and incidents.
Zero external database dependencies; file created automatically.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DB_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sentrix.db")


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    if db_path is None:
        db_path = DB_FILE
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Create tables if they do not exist and ensure schema is up to date."""
    if db_path is None:
        db_path = DB_FILE
    conn = get_connection(db_path)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS hosts (
        host_name TEXT PRIMARY KEY,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'online'
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_name TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        cpu_percent REAL NOT NULL,
        memory_percent REAL NOT NULL,
        disk_percent REAL NOT NULL,
        net_sent_bps REAL NOT NULL,
        net_recv_bps REAL NOT NULL,
        cpu_temp REAL,
        temp_simulated INTEGER DEFAULT 0
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_name TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        message TEXT NOT NULL,
        source_file TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'warning'
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_type TEXT NOT NULL DEFAULT 'general',
        title TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'warning',
        status TEXT NOT NULL DEFAULT 'active',
        affected_hosts TEXT NOT NULL,
        timeline TEXT NOT NULL,
        likely_cause TEXT NOT NULL,
        suggested_action TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)

    # Check for incident_type column in case of existing database
    try:
        cur.execute("ALTER TABLE incidents ADD COLUMN incident_type TEXT DEFAULT 'general';")
    except Exception:
        pass

    try:
        cur.execute("ALTER TABLE metrics ADD COLUMN temp_simulated INTEGER DEFAULT 0;")
    except Exception:
        pass

    # Indices for fast polling
    cur.execute("CREATE INDEX IF NOT EXISTS idx_metrics_host ON metrics (host_name, id DESC);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON events (host_name, id DESC);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status, incident_type, updated_at DESC);")

    conn.commit()
    conn.close()


def reset_db(db_path: Optional[str] = None) -> None:
    """Clear all records from database tables for a clean slate."""
    if db_path is None:
        db_path = DB_FILE
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM metrics;")
    cur.execute("DELETE FROM events;")
    cur.execute("DELETE FROM incidents;")
    cur.execute("DELETE FROM hosts;")
    conn.commit()
    conn.close()


def touch_host(host_name: str, conn: Optional[sqlite3.Connection] = None) -> None:
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True

    now = datetime.now(timezone.utc).isoformat()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO hosts (host_name, first_seen, last_seen, status)
        VALUES (?, ?, ?, 'online')
        ON CONFLICT(host_name) DO UPDATE SET
            last_seen = excluded.last_seen,
            status = 'online';
    """, (host_name, now, now))
    conn.commit()
    if should_close:
        conn.close()


def insert_metrics(data: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> int:
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True

    touch_host(data["host_name"], conn)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO metrics (host_name, timestamp, cpu_percent, memory_percent, disk_percent, net_sent_bps, net_recv_bps, cpu_temp, temp_simulated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        data["host_name"],
        data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        float(data.get("cpu_percent", 0.0)),
        float(data.get("memory_percent", 0.0)),
        float(data.get("disk_percent", 0.0)),
        float(data.get("net_sent_bps", 0.0)),
        float(data.get("net_recv_bps", 0.0)),
        data.get("cpu_temp"),
        1 if data.get("temp_simulated") else 0
    ))
    conn.commit()
    row_id = cur.lastrowid
    if should_close:
        conn.close()
    return row_id


def insert_events(events: List[Dict[str, Any]], conn: Optional[sqlite3.Connection] = None) -> List[int]:
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True

    cur = conn.cursor()
    inserted_ids = []
    for ev in events:
        touch_host(ev["host_name"], conn)
        cur.execute("""
            INSERT INTO events (host_name, timestamp, event_type, message, source_file, severity)
            VALUES (?, ?, ?, ?, ?, ?);
        """, (
            ev["host_name"],
            ev.get("timestamp", datetime.now(timezone.utc).isoformat()),
            ev.get("event_type", "error"),
            ev.get("message", ""),
            ev.get("source_file", "app.log"),
            ev.get("severity", "warning")
        ))
        inserted_ids.append(cur.lastrowid)

    conn.commit()
    if should_close:
        conn.close()
    return inserted_ids


def get_hosts(conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True

    cur = conn.cursor()
    cur.execute("SELECT host_name, first_seen, last_seen, status FROM hosts ORDER BY host_name ASC;")
    rows = [dict(r) for r in cur.fetchall()]
    if should_close:
        conn.close()
    return rows


def get_system_stats(conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    """Single query source for dashboard overview metrics & tile counts."""
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True

    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM hosts WHERE status = 'online';")
    hosts_online = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM incidents WHERE status = 'active';")
    active_incidents = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM events WHERE event_type = 'failed_login';")
    failed_logins = cur.fetchone()[0]

    cur.execute("SELECT AVG(cpu_percent) FROM (SELECT cpu_percent FROM metrics ORDER BY id DESC LIMIT 10);")
    avg_cpu_row = cur.fetchone()[0]
    avg_cpu = round(float(avg_cpu_row), 1) if avg_cpu_row is not None else 0.0

    if should_close:
        conn.close()

    return {
        "hosts_online": hosts_online,
        "active_incidents": active_incidents,
        "failed_logins": failed_logins,
        "avg_cpu": avg_cpu
    }


def get_recent_metrics(host_name: Optional[str] = None, limit: int = 50, conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True

    cur = conn.cursor()
    if host_name:
        cur.execute("""
            SELECT id, host_name, timestamp, cpu_percent, memory_percent, disk_percent, net_sent_bps, net_recv_bps, cpu_temp, temp_simulated
            FROM metrics
            WHERE host_name = ?
            ORDER BY id DESC
            LIMIT ?;
        """, (host_name, limit))
    else:
        cur.execute("""
            SELECT id, host_name, timestamp, cpu_percent, memory_percent, disk_percent, net_sent_bps, net_recv_bps, cpu_temp, temp_simulated
            FROM metrics
            ORDER BY id DESC
            LIMIT ?;
        """, (limit,))

    rows = [dict(r) for r in cur.fetchall()]
    rows.reverse()
    if should_close:
        conn.close()
    return rows


def get_recent_events(host_name: Optional[str] = None, limit: int = 50, conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True

    cur = conn.cursor()
    if host_name:
        cur.execute("""
            SELECT id, host_name, timestamp, event_type, message, source_file, severity
            FROM events
            WHERE host_name = ?
            ORDER BY id DESC
            LIMIT ?;
        """, (host_name, limit))
    else:
        cur.execute("""
            SELECT id, host_name, timestamp, event_type, message, source_file, severity
            FROM events
            ORDER BY id DESC
            LIMIT ?;
        """, (limit,))

    rows = [dict(r) for r in cur.fetchall()]
    if should_close:
        conn.close()
    return rows


def create_or_update_incident(
    incident_type: str,
    title: str,
    severity: str,
    affected_hosts: List[str],
    timeline: List[Dict[str, Any]],
    likely_cause: str,
    suggested_action: str,
    conn: Optional[sqlite3.Connection] = None
) -> int:
    """
    Creates a new incident OR merges into an existing active incident
    of the same type with overlapping hosts within the correlation window.
    Timeline and counts grow consistently upon merging.
    """
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True

    now = datetime.now(timezone.utc).isoformat()
    cur = conn.cursor()

    # Find active incidents of the same type
    cur.execute("""
        SELECT id, incident_type, title, severity, affected_hosts, timeline, likely_cause, suggested_action, created_at, updated_at
        FROM incidents
        WHERE incident_type = ? AND status = 'active'
        ORDER BY id DESC;
    """, (incident_type,))
    candidates = cur.fetchall()

    target = None
    input_hosts = set(affected_hosts)

    for cand in candidates:
        try:
            cand_hosts = set(json.loads(cand["affected_hosts"]))
        except Exception:
            cand_hosts = set()

        # Match if hosts overlap or if either is empty
        if not cand_hosts or not input_hosts or cand_hosts.intersection(input_hosts):
            target = cand
            break

    if target:
        inc_id = target["id"]
        try:
            curr_timeline = json.loads(target["timeline"])
        except Exception:
            curr_timeline = []

        # Merge timelines and deduplicate by (timestamp, host, message)
        seen = set()
        deduped_timeline = []
        for item in curr_timeline + timeline:
            key = (item.get("timestamp"), item.get("host"), item.get("message"))
            if key not in seen:
                seen.add(key)
                deduped_timeline.append(item)

        # Merge affected hosts
        try:
            prev_hosts = json.loads(target["affected_hosts"])
        except Exception:
            prev_hosts = []
        merged_hosts = sorted(list(set(prev_hosts).union(input_hosts)))
        hosts_str = ", ".join(merged_hosts) if merged_hosts else "monitored node"

        # Re-compute count strictly from merged timeline for full consistency
        if incident_type == "brute_force":
            count = sum(1 for it in deduped_timeline if it.get("event_type") == "failed_login")
            updated_title = f"Repeated Authentication Failures ({count} attempts)"
            updated_cause = (
                f"Repeated authentication failures ({count} failed attempts) detected on {hosts_str}. "
                f"Pattern indicates an automated credential-stuffing or brute-force attack."
            )
            updated_sev = "critical" if count >= 5 else "warning"
        elif incident_type == "error_spike":
            count = sum(1 for it in deduped_timeline if it.get("event_type") == "error")
            updated_title = f"Application Error Surge ({count} exceptions detected)"
            updated_cause = (
                f"Sudden surge in unhandled exceptions ({count} exceptions detected) on {hosts_str} "
                f"immediately following code deployment or config update. "
                f"High error frequency indicates an unexpected null reference or dependency connection issue."
            )
            updated_sev = "critical" if (count >= 5 or severity == "critical") else "warning"
        else:
            updated_title = title
            updated_cause = likely_cause
            updated_sev = severity

        cur.execute("""
            UPDATE incidents
            SET title = ?, severity = ?, affected_hosts = ?, timeline = ?, likely_cause = ?, suggested_action = ?, updated_at = ?
            WHERE id = ?;
        """, (
            updated_title,
            updated_sev,
            json.dumps(merged_hosts),
            json.dumps(deduped_timeline[-30:]),
            updated_cause,
            suggested_action,
            now,
            inc_id
        ))
    else:
        cur.execute("""
            INSERT INTO incidents (incident_type, title, severity, status, affected_hosts, timeline, likely_cause, suggested_action, created_at, updated_at)
            VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?);
        """, (
            incident_type,
            title,
            severity,
            json.dumps(sorted(list(input_hosts))),
            json.dumps(timeline[-30:]),
            likely_cause,
            suggested_action,
            now,
            now
        ))
        inc_id = cur.lastrowid

    conn.commit()
    if should_close:
        conn.close()
    return inc_id


def get_incidents(status: Optional[str] = None, limit: int = 20, conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True

    cur = conn.cursor()
    if status:
        cur.execute("""
            SELECT id, incident_type, title, severity, status, affected_hosts, timeline, likely_cause, suggested_action, created_at, updated_at
            FROM incidents
            WHERE status = ?
            ORDER BY id DESC LIMIT ?;
        """, (status, limit))
    else:
        cur.execute("""
            SELECT id, incident_type, title, severity, status, affected_hosts, timeline, likely_cause, suggested_action, created_at, updated_at
            FROM incidents
            ORDER BY id DESC LIMIT ?;
        """, (limit,))

    rows = []
    for r in cur.fetchall():
        d = dict(r)
        try:
            d["affected_hosts"] = json.loads(d["affected_hosts"])
        except Exception:
            d["affected_hosts"] = []
        try:
            d["timeline"] = json.loads(d["timeline"])
        except Exception:
            d["timeline"] = []
        rows.append(d)

    if should_close:
        conn.close()
    return rows

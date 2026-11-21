"""
SENTRIX Central Server
----------------------
FastAPI backend that ingests approved operational telemetry, stores it
in SQLite, correlates events into incidents, and serves the live dashboard.

Endpoints:
  - POST /ingest/metrics
  - POST /ingest/events
  - GET  /api/metrics
  - GET  /api/events
  - GET  /api/incidents
  - GET  /api/hosts
  - GET  /api/health
  - GET  /api/stats
  - POST /api/reset
  - GET  /api/privacy-proof
  - GET  / (serves dashboard/index.html)
"""

import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Ensure Sentrix root directory is in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from server import db
from server.correlator import correlate_and_evaluate_incidents, process_metric_telemetry, _METRIC_HISTORY

API_KEY = os.getenv("SENTRIX_API_KEY", "").strip()
DASHBOARD_DIR = os.path.join(PROJECT_ROOT, "dashboard")
SERVER_START_TIME = time.time()
# Port for uvicorn (Render sets $PORT; default 8000 for local dev)
SERVER_PORT = int(os.getenv("PORT", "8000"))

# Reset control: In production environments, reset is disabled by default
IS_PRODUCTION = bool(
    os.getenv("RENDER")
    or os.getenv("PRODUCTION")
    or os.getenv("ENV") == "production"
)
DEFAULT_ALLOW_RESET = "false" if IS_PRODUCTION else "true"
ALLOW_RESET = os.getenv("SENTRIX_ALLOW_RESET", DEFAULT_ALLOW_RESET).lower() in ("true", "1", "yes")

# In-memory buffer of latest ingested payloads for the Privacy & Redaction Proof panel
_PRIVACY_PROOF_PAYLOADS: List[Dict[str, Any]] = []

# Initialize SQLite database immediately
db.init_db()

app = FastAPI(
    title="SENTRIX Observability & Security Platform",
    description="Privacy-first AI observability server",
    version="1.0.0"
)

# Enable CORS for local testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Authentication Helper
# ---------------------------------------------------------------------------

def verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    """Ensure collector agent provides valid key."""
    if not API_KEY or not x_api_key or x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header"
        )
    return x_api_key


# ---------------------------------------------------------------------------
# Pydantic Ingestion Models
# ---------------------------------------------------------------------------

class MetricPayload(BaseModel):
    host_name: str
    timestamp: Optional[str] = None
    cpu_percent: float = Field(..., ge=0, le=100)
    memory_percent: float = Field(..., ge=0, le=100)
    disk_percent: float = Field(..., ge=0, le=100)
    net_sent_bps: float = 0.0
    net_recv_bps: float = 0.0
    cpu_temp: Optional[float] = None
    temp_simulated: Optional[bool] = False


class EventItem(BaseModel):
    host_name: str
    timestamp: Optional[str] = None
    event_type: str = "error"
    message: str
    source_file: str = "app.log"
    severity: str = "warning"


class EventsPayload(BaseModel):
    events: List[EventItem]


# ---------------------------------------------------------------------------
# Ingest Endpoints (Synchronous def for threadpool execution with SQLite)
# ---------------------------------------------------------------------------

@app.post("/ingest/metrics", status_code=status.HTTP_201_CREATED)
def ingest_metrics(payload: MetricPayload, _auth: str = Depends(verify_api_key)):
    data = payload.model_dump()
    if not data.get("timestamp"):
        data["timestamp"] = datetime.now(timezone.utc).isoformat()

    row_id = db.insert_metrics(data)
    # Check for anomalies and correlate
    process_metric_telemetry(data)

    # Store in privacy proof buffer
    _PRIVACY_PROOF_PAYLOADS.append({
        "received_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "type": "metrics",
        "host": data["host_name"],
        "payload": {
            "cpu_percent": data["cpu_percent"],
            "memory_percent": data["memory_percent"],
            "disk_percent": data["disk_percent"],
            "cpu_temp": data["cpu_temp"],
            "temp_simulated": data.get("temp_simulated", False)
        }
    })
    if len(_PRIVACY_PROOF_PAYLOADS) > 60:
        _PRIVACY_PROOF_PAYLOADS.pop(0)

    return {"status": "ok", "id": row_id}


@app.post("/ingest/events", status_code=status.HTTP_201_CREATED)
def ingest_events(payload: EventsPayload, _auth: str = Depends(verify_api_key)):
    items = [item.model_dump() for item in payload.events]
    now_ts = datetime.now(timezone.utc).isoformat()
    for it in items:
        if not it.get("timestamp"):
            it["timestamp"] = now_ts

    ids = db.insert_events(items)
    # Correlate into incidents
    correlate_and_evaluate_incidents()

    # Store in privacy proof buffer (proves that raw logs were redacted locally)
    for it in items:
        _PRIVACY_PROOF_PAYLOADS.append({
            "received_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "type": "event",
            "host": it["host_name"],
            "payload": {
                "event_type": it["event_type"],
                "message": it["message"],
                "severity": it["severity"]
            }
        })
    if len(_PRIVACY_PROOF_PAYLOADS) > 60:
        del _PRIVACY_PROOF_PAYLOADS[:-60]

    return {"status": "ok", "count": len(ids)}


# ---------------------------------------------------------------------------
# API Query Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health")
def get_health():
    stats = db.get_system_stats()
    return {
        "status": "healthy",
        "service": "SENTRIX Central Server",
        "version": "1.0.0",
        "uptime_seconds": int(time.time() - SERVER_START_TIME),
        "hosts_count": stats["hosts_online"],
        "active_incidents_count": stats["active_incidents"]
    }


@app.get("/api/stats")
def get_stats():
    """Unified system statistics for dashboard tiles."""
    return db.get_system_stats()


@app.post("/api/reset")
def reset_system(_auth: str = Depends(verify_api_key)):
    """Wipes database and in-memory caches to clear stale hosts before a demo.

    Security Controls:
      1. POST only (GET is strictly forbidden and returns 405 Method Not Allowed).
      2. Requires valid X-API-Key authentication (returns 401 Unauthorized if missing/invalid).
      3. Disabled in production environments by default (returns 403 Forbidden unless SENTRIX_ALLOW_RESET=true).
    """
    if not ALLOW_RESET:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Database reset operation is disabled in this environment"
        )
    db.reset_db()
    _PRIVACY_PROOF_PAYLOADS.clear()
    _METRIC_HISTORY.clear()
    return {"status": "ok", "message": "Database and telemetry reset successfully"}


@app.get("/api/hosts")
def get_hosts():
    return {"hosts": db.get_hosts()}


@app.get("/api/metrics")
def get_metrics(
    host: Optional[str] = Query(None, description="Host name filter"),
    limit: int = Query(50, ge=1, le=500)
):
    host_filter = host if isinstance(host, str) else None
    limit_val = limit if isinstance(limit, int) else 50
    rows = db.get_recent_metrics(host_name=host_filter, limit=limit_val)
    return {"metrics": rows}


@app.get("/api/events")
def get_events(
    host: Optional[str] = Query(None, description="Host name filter"),
    limit: int = Query(50, ge=1, le=500)
):
    host_filter = host if isinstance(host, str) else None
    limit_val = limit if isinstance(limit, int) else 50
    rows = db.get_recent_events(host_name=host_filter, limit=limit_val)
    return {"events": rows}


@app.get("/api/incidents")
def get_incidents(
    status: Optional[str] = Query(None, description="active or resolved"),
    limit: int = Query(20, ge=1, le=100)
):
    status_filter = status if isinstance(status, str) else None
    limit_val = limit if isinstance(limit, int) else 20
    rows = db.get_incidents(status=status_filter, limit=limit_val)
    return {"incidents": rows}


@app.get("/api/privacy-proof")
def get_privacy_proof():
    """Returns recent received payloads to prove only redacted data was ingested."""
    return {"recent_payloads": list(reversed(_PRIVACY_PROOF_PAYLOADS))}


# ---------------------------------------------------------------------------
# Static Dashboard Hosting
# ---------------------------------------------------------------------------

if os.path.exists(DASHBOARD_DIR):
    app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")

    @app.get("/")
    def serve_dashboard():
        index_file = os.path.join(DASHBOARD_DIR, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"error": "Dashboard index.html not found"}


# ---------------------------------------------------------------------------
# Standalone Entry Point  (python -m server.main  or  python server/main.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.main:app", host="0.0.0.0", port=SERVER_PORT, log_level="info")

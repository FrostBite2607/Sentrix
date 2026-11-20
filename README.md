# SENTRIX — AI-Powered Observability & Security Platform MVP

> **Prototype for CICADA 2026**  
> *Sees everything. Leaks nothing.*

SENTRIX is a privacy-first observability platform that monitors servers and applications, correlates related events across nodes, explains root causes in plain language, and **guarantees that raw logs never leave the customer's environment**.

---

## Architecture & Privacy Guarantee

```
 Customer Environment (Local)                      Central Server (SENTRIX)
┌─────────────────────────────────┐               ┌───────────────────────────────┐
│  Raw Logs (/var/log/*.log)      │               │  FastAPI Telemetry Ingestion  │
│  System Metrics (CPU, Mem, Net) │               │  (/ingest/metrics, /events)   │
└────────────────┬────────────────┘               └──────────────┬────────────────┘
                 │                                               │
                 ▼                                               ▼
┌─────────────────────────────────┐               ┌───────────────────────────────┐
│   SENTRIX Collector Agent       │               │      SQLite Storage Layer     │
│  - Reads local telemetry        │               │   (hosts, metrics, events)    │
│  - Local Redaction Engine       │               └──────────────┬────────────────┘
│    (strips emails, IPs, tokens, │                              │
│     passwords, usernames, card#)│                              ▼
└────────────────┬────────────────┘               ┌───────────────────────────────┐
                 │                                │  Event & Metric Correlator    │
                 │ Approved operational data only │  - Temporal Clustering (<2m)  │
                 │ (numeric metrics + redacted)   │  - Security & Anomaly Rules   │
                 └───────────────────────────────►│  - AI Root Cause Explainer    │
                                                  └──────────────┬────────────────┘
                                                                 │
                                                                 ▼
                                                  ┌───────────────────────────────┐
                                                  │    Live Web Dashboard (2s)    │
                                                  │  - Charts, Incidents, Modals  │
                                                  │  - Privacy Proof Panel        │
                                                  └───────────────────────────────┘
```

1. **Local Collector Agent (`collector/agent.py`)**: Runs directly on the host machine. Every 5 seconds it reads system metrics (psutil) and tails local log files.
2. **Local Redactor (`collector/redactor.py`)**: Strips emails, IPv4/IPv6 addresses, usernames, passwords, bearer tokens, API keys, and credit cards before anything leaves the node.
3. **Approved Egress Only**: Only numeric metrics and pre-sanitized messages reach the central server. The agent prints a visible `"──── WHAT LEFT THIS MACHINE ────"` audit line on every cycle.
4. **Central Engine (`server/correlator.py` & `explainer.py`)**: Stores telemetry in SQLite, detects anomalies, correlates related alerts (e.g. overheating server + slow response times), and provides plain-language root-cause explanations and recommended fixes.
5. **Live Dashboard (`dashboard/`)**: A dark, clean SaaS interface polling the API every 2 seconds, with live charts, incident modals, and a live **Privacy Proof** stream.

---

## Project Structure

```text
Sentrix/
├── collector/
│   ├── agent.py            # Local agent (psutil metrics + log tailing)
│   ├── redactor.py         # Local privacy redaction engine
│   └── log_watcher.py      # Stateful log file parser
├── server/
│   ├── main.py             # FastAPI backend & static dashboard server
│   ├── db.py               # SQLite storage for hosts, metrics, events, incidents
│   ├── correlator.py       # Anomaly detection & multi-event incident grouping
│   └── explainer.py        # Rule-based & LLM root-cause generator
├── dashboard/
│   ├── index.html          # Dashboard UI
│   ├── style.css           # Dark theme (#070B14, cards #0D1424, cyan #22D3EE)
│   └── app.js              # Polling client & canvas chart visualizer
├── simulator/
│   └── incidents.py        # Demo incident injector (overheating, brute-force, spike)
├── sample_logs/
│   ├── app.log             # Sample application logs
│   └── auth.log            # Sample authentication logs
├── tests/
│   ├── test_redactor.py    # 21 unit tests verifying privacy redactions
│   └── test_correlator.py  # Anomaly detection & incident correlation tests
├── run_demo.py             # One-command demonstration runner
├── requirements.txt        # Python dependencies
├── .gitignore              # Excludes local secrets and generated files
├── .env.example            # Placeholder-only environment template
└── README.md
```

---

## Quickstart

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure API Authentication

The server, collector, and incident simulator use `SENTRIX_API_KEY` from the
process environment. The `.env.example` file is a placeholder template; SENTRIX
does not load `.env` files automatically. In PowerShell, generate a temporary
key for the current shell with:

```powershell
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$env:SENTRIX_API_KEY = [Convert]::ToBase64String($bytes)
$rng.Dispose()
```

Keep the value private and do not commit it. The one-command demo generates a
temporary random key automatically when `SENTRIX_API_KEY` is not already set.
When running the server, collector, or simulator separately, set the same
environment variable for each process.

### 3. Run All Tests
```bash
python -m pytest tests/ -v
```
*(All 33 tests verify redaction safety, anomaly detection, incident correlation, authentication, and explanation generation).*

### 4. One-Command Live Demonstration
```bash
python run_demo.py
```
This automatically:
- Starts the central FastAPI server on port 8000
- Launches two collector agents (`web-prod-01` and `db-prod-01`)
- Injects 3 realistic failure scenarios
- Serves the live dashboard at **http://localhost:8000**

---

## Triggering Demo Scenarios On-Demand

You can trigger any scenario at any time from a terminal while the server is running:

### Scenario 1: Overheating Server Causing Slow Website
```bash
python -m simulator.incidents overheating
```
*Injects high CPU (96%) and thermal temperature (89°C) on `web-prod-01` along with high response latency. SENTRIX correlates the two and identifies thermal throttling.*

### Scenario 2: Repeated Failed Logins (Brute-Force)
```bash
python -m simulator.incidents brute-force
```
*Simulates 4 rapid failed logins with credentials and IP. The redactor replaces sensitive details with `[EMAIL]`, `[IP]`, and `[PASSWORD]`. SENTRIX flags credential stuffing and recommends IP blocking.*

### Scenario 3: Application Error Surge After Deployment
```bash
python -m simulator.incidents deployment-spike
```
*Simulates 3 unhandled exceptions following a software release. SENTRIX clusters them and recommends a rollback.*

---

## Student Viva & Evaluation Guide

- **How is privacy enforced?**  
  Look at `collector/agent.py` and `collector/redactor.py`. Redaction happens inside the customer machine *before* `requests.post()` is ever invoked. The `test_server_payload_has_no_raw_pii` test ensures that no unredacted email or IP can ever leave the agent.
- **Can it run completely offline?**  
  Yes. The root-cause explainer has built-in rule heuristics. Zero external cloud dependencies or API keys are required for the viva demo.
- **Does it support optional LLMs?**  
  Yes. If `LLM_API_KEY` is exported, `explainer.py` queries the Gemini API for natural-language analysis using **only pre-redacted summaries**. If the network fails, it immediately falls back to deterministic rules.

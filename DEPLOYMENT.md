# SENTRIX — Render Deployment Guide

> Deploy the SENTRIX central server and dashboard as a public web service on Render.

---

## Prerequisites

- A [Render](https://render.com) account (free tier works).
- The SENTRIX repository pushed to GitHub:  
  `https://github.com/FrostBite2607/Sentrix`

---

## 1. Create the Web Service on Render

1. Log in to [Render Dashboard](https://dashboard.render.com).
2. Click **New → Web Service**.
3. Connect your GitHub account and select the **FrostBite2607/Sentrix** repository.
4. Render will auto-detect `render.yaml` and pre-fill the settings below.  
   If it does not, enter them manually:

| Setting            | Value                                                      |
| ------------------ | ---------------------------------------------------------- |
| **Name**           | `sentrix`                                                  |
| **Runtime**        | Python                                                     |
| **Build Command**  | `pip install -r requirements.txt`                          |
| **Start Command**  | `uvicorn server.main:app --host 0.0.0.0 --port $PORT`     |
| **Health Check**   | `/api/health`                                              |

5. Click **Create Web Service**.

---

## 2. Set Environment Variables

In the Render dashboard for your service, go to **Environment → Environment Variables** and add:

| Key                | Value                                | Notes                              |
| ------------------ | ------------------------------------ | ---------------------------------- |
| `SENTRIX_API_KEY`  | *(a strong random string)*           | Required. Never share publicly.    |
| `PYTHON_VERSION`   | `3.11.6`                             | Optional; ensures correct runtime. |

> [!CAUTION]
> Never commit `SENTRIX_API_KEY` to source control or expose it in frontend code.

If using `render.yaml`, Render can auto-generate `SENTRIX_API_KEY` on first deploy.

---

## 3. Deploy

Render deploys automatically on every push to the connected branch.

- Build: installs Python packages from `requirements.txt`.
- Start: runs `uvicorn` bound to `0.0.0.0` on Render's `$PORT` (default 10000).
- Health check: Render pings `GET /api/health` to confirm the service is live.

After deployment completes, Render provides a public URL like:

```
https://sentrix-XXXX.onrender.com
```

Open it in a browser to see the SENTRIX dashboard.

---

## 4. Connect a Local Collector Agent

The monitoring agent runs on your local machine and sends telemetry to the deployed server.

```bash
# Set the API key (must match the one configured on Render)
export SENTRIX_API_KEY="your-render-api-key-here"

# Start the collector
python -m collector.agent \
    --host-name my-laptop \
    --server https://sentrix-XXXX.onrender.com
```

On Windows PowerShell:

```powershell
$env:SENTRIX_API_KEY = "your-render-api-key-here"
python -m collector.agent --host-name my-laptop --server https://sentrix-XXXX.onrender.com
```

The agent sends only redacted operational data. Raw logs never leave your machine.

---

## 5. Run the Simulator Against Render

```bash
export SENTRIX_API_KEY="your-render-api-key-here"
python -m simulator.incidents all --server https://sentrix-XXXX.onrender.com
```

This injects the three demo scenarios (overheating, brute-force, error spike) into the live deployed instance.

---

## 6. Post-Deployment Testing

After deployment, verify these:

| Test                          | How                                                             | Expected                |
| ----------------------------- | --------------------------------------------------------------- | ----------------------- |
| Dashboard loads               | Open `https://sentrix-XXXX.onrender.com` in a browser           | Dark-themed dashboard   |
| Health check                  | `curl https://sentrix-XXXX.onrender.com/api/health`             | `{"status": "healthy"}` |
| API auth works                | `curl -H "X-API-Key: wrong" .../ingest/metrics` → 401           | 401 Unauthorized        |
| Agent connects                | Run collector agent locally with `--server` pointing to Render  | Metrics appear on dashboard |
| Simulator works               | Run `python -m simulator.incidents all --server ...`            | Incidents appear on dashboard |

---

## 7. Known Limitations

### SQLite on Render (Ephemeral Storage)
Render's free tier uses an **ephemeral filesystem**. The SQLite database (`sentrix.db`) resets on each deploy or service restart. This is acceptable for a hackathon demo.

For persistent data:
- Render offers **Persistent Disks** (\$0.25/GB/month).
- Or migrate to Render's managed PostgreSQL.

### Free Tier Cold Starts
On Render's free tier, the service spins down after 15 minutes of inactivity. The first request after idle takes ~30–60 seconds.

### Local Development Still Works
`python run_demo.py` continues to work locally on `http://localhost:8000` exactly as before. The Render deployment does not affect the local workflow.

---

## Architecture Reminder

```
Local Machine                           Render (Public)
┌──────────────────────┐                ┌──────────────────────────┐
│  Collector Agent     │  HTTPS POST    │  FastAPI Server          │
│  (psutil + redactor) │───────────────▶│  /ingest/metrics         │
│                      │  redacted only │  /ingest/events          │
└──────────────────────┘                │                          │
                                        │  SQLite + Correlator     │
                                        │  + Explainer             │
                                        │                          │
                                        │  GET / → Dashboard       │
                                        │  GET /api/* → JSON APIs  │
                                        └──────────────────────────┘
```

Raw logs **never** leave the local machine.

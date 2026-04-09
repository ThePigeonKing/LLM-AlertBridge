# User Guide

## Accessing the System

1. Connect to the cloud network via OpenVPN
2. Open your browser and navigate to `http://10.128.0.29:8000/alerts`
3. The main page shows the alert list

## Alert List

The alerts page shows all security alerts with:
- **Severity** badge (Critical / High / Medium / Low / Info)
- **Rule ID** and description from Wazuh
- **Agent** — which host generated the alert
- **Status** — Pending, Analyzing, Analyzed, or Failed
- **Timestamp**

Click any row to open the alert detail page.

### Syncing Alerts

Click **"Sync from Wazuh"** to fetch new alerts from the Wazuh Indexer. Only new alerts (not already in the database) are imported.

## Alert Detail Page

The detail page has three panels:

### Left: Alert Details

Shows alert metadata, with collapsible sections for raw and normalized JSON data.

### Left: Host Context (Enrichment)

Click **"Enrich with osquery"** to collect host-level data from the alert's source agent. This queries osquery on the target host for:
- Running processes
- Open network connections
- Logged-in users
- File events, crontabs, SUID binaries (depending on alert type)

The enrichment data is displayed in tabular form.

### Left: Correlation

If enrichment data exists, the system automatically shows:
- **Temporal alerts** — other alerts from the same host within a time window
- **Context matches** — connections between alert fields and host data (e.g., source IP found in active connections)
- **MITRE ATT&CK chains** — multiple alerts sharing the same tactic

### Right: LLM Analysis

Select an analysis mode:

| Mode | Description |
|---|---|
| **LLM + Enrichment** | Full analysis with host context and correlation (recommended) |
| **LLM Only** | Analysis using only alert data |
| **Baseline** | Deterministic rule-based assessment (no LLM call, instant) |

Click **"Analyze"** to run the analysis. The result shows:
- **Criticality** badge with score and justification
- **Recommended response** action with urgency level
- **Summary** and **hypothesis**
- **Possible causes**, **key indicators**, **recommended checks**
- **Confidence note**
- Processing metadata (model, latency, token usage)

## Running Experiments

See `experiments/README.md` for instructions on running the evaluation framework.

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Database connectivity check |
| GET | `/api/alerts` | List alerts (paginated) |
| GET | `/api/alerts/{id}` | Get single alert |
| POST | `/api/alerts/sync` | Fetch new alerts from Wazuh |
| POST | `/api/alerts/{id}/enrich` | Collect osquery data for alert |
| POST | `/api/alerts/{id}/analyze?mode=...` | Run analysis (baseline/llm/llm_enriched) |
| GET | `/api/alerts/{id}/analysis` | Get latest analysis for alert |
| GET | `/api/analyses/{id}` | Get analysis by ID |
| GET | `/docs` | Interactive API documentation (Swagger) |

# Deployment guide: upgrading to the thesis version

You already have the project-stage system running on `core-compute` with Wazuh + PostgreSQL + FastAPI in Docker Compose and LM Studio on your laptop through the VPN. This guide walks you through deploying the thesis-stage enhancements (enrichment, correlation, multi-mode analysis, evaluation framework) **on top of** that existing setup — without breaking anything currently running.

See [network.md](network.md) for the full host inventory.

---

## What changed from the project version

| Area | Project (before) | Thesis (after) |
|---|---|---|
| Database | 2 tables (`alerts`, `analyses`) | 3 tables + 6 new columns on `analyses` |
| Analysis | Single LLM mode | 3 modes (baseline / llm / llm_enriched) |
| osquery | Empty stub | Working client (SSH + mock transports) |
| Prompts | 6-field JSON | 8-field JSON with criticality + response |
| API | `/analyze` | `/analyze?mode=…` + `/enrich` |
| UI | Analyze button | Mode selector + enrichment panel + correlation panel |
| Tests | None | 63 tests |
| Evaluation | None | Corpus of 20 alerts + runner + analysis scripts |
| Config | 8 env vars | 12 env vars (added osquery + correlation) |

---

## Pre-flight: check your current state

SSH into `core-compute`:

```bash
ssh core-compute
cd LLM-AlertBridge
```

Confirm the existing stack is running:

```bash
docker compose ps
# Should show: db, backend, wazuh.indexer, wazuh.manager, wazuh.dashboard
# All healthy or running

curl -s http://10.128.0.29:8000/health
# Should return: {"status":"ok","database":"ok"}
```

If the stack is down, start it first:

```bash
docker compose up -d
```

Check the current database migration head:

```bash
docker compose exec backend uv run alembic current
# Should show: c034ee325edf (head)
```

---

## Step 1: Pull the new code

```bash
cd ~/LLM-AlertBridge    # or wherever your repo lives on core-compute
git pull origin main     # or your branch name
```

If you haven't committed the new code yet, push it from your laptop first:

```bash
# On your laptop
cd LLM-AlertBridge
git add -A
git commit -m "thesis: enrichment, correlation, multi-mode analysis, evaluation framework"
git push
```

---

## Step 2: Update `.env`

The new code adds osquery and correlation settings. Add these lines to the **existing** `.env` on `core-compute` (the previous variables stay the same):

```bash
# Append to existing .env on core-compute
cat >> .env << 'EOF'

# osquery enrichment (new for thesis)
OSQUERY_TRANSPORT=mock
OSQUERY_SSH_USER=root
OSQUERY_SSH_KEY_PATH=
OSQUERY_SSH_TIMEOUT=10

# Correlation (new for thesis)
CORRELATION_TIME_WINDOW_MINUTES=15
EOF
```

**`OSQUERY_TRANSPORT=mock`** is safe — the system returns built-in sample data without needing osquery on target hosts. Switch to `ssh` later if you install osquery (see Step 6).

All existing variables (`LM_STUDIO_BASE_URL`, `LM_STUDIO_MODEL`, Wazuh credentials, etc.) remain unchanged.

---

## Step 3: Rebuild and restart the stack

```bash
docker compose down
docker compose up --build -d
```

The `backend` container's startup command runs `alembic upgrade head` automatically, which applies the new migration (`a1b2c3d4e5f6`). This migration:
- Creates the `enrichments` table
- Adds 6 nullable columns to `analyses` (`criticality_score`, `criticality_level`, `criticality_justification`, `response_action`, `response_urgency`, `analysis_mode`)

**Existing data is preserved** — all new columns are nullable, so old analysis records remain valid.

---

## Step 4: Verify the deployment

### 4.1 Health check

```bash
curl -s http://10.128.0.29:8000/health
# {"status":"ok","database":"ok"}
```

### 4.2 Migration check

```bash
docker compose exec backend uv run alembic current
# Should show: a1b2c3d4e5f6 (head)
```

### 4.3 Database tables

```bash
docker compose exec db psql -U alertbridge -c "\dt"
```

Expected output should include `alerts`, `analyses`, `enrichments`, and `alembic_version`.

### 4.4 New API endpoints

```bash
# List alerts (should return existing alerts)
curl -s http://10.128.0.29:8000/api/alerts | python3 -m json.tool | head -5

# Check that the new mode parameter is accepted
curl -s -X POST "http://10.128.0.29:8000/api/alerts/sync?limit=5"
```

### 4.5 UI check

Open in your browser (via VPN): `http://10.128.0.29:8000/alerts`

- Alert list should look the same as before
- Click any alert — the detail page now has:
  - **"Enrich with osquery"** button (left panel)
  - **Analysis Mode selector** (Baseline / LLM Only / LLM + Enrichment) before the Analyze button
  - If you had old analyses, they display normally (missing criticality/response fields are tolerated)

### 4.6 Test the new features

1. Click any alert
2. Click **"Enrich with osquery"** — in mock mode this returns sample host data instantly
3. Select **"Baseline"** mode and click **Analyze** — this runs without LLM, shows a rule-based assessment with criticality badge and response recommendation
4. If LM Studio is running, select **"LLM + Enrichment"** and click **Analyze** — this sends enrichment context to the LLM

---

## Step 5: Run the evaluation framework

The evaluation runs **from `core-compute`** (or from your laptop if you have the code and Python environment). It does not need Docker.

### 5.1 Baseline evaluation (no LLM required)

```bash
# On core-compute, from the repo root
docker compose exec backend uv run python experiments/run_evaluation.py --mode baseline
```

Or if you have `uv` installed directly on the host:

```bash
cd ~/LLM-AlertBridge
uv run python experiments/run_evaluation.py --mode baseline
```

Expected output:

```
Loaded 20 alerts from corpus
[1/20] Processing eval-001 (ssh_brute_force)...
...
Schema conformance: 20/20 (100.0%)
Severity accuracy:  8/20 (40.0%)
Response accuracy:  4/20 (20.0%)
...
Results saved to experiments/results/baseline_default
```

### 5.2 LLM evaluations (requires LM Studio on laptop)

1. Make sure LM Studio is running on your laptop with a model loaded
2. Make sure the VPN / SSH tunnel is active so `core-compute` can reach LM Studio
3. Run:

```bash
# LLM without enrichment
uv run python experiments/run_evaluation.py --mode llm --model "your-model-name"

# LLM with enrichment (uses simulated enrichment from corpus)
uv run python experiments/run_evaluation.py --mode llm_enriched --model "your-model-name"
```

Each run takes 2–10 minutes depending on your hardware and model size.

### 5.3 Compare results

```bash
uv run python experiments/analyze_results.py
```

Produces `experiments/results/comparison_table.md` — paste this into your thesis.

---

## Step 6 (optional): Enable live osquery enrichment

If you want real host context instead of mock data:

### 6.1 Install osquery on target hosts

```bash
# SSH into each target host
ssh target-1-compute   # 10.128.0.35
ssh target-2-compute   # 10.128.0.14

# On each (Ubuntu/Debian):
export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY
sudo add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
sudo apt-get update && sudo apt-get install -y osquery
sudo systemctl enable osqueryd && sudo systemctl start osqueryd
```

### 6.2 Set up SSH access from the backend container

The backend container needs to SSH into target hosts. This means the SSH key must be available inside the container.

On `core-compute`:

```bash
# Generate a key specifically for osquery (if you don't have one)
ssh-keygen -t ed25519 -f ~/.ssh/osquery_key -N ""

# Copy to target hosts
ssh-copy-id -i ~/.ssh/osquery_key root@10.128.0.35
ssh-copy-id -i ~/.ssh/osquery_key root@10.128.0.14

# Test
ssh -i ~/.ssh/osquery_key root@10.128.0.35 "osqueryi --json 'SELECT version FROM osquery_info;'"
```

### 6.3 Mount the SSH key into the container

Add a volume mount to the `backend` service in `docker-compose.yml`:

```yaml
  backend:
    # ... existing config ...
    volumes:
      - ./backend:/app/backend
      - ./frontend:/app/frontend
      - ./alembic.ini:/app/alembic.ini
      - ~/.ssh/osquery_key:/root/.ssh/osquery_key:ro     # <-- add this line
```

### 6.4 Update `.env`

```bash
OSQUERY_TRANSPORT=ssh
OSQUERY_SSH_USER=root
OSQUERY_SSH_KEY_PATH=/root/.ssh/osquery_key
OSQUERY_SSH_TIMEOUT=10
```

### 6.5 Rebuild

```bash
docker compose down && docker compose up --build -d
```

### 6.6 Verify

Open an alert in the UI, click **"Enrich with osquery"**. If the target host's Wazuh agent name matches the SSH-reachable hostname/IP, you should see real process, connection, and user data from that host.

**If it fails:** check backend logs:

```bash
docker compose logs -f backend 2>&1 | grep -i osquery
```

Common issues:
- SSH key not mounted → `OsqueryError: SSH to ... failed`
- osquery not installed → `osquery on ... returned code 127`
- Host unreachable → `SSH to ... timed out`

The system degrades gracefully — failed queries show as empty results, the analysis continues without them.

---

## Step 7: Run tests (optional, for verification)

```bash
# Inside the backend container
docker compose exec backend uv run pytest backend/tests/ -v

# Or directly on core-compute if uv is installed
cd ~/LLM-AlertBridge && uv run pytest backend/tests/ -v
```

All 63 tests should pass. Tests do not require a database or LM Studio — they use mocks and fixtures.

---

## Rollback plan

If something goes wrong and you need the old version:

```bash
# Revert to previous commit
git checkout HEAD~1

# Downgrade the database migration
docker compose exec backend uv run alembic downgrade c034ee325edf

# Rebuild with old code
docker compose down && docker compose up --build -d
```

The downgrade migration drops the `enrichments` table and removes the new columns from `analyses`. Existing alert and analysis data is preserved.

---

## Quick reference: what runs where

```
core-compute (10.128.0.29)
├── Docker Compose
│   ├── db           (Postgres :5432, localhost only)
│   ├── backend      (FastAPI :8000, bound to 10.128.0.29)
│   ├── wazuh.indexer    (OpenSearch :9200, internal only)
│   ├── wazuh.manager    (API :55000, agents :1514/:1515)
│   └── wazuh.dashboard  (Kibana :8443)
│
├── [optional] osquery SSH → target-1 (10.128.0.35)
│                          → target-2 (10.128.0.14)
│
└── VPN ← openvpn-access-server (10.128.0.7)

Analyst laptop (via VPN)
├── LM Studio (:1234) — reached from core-compute via VPN IP or SSH tunnel
├── Browser → http://10.128.0.29:8000/alerts
└── [optional] uv run python experiments/run_evaluation.py (from local clone)
```

---

## Complete `.env` for thesis deployment

This is a full example. Variables from your existing `.env` that you've already configured (passwords, model name, LM Studio URL) stay as-is — just add the new osquery/correlation block:

```bash
# LM Studio (already configured)
LM_STUDIO_BASE_URL=http://10.128.0.7:8080/v1    # your SSH tunnel endpoint
LM_STUDIO_MODEL=qwen/qwen3.5-9b                 # your loaded model

# Wazuh (already configured — Compose overrides these for the backend container)
WAZUH_API_URL=https://10.128.0.29:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=MyS3cr37P450r.*-
WAZUH_VERIFY_SSL=false

WAZUH_INDEXER_URL=https://10.128.0.29:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=SecretPassword

# Database (Compose overrides this for the backend container)
DATABASE_URL=postgresql+asyncpg://alertbridge:alertbridge@localhost:5432/alertbridge

# --- NEW for thesis ---

# osquery: "mock" for simulated data, "ssh" for real host queries
OSQUERY_TRANSPORT=mock
OSQUERY_SSH_USER=root
OSQUERY_SSH_KEY_PATH=
OSQUERY_SSH_TIMEOUT=10

# Correlation time window (minutes)
CORRELATION_TIME_WINDOW_MINUTES=15

# Application
LOG_LEVEL=INFO

# Docker Compose publish addresses (already configured)
WAZUH_PUBLISH_IP=10.128.0.29
ALERTBRIDGE_HTTP_PUBLISH=10.128.0.29:8000:8000
```

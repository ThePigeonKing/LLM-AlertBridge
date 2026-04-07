# LLM-AlertBridge

A research prototype for analyzing SOC/SIEM security alerts using a locally deployed LLM. The backend, database, and Wazuh run centrally on `core-compute` in Yandex Cloud, while the LLM runs on the analyst's laptop via LM Studio. Communication between the cloud and the laptop is secured through an OpenVPN tunnel, ensuring that sensitive data never reaches external cloud LLM services.

The LLM acts as an **intelligent assistant** for the analyst -- it does not make autonomous decisions or trigger automated responses. The final judgment always remains with the human operator.

## Motivation

- SOC/SIEM systems generate a high volume of alerts requiring manual triage.
- Analysts spend significant time collecting context and interpreting initial alerts.
- Cloud-based LLM services cannot be used for sensitive security telemetry.
- This system reduces routine workload, accelerates initial triage, and presents structured incident views -- all while keeping data local.

## Architecture

```
            Yandex Cloud                              Analyst Laptop
  ┌─────────────────────────────┐              ┌─────────────────────┐
  │  core-compute               │  VPN tunnel  │                     │
  │  ┌───────────┐ ┌─────────┐ │◄────────────►│  LM Studio          │
  │  │PostgreSQL │ │ FastAPI  │─┼──────────────│  (Local LLM,        │
  │  │           │ │ Backend  │ │  LLM API     │   port 1234)        │
  │  └───────────┘ └─────────┘ │              └─────────────────────┘
  │  ┌─────────────────────┐   │                       │
  │  │ Wazuh Manager       │   │                ┌──────▼──────┐
  │  └─────────────────────┘   │                │   Analyst   │
  │                             │                │  (Browser → │
  │  target-1  target-2        │                │  :8000 VPN) │
  │  (Agents)  (Agents)        │                └─────────────┘
  │                             │
  │  attacker-compute           │
  │  (Simulations)              │
  └─────────────────────────────┘
```

See [docs/architecture.md](docs/architecture.md) for the full infrastructure topology. For step-by-step deployment and startup, see [docs/deployment.md](docs/deployment.md).

### Core Workflow

1. Wazuh (on `core-compute`) detects a security event and generates an alert.
2. The FastAPI backend (on `core-compute`) fetches the alert via the local Wazuh API.
3. The alert is normalized into a unified internal format and stored in PostgreSQL.
4. A structured prompt is sent to LM Studio on the analyst's laptop via VPN.
5. The LLM returns a structured JSON analysis back to the backend.
6. The result is persisted and displayed to the analyst through the web UI (`core-compute:8000`).

## Tech Stack

| Component            | Technology                          | Rationale                                                    |
|----------------------|-------------------------------------|--------------------------------------------------------------|
| SIEM / Alert Source  | Wazuh                               | Open-source, active community, rich alert taxonomy           |
| Backend              | Python 3.12+ / FastAPI              | Async-native, auto-generated OpenAPI docs, Pydantic models   |
| Local LLM Runtime   | LM Studio                           | OpenAI-compatible API, runs on consumer hardware (MacBook)   |
| LLM Client          | `openai` Python SDK                 | Compatible with LM Studio; clean, well-maintained client     |
| Web UI               | Jinja2 + HTMX + Tailwind CSS       | Server-rendered simplicity with dynamic behavior; no JS framework overhead |
| Database             | PostgreSQL 16 (Docker)               | JSONB indexing, async via asyncpg, production-ready from day one |
| ORM / Migrations     | SQLAlchemy 2.0 + Alembic            | Async support, type-safe queries, versioned schema           |
| Configuration        | Pydantic Settings + `.env`          | Type-safe config with environment variable support           |
| Dependency Mgmt      | `uv` + `pyproject.toml`            | Modern, fast Python package management                       |
| Context Enrichment   | osquery (Stage 2)                   | Lightweight host-level telemetry collection                  |
| Test Environment     | Yandex Cloud                        | Wazuh, backend, DB on core-compute; target hosts; attacker VM |

## Project Structure

```
LLM-AlertBridge/
├── README.md
├── pyproject.toml                  # Project metadata, dependencies, tool config
├── alembic.ini                     # Database migration configuration
├── docker-compose.yml              # PostgreSQL + backend (deployed on core-compute)
├── Dockerfile                      # Backend container image
├── .env.example                    # Environment variable template
│
├── docs/
│   └── architecture.md             # Infrastructure topology and data flow
│
├── backend/
│   ├── app/
│   │   ├── main.py                 # FastAPI application factory
│   │   ├── config.py               # Pydantic Settings (env-based config)
│   │   ├── templates.py            # Jinja2Templates instance
│   │   │
│   │   ├── api/                    # HTTP layer
│   │   │   ├── router.py           # Top-level router aggregation
│   │   │   ├── alerts.py           # Alert CRUD + analysis trigger endpoints
│   │   │   ├── analysis.py         # Analysis result endpoints
│   │   │   ├── health.py           # Liveness / readiness probes
│   │   │   └── views.py            # Server-rendered page routes
│   │   │
│   │   ├── models/                 # SQLAlchemy ORM models (async, PostgreSQL)
│   │   │   ├── alert.py            # Alert table (JSONB, UUID PKs)
│   │   │   └── analysis.py         # Analysis result table
│   │   │
│   │   ├── schemas/                # Pydantic request/response schemas
│   │   │   ├── alert.py            # Alert DTOs
│   │   │   └── analysis.py         # Analysis DTOs (incl. LLM output format)
│   │   │
│   │   ├── services/               # Business logic layer
│   │   │   ├── alert_service.py    # Alert ingestion and normalization
│   │   │   ├── analysis_service.py # Orchestration: normalize → prompt → LLM → store
│   │   │   └── llm_service.py      # Prompt building and response parsing
│   │   │
│   │   ├── integrations/           # External system connectors
│   │   │   ├── wazuh/
│   │   │   │   ├── client.py       # Wazuh REST API client (async, JWT auth)
│   │   │   │   └── normalizer.py   # Raw alert → internal format mapping
│   │   │   ├── lm_studio/
│   │   │   │   └── client.py       # OpenAI-compatible client (custom base_url)
│   │   │   └── osquery/            # Stub for Stage 2
│   │   │
│   │   ├── db/
│   │   │   ├── session.py          # Async engine + session factory (asyncpg)
│   │   │   └── migrations/         # Alembic migration versions
│   │   │
│   │   └── prompts/                # LLM prompt templates
│   │       ├── system.txt          # System-level instructions
│   │       └── analysis.txt        # Per-alert analysis template
│   │
│   └── tests/
│
├── frontend/
│   ├── templates/                  # Jinja2 templates
│   │   ├── base.html               # Layout (Tailwind CDN + HTMX)
│   │   ├── alerts.html             # Alert list view
│   │   ├── alert_detail.html       # Alert + LLM analysis view
│   │   ├── 404.html
│   │   └── partials/
│   │       └── analysis_result.html  # HTMX fragment for analysis
│   └── static/
│
├── scripts/
│   └── seed_alerts.py              # Load 8 sample alerts for local dev
│
└── experiments/                    # Stage 2: experimental evaluation
```

## LLM Analysis Output Format

Each alert analysis produces a structured JSON result:

```json
{
  "summary": "Brief description of the security event",
  "hypothesis": "Preliminary hypothesis about the nature and intent of the event",
  "possible_causes": [
    "Brute-force SSH login attempt from external IP",
    "Compromised credential reuse from a leaked database"
  ],
  "key_indicators": [
    "Source IP 203.0.113.42 has 47 failed auth attempts in 5 minutes",
    "Target account 'root' is a high-privilege system account"
  ],
  "recommended_checks": [
    "Verify source IP reputation in threat intelligence feeds",
    "Check if the target account has been accessed successfully recently",
    "Review authentication logs for lateral movement indicators"
  ],
  "confidence_note": "Medium confidence — pattern is consistent with brute-force, but additional context from host-level telemetry would increase certainty"
}
```

Stage 2 extends this format with context sources, similar incidents, dialogue history, and analyst feedback.

## Development Stages

### Stage 1 — Project (Current)

Build a working prototype demonstrating the end-to-end pipeline:

**Wazuh → alert → backend → LLM → web UI → analyst sees structured analysis**

| Area                 | Scope                                                       |
|----------------------|-------------------------------------------------------------|
| Infrastructure       | Deploy Wazuh + Linux test hosts in Yandex Cloud             |
| Backend              | Alert ingestion, normalization, LLM orchestration, storage  |
| LLM Integration      | Single model via LM Studio, fixed prompt, JSON output       |
| Web UI               | Alert list, alert detail page with LLM analysis             |
| Database             | PostgreSQL with SQLAlchemy async; alerts, analyses, processing status |

### Stage 2 — Master's Thesis

Extend the prototype into a research-grade system with experimental evaluation:

| Area                 | Scope                                                       |
|----------------------|-------------------------------------------------------------|
| Context Enrichment   | osquery integration for host-level telemetry                |
| Analyst Dialogue     | Follow-up questions within alert context; dialogue history  |
| Similarity Search    | Find historically similar alerts/incidents with scoring     |
| Feedback Loop        | Analyst ratings, final event classification, learning basis |
| Experiments          | Multi-mode comparison (no LLM / LLM / LLM + context), multi-model benchmarks, quantitative metrics |
| Architecture         | Optional async queue (Redis/Celery), advanced caching       |

## Getting Started

### Prerequisites

- **On `core-compute` (Yandex Cloud):** Docker, Docker Compose
- **On analyst laptop:** [LM Studio](https://lmstudio.ai/) with a loaded model, OpenVPN client
- VPN connectivity between the laptop and `core-compute`

### Deployment on core-compute

```bash
# Clone the repository on core-compute
git clone <repo-url> && cd LLM-AlertBridge

# Copy environment config
cp .env.example .env
# Edit .env: set LM_STUDIO_BASE_URL to your laptop's VPN IP,
# set WAZUH_API_URL to localhost (Wazuh runs on the same host)

# Start everything (PostgreSQL + backend, auto-runs migrations)
docker compose up --build -d
```

### On the analyst laptop

1. Connect to the cloud network via OpenVPN.
2. Start LM Studio and load your model. Ensure the local server is running on port 1234.
3. Open the web UI in your browser: `http://<core-compute-vpn-ip>:8000/alerts`

### Local development (without cloud)

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync

# Start PostgreSQL via Docker
docker compose up db -d

# Copy environment config and set LM_STUDIO_BASE_URL=http://localhost:1234/v1
cp .env.example .env

# Run database migrations
uv run alembic upgrade head

# Seed sample alerts (optional)
uv run python scripts/seed_alerts.py

# Start the development server
uv run uvicorn backend.app.main:app --reload --port 8000
```

### Configuration

All configuration is managed via environment variables (see `.env.example`):

| Variable              | Description                              | Default                    |
|-----------------------|------------------------------------------|----------------------------|
| `LM_STUDIO_BASE_URL`  | LM Studio API endpoint (laptop VPN IP)  | `http://localhost:1234/v1` |
| `LM_STUDIO_MODEL`     | Model identifier loaded in LM Studio    | —                          |
| `WAZUH_API_URL`        | Wazuh manager API endpoint              | `https://localhost:55000`  |
| `WAZUH_API_USER`       | Wazuh API username                      | —                          |
| `WAZUH_API_PASSWORD`   | Wazuh API password                      | —                          |
| `DATABASE_URL`         | SQLAlchemy database connection string   | `postgresql+asyncpg://alertbridge:alertbridge@localhost:5432/alertbridge` |
| `LOG_LEVEL`            | Logging verbosity                       | `INFO`                     |

## Design Decisions

### Why local LLM, not cloud?
Security alert data may contain sensitive infrastructure details (IPs, hostnames, user accounts, vulnerability indicators). Sending this to external cloud LLM APIs violates the data confidentiality principle. The LLM runs on the analyst's laptop via LM Studio, and alert data is transmitted only over an encrypted VPN tunnel within the controlled infrastructure.

### Why Jinja2 + HTMX instead of React/Vue?
For a research prototype, server-side rendering with HTMX provides dynamic UI behavior (partial updates, lazy loading, SSE streaming for dialogue) without the overhead of a JavaScript build pipeline or SPA complexity. This keeps the codebase focused on the backend logic where the research value lies.

### Why PostgreSQL from day one?
PostgreSQL provides JSONB columns with native indexing (essential for querying alert data), robust concurrent access, and production-grade reliability. Using SQLAlchemy 2.0 async with Alembic migrations keeps the schema versioned and the codebase ready for Stage 2 extensions.

### Why `openai` SDK for LM Studio?
LM Studio exposes an OpenAI-compatible API. Using the official `openai` Python client with a custom `base_url` gives us a stable, well-documented interface with built-in retry logic, streaming support, and structured output parsing.

## License

This project is developed as part of a Master's thesis and is intended for academic and research purposes.

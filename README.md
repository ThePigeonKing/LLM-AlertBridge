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
            Yandex Cloud (10.128.0.0/24)              Analyst Laptop
  ┌──────────────────────────────────┐         ┌─────────────────────┐
  │ core-compute 10.128.0.29         │  VPN    │ LM Studio (your IP) │
  │ ┌──────────┐ ┌────────────────┐ │◄───────►│ port 1234           │
  │ │PostgreSQL│ │ FastAPI :8000  │─┼─────────│                     │
  │ └──────────┘ └────────────────┘ │         └─────────────────────┘
  │ Wazuh manager                    │                  │
  │ target-1 .35   target-2 .14      │           ┌───────▼───────┐
  │ attacker .36   openvpn .7        │           │ Browser →     │
  └──────────────────────────────────┘           │ 10.128.0.29   │
                                                 └───────────────┘
```

See [docs/architecture.md](docs/architecture.md) for full component diagrams, trust boundaries, and data flow.

### Core Workflow

1. Wazuh detects a security event and generates an alert.
2. The FastAPI backend fetches the alert via the Wazuh Indexer (OpenSearch).
3. The alert is normalized into a unified internal format and stored in PostgreSQL.
4. **(Optional)** Host context is collected from osquery on the target host.
5. **(Optional)** The alert is correlated with other events and enrichment data.
6. A structured prompt is sent to LM Studio (with or without enrichment context).
7. The LLM returns a structured JSON analysis with criticality assessment and response recommendation.
8. The result is persisted and displayed in the web UI.

### Analysis Modes

| Mode | What it uses | LLM call |
|---|---|---|
| `baseline` | Alert metadata + rule-based heuristics | No |
| `llm` | Alert data only | Yes |
| `llm_enriched` | Alert + osquery context + correlation | Yes |

## Tech Stack

| Component | Technology | Rationale |
|---|---|---|
| SIEM / Alert Source | Wazuh | Open-source, active community, rich alert taxonomy |
| Backend | Python 3.12+ / FastAPI | Async-native, auto-generated OpenAPI docs, Pydantic models |
| Local LLM Runtime | LM Studio | OpenAI-compatible API, runs on consumer hardware |
| LLM Client | `openai` Python SDK | Compatible with LM Studio; clean, well-maintained client |
| Web UI | Jinja2 + HTMX + Tailwind CSS | Server-rendered with dynamic behavior; no JS framework overhead |
| Database | PostgreSQL 16 (Docker) | JSONB indexing, async via asyncpg |
| ORM / Migrations | SQLAlchemy 2.0 + Alembic | Async support, type-safe queries, versioned schema |
| Context Enrichment | osquery | Lightweight host-level telemetry collection |
| Test Environment | Yandex Cloud | Wazuh, backend, DB on core-compute; target hosts; attacker VM |

## Project Structure

```
LLM-AlertBridge/
├── README.md
├── pyproject.toml
├── alembic.ini
├── docker-compose.yml
├── Dockerfile
├── .env.example
│
├── docs/
│   ├── architecture.md             # Component diagrams, trust boundaries, data flows
│   ├── algorithms.md               # Formal algorithm descriptions
│   ├── user-guide.md               # How to use the system
│   ├── network.md                  # Fixed internal IPv4 addresses
│   ├── deployment.md               # Deploy and start services
│   └── wazuh.md                    # Wazuh TLS and configuration
│
├── backend/
│   ├── app/
│   │   ├── main.py                 # FastAPI application factory
│   │   ├── config.py               # Pydantic Settings (env-based config)
│   │   ├── templates.py            # Jinja2Templates instance
│   │   │
│   │   ├── api/                    # HTTP layer
│   │   │   ├── router.py           # Top-level router aggregation
│   │   │   ├── alerts.py           # Alert CRUD + enrich + analyze endpoints
│   │   │   ├── analysis.py         # Analysis result endpoints
│   │   │   ├── health.py           # Liveness / readiness probes
│   │   │   └── views.py            # Server-rendered page routes
│   │   │
│   │   ├── models/                 # SQLAlchemy ORM models
│   │   │   ├── alert.py            # Alert table (JSONB, UUID PKs)
│   │   │   ├── analysis.py         # Analysis result table (incl. criticality, response)
│   │   │   └── enrichment.py       # Host context enrichment table
│   │   │
│   │   ├── schemas/                # Pydantic request/response schemas
│   │   │   ├── alert.py            # Alert DTOs
│   │   │   ├── analysis.py         # Analysis DTOs (criticality, response recommendation)
│   │   │   ├── enrichment.py       # Enrichment DTOs
│   │   │   └── correlation.py      # Correlation result DTOs
│   │   │
│   │   ├── services/               # Business logic layer
│   │   │   ├── alert_service.py    # Alert ingestion and queries
│   │   │   ├── analysis_service.py # Multi-mode analysis orchestration
│   │   │   ├── llm_service.py      # Prompt building, response parsing, sanitization
│   │   │   ├── enrichment_service.py # osquery enrichment orchestration
│   │   │   ├── correlation_service.py # Temporal, context, MITRE correlation
│   │   │   └── baseline_service.py # Rule-based assessment (no LLM)
│   │   │
│   │   ├── integrations/           # External system connectors
│   │   │   ├── wazuh/
│   │   │   │   ├── client.py       # Wazuh REST API + Indexer client
│   │   │   │   └── normalizer.py   # Raw alert → internal format
│   │   │   ├── lm_studio/
│   │   │   │   └── client.py       # OpenAI-compatible client
│   │   │   └── osquery/
│   │   │       ├── client.py       # osquery client (SSH + mock transports)
│   │   │       └── queries.py      # Query catalog and selection logic
│   │   │
│   │   ├── db/
│   │   │   ├── session.py          # Async engine + session factory
│   │   │   └── migrations/         # Alembic migration versions
│   │   │
│   │   └── prompts/                # LLM prompt templates
│   │       ├── system.txt          # System-level instructions (incl. criticality/response schema)
│   │       └── analysis.txt        # Per-alert analysis template (with context sections)
│   │
│   └── tests/
│       ├── conftest.py             # Shared fixtures and factories
│       ├── test_normalizer.py      # Wazuh normalization tests
│       ├── test_llm_parser.py      # LLM response parsing + sanitization tests
│       ├── test_enrichment.py      # osquery query selection + mock client tests
│       ├── test_correlation.py     # Context correlation tests
│       ├── test_assessment.py      # Baseline assessment + schema validation tests
│       └── test_integration.py     # Full pipeline integration tests
│
├── frontend/
│   └── templates/
│       ├── base.html               # Layout (Tailwind CDN + HTMX)
│       ├── alerts.html             # Alert list view
│       ├── alert_detail.html       # Alert + enrichment + correlation + analysis
│       ├── 404.html
│       └── partials/
│           ├── analysis_result.html  # Analysis with criticality badge + response card
│           ├── enrichment_result.html # osquery data tables
│           └── correlation_result.html # Correlated events display
│
├── experiments/
│   ├── README.md                   # Evaluation methodology
│   ├── corpus.json                 # 20 labeled alerts with ground truth
│   ├── run_evaluation.py           # Evaluation runner (baseline/llm/llm_enriched)
│   └── analyze_results.py          # Cross-run comparison and metrics
│
├── scripts/
│   └── seed_alerts.py              # Load sample alerts for local dev
│
└── deploy/wazuh/                   # Wazuh configuration and TLS
```

## LLM Analysis Output Format

Each alert analysis produces a structured JSON result:

```json
{
  "summary": "Brief description of the security event",
  "hypothesis": "Preliminary hypothesis about the nature and intent",
  "possible_causes": ["Array of possible explanations"],
  "key_indicators": ["Specific data points that stand out"],
  "recommended_checks": ["Concrete manual steps for the analyst"],
  "confidence_note": "Confidence level and what additional context would help",
  "criticality": {
    "score": 7,
    "level": "high",
    "justification": "Why this criticality level was assigned",
    "contributing_factors": ["Factors that influenced the score"]
  },
  "response": {
    "action": "contain",
    "urgency": "within_1h",
    "specific_steps": ["Concrete response actions"],
    "escalation_needed": true,
    "escalation_reason": "Active compromise requires team response"
  }
}
```

## Getting Started

### Prerequisites

- **On `core-compute`:** Docker, Docker Compose
- **On analyst laptop:** [LM Studio](https://lmstudio.ai/) with a loaded model, OpenVPN client
- VPN connectivity between the laptop and `core-compute`

### Deployment on core-compute

```bash
git clone <repo-url> && cd LLM-AlertBridge
cp .env.example .env
# Edit .env: set LM_STUDIO_BASE_URL, passwords, etc.
docker compose up --build -d
```

### Local development (without cloud)

```bash
uv sync --extra dev
docker compose up db -d
cp .env.example .env
uv run alembic upgrade head
uv run python scripts/seed_alerts.py
uv run uvicorn backend.app.main:app --reload --port 8000
```

### Running tests

```bash
uv run pytest backend/tests/ -v
```

### Running evaluation

```bash
python experiments/run_evaluation.py --mode baseline
python experiments/run_evaluation.py --mode llm --model "your-model-name"
python experiments/run_evaluation.py --mode llm_enriched --model "your-model-name"
python experiments/analyze_results.py
```

## Configuration

All configuration is managed via environment variables (see `.env.example`):

| Variable | Description | Default |
|---|---|---|
| `LM_STUDIO_BASE_URL` | LM Studio endpoint | `http://localhost:1234/v1` |
| `LM_STUDIO_MODEL` | Model identifier | — |
| `WAZUH_INDEXER_URL` | OpenSearch endpoint | — |
| `DATABASE_URL` | PostgreSQL connection | `postgresql+asyncpg://...` |
| `OSQUERY_TRANSPORT` | `ssh` or `mock` | `mock` |
| `OSQUERY_SSH_USER` | SSH user for osquery | `root` |
| `CORRELATION_TIME_WINDOW_MINUTES` | Temporal correlation window | `15` |
| `LOG_LEVEL` | Logging verbosity | `INFO` |

## License

This project is developed as part of a Master's thesis and is intended for academic and research purposes.

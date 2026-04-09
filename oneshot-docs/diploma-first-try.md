1. What this project is
LLM-AlertBridge is a research prototype: it connects Wazuh (SIEM) on a central host, a FastAPI + PostgreSQL service, and a local LLM (LM Studio) on an analyst machine over VPN (and optionally SSH tunneling). The idea is assistive triage — structured LLM output for humans, no autonomous blocking or response actions.

2. What is implemented today (functionality)
Infrastructure and deployment
Docker Compose on core-compute: PostgreSQL, backend, full Wazuh single-node stack (indexer, manager, dashboard), TLS cert generation flow, documented sysctl and memory tuning.
Networking model: internal IPs, WAZUH_PUBLISH_IP, binding services to internal addresses; docs for VPN, LM Studio reachability, optional SSH reverse tunnel script.
Backend (FastAPI)
App shell: create_app(), lifespan logging, static files, OpenAPI.
Health: GET /health — DB connectivity check.
Alerts API (/api/alerts):
List with pagination and optional status filter.
Get one alert by UUID.
Get latest analysis for an alert.
POST /api/alerts/sync — pull alerts from Wazuh storage, normalize, dedupe by wazuh_id, persist.
POST /api/alerts/{id}/analyze — run LLM pipeline, store Analysis, update alert status (with retries).
Analyses API: GET /api/analyses/{analysis_id}.
HTML UI (views): redirect / → /alerts, paginated alert list, alert detail with HTMX-friendly analyze/sync responses.
Data layer
SQLAlchemy 2 async + Alembic migrations.
Alert: UUID PK, wazuh_id, raw_data / normalized_data (JSONB), severity, rule fields, agent, AlertStatus lifecycle.
Analysis: structured fields (summary, hypothesis, lists, confidence), raw_response, model name, token counts, latency.
Integrations
Wazuh:
Alerts are read from the Wazuh Indexer (OpenSearch) via wazuh-alerts-*/_search, not the manager’s non-existent /alerts REST path.
Normalizer maps Wazuh-shaped JSON into a stable internal schema for prompts and storage.
LM Studio:
OpenAI-compatible client (base_url from settings), chat completion for analysis.
Compatibility fix: no response_format: json_object (LM Studio expects text / json_schema), parsing handled in code.
osquery: package stub only (empty __init__.py) — “Stage 2” in README, not implemented.
LLM pipeline
Prompts (system.txt, analysis.txt): SOC-style instructions, required JSON field schema.
llm_service: template fill, JSON parse (raw + fenced markdown), fallback summary if parse fails.
analysis_service: load alert → ANALYZING → call LM Studio → parse → save → COMPLETED / FAILED after retries.
Supporting assets
scripts/seed_alerts.py: seed DB without live Wazuh.
Docs: architecture, network, deployment, Wazuh (including troubleshooting e.g. API password policy, indexer memory).
Tests
conftest.py is empty; there are no real automated tests beyond project scaffolding.
3. What counts as “project work” vs “diploma” in your framing
Treat everything listed above as the completed course / project foundation: integrated stack, ingestion, UI, basic LLM analysis, documentation.

For a master’s thesis, examiners usually expect a defined research or engineering contribution beyond “we built a system”: e.g. a problem statement, method, experiments, metrics, comparison, limitations, and ideally novelty or rigorous evaluation. That delta is what you should plan to add on top of this codebase.

4. Recommendations: what to add so it becomes diploma-grade
Pick one main thread (thesis “spine”) and 1–2 supporting threads. Examples that fit this repo well:

A. Empirical evaluation (strong fit for a thesis)
Corpus: fixed set of Wazuh alerts (real or from your lab + seed_alerts variants), with ground-truth or analyst labels (e.g. true positive / benign / needs escalation).
Metrics: precision/recall or agreement with analysts on triage labels; structured-field quality (schema validity, hallucination checks against alert JSON only).
Baselines: rule-only heuristics, template-based summary, another model or temperature settings; ablation (with/without MITRE fields, with/without full_log).
Human study (optional but powerful): SUS questionnaire, time-to-triage, analyst trust — even a small n with clear protocol.
B. Context enrichment and “intelligent” triage (builds on the osquery stub)
Implement read-only osquery (or agent API) on targets to pull process, socket, user context for the same host as the alert, then inject into the prompt or a RAG chunk.
Thesis angle: measurable gain from enrichment vs raw alert only (same metrics as A).
C. Security and governance of LLM in SOC (thesis angle: “безопасность и приватность”)
Threat model: prompt injection via log fields, leakage across tenants, logging of prompts/responses.
Mitigations: field allowlists, max length, PII redaction, optional encryption at rest for raw_data, audit log of who ran analysis.
Policy: document alignment with “human final decision” and no auto-actions.
D. Product/thesis hybrid: incident workflow
Case management: link multiple alerts to an “incident”, status, assignee, notes.
Export: PDF/Markdown report for shift handover.
Webhooks or SIEM callback (read-only) for “analysis ready”.
E. Engineering depth (if the committee values implementation rigor)
Authentication/authorization for UI and API (currently open on internal network).
Idempotent sync, cursor-based polling from OpenSearch, backpressure if indexer is slow.
Structured logging, metrics (Prometheus), tracing; chaos tests for VPN down / LM Studio down.
Test suite: unit tests for normalizer, parse_llm_response, fake Wazuh/OpenSearch/LLM clients; integration tests with Testcontainers.
F. Documentation as thesis artifacts
Formal architecture (components, trust boundaries, data flows).
Reproducibility: one command or documented steps to replay the evaluation corpus and tables in the text.
Related work: LLM for SOC, Wazuh ecosystem, local LLM vs cloud, limitations of small models.
5. Practical suggestion
A defensible master’s thesis on this base could be titled around:
“Метод и экспериментальная оценка использования локальной LLM для первичного разбора алертов SIEM (Wazuh) в изолированной инфраструктуре”
with contribution = protocol + metrics + comparison + enrichment (optional), not only we deployed Docker.

If you tell me your department’s expectations (pages, required chapters, more “research” vs “development”), the list above can be narrowed to a single roadmap (milestones + chapter mapping).
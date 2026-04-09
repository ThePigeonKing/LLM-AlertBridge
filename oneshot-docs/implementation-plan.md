# Implementation Plan — LLM-AlertBridge → Master's Thesis

## Scope of this plan

This plan covers **all implementation work** in the codebase required to turn the
existing project-stage prototype into a thesis-grade system that satisfies both ТЗs.

Research done **outside** this codebase (LLM benchmarking, literature review,
thesis text writing) is listed in §9 for completeness but is not broken into
subtasks here.

---

## Mapping: ТЗ requirements → implementation blocks

| ТЗ requirement | Who | Implementation block |
|---|---|---|
| Сбор контекстных данных с хостов | Ковригина | Block 1: osquery enrichment |
| Корреляция событий и контекста | Ковригина | Block 2: correlation engine |
| Подготовка данных для интеллектуального анализа | Ковригина | Block 4: enrichment → analysis integration |
| Интеллектуальный анализ событий ИБ | Полищук | Block 3: assessment & response module |
| Оценка критичности инцидента | Полищук | Block 3: assessment & response module |
| Рекомендации по выбору способа реагирования | Полищук | Block 3: assessment & response module |
| Проверка эффективности (оба ТЗ §3.7) | Both | Block 5: evaluation framework |
| Устойчивость, тесты, надёжность (§3.2) | Both | Block 6: engineering quality |
| Описание архитектуры, алгоритмов, документация (§3.6) | Both | Block 7: documentation artifacts |

---

## Block 1 — osquery Enrichment Subsystem

**Satisfies:** Ковригина ТЗ — context collection from OS/host/process sources

### 1.1 osquery client

File: `backend/app/integrations/osquery/client.py`

- Async HTTP client that talks to osqueryd's Thrift/HTTP interface (or
  alternatively runs `osqueryi --json` over SSH if osqueryd isn't running as a
  daemon — design for both modes with a strategy pattern).
- Configuration: add `OSQUERY_TRANSPORT` (`http` | `ssh`),
  `OSQUERY_HTTP_URL`, `OSQUERY_SSH_HOST`, `OSQUERY_SSH_USER`,
  `OSQUERY_SSH_KEY_PATH` to `config.py`.
- Core method: `async query(host: str, sql: str) -> list[dict]`.
- Timeout + graceful degradation (if osquery is unreachable, enrichment
  returns partial result, not crash).

### 1.2 Enrichment query set

File: `backend/app/integrations/osquery/queries.py`

Predefined SQL queries scoped by alert context:

| Query name | osquery SQL | When to use |
|---|---|---|
| `running_processes` | `SELECT pid, name, path, cmdline, uid, start_time FROM processes` | Always |
| `open_connections` | `SELECT pid, local_address, local_port, remote_address, remote_port, state FROM process_open_sockets` | Network-related alerts |
| `listening_ports` | `SELECT pid, port, protocol, address FROM listening_ports` | Network-related alerts |
| `logged_in_users` | `SELECT user, host, time, tty FROM logged_in_users` | Auth-related alerts |
| `crontabs` | `SELECT command, path, minute, hour FROM crontab` | Persistence-related alerts |
| `suid_binaries` | `SELECT path, username, permissions FROM suid_bin` | Privilege escalation alerts |
| `file_events` | `SELECT target_path, action, time FROM file_events WHERE target_path LIKE ...` | File integrity alerts |

Logic to select which queries to run lives in `enrichment_service` (next),
keyed on alert `rule_groups` / MITRE tactic.

### 1.3 Enrichment service

File: `backend/app/services/enrichment_service.py`

```
async def enrich_alert(alert_id, session) -> EnrichmentResult:
    alert = load alert
    host = alert.agent_name  # target host for osquery
    relevant_queries = select_queries(alert.normalized_data)
    results = {}
    for qname, qsql in relevant_queries:
        try:
            results[qname] = await osquery_client.query(host, qsql)
        except OsqueryUnavailable:
            results[qname] = {"error": "host unreachable"}
    enrichment = EnrichmentResult(
        alert_id=alert_id,
        host=host,
        collected_at=now,
        data=results,
        queries_run=list(relevant_queries.keys()),
        queries_failed=[k for k,v in results.items() if "error" in v],
    )
    persist enrichment
    return enrichment
```

### 1.4 Data model

File: `backend/app/models/enrichment.py`

```
class Enrichment(Base):
    id: UUID PK
    alert_id: FK → alerts.id
    host: str
    collected_at: datetime
    data: JSONB           # raw osquery results keyed by query name
    queries_run: JSONB    # list of query names executed
    queries_failed: JSONB # list of query names that errored
    created_at: datetime
```

New Alembic migration: `add_enrichments_table`.

### 1.5 API endpoint

File: `backend/app/api/alerts.py` — add:

```
POST /api/alerts/{id}/enrich
```

Returns enrichment result. HTMX-aware: if `HX-Request`, return HTML partial.

### 1.6 UI integration

File: `frontend/templates/alert_detail.html`

- "Enrich with osquery" button (like the existing "Analyze with LLM" button)
- Collapsible section showing enrichment data grouped by query name
- Visual indicator if enrichment failed partially

### 1.7 Tests

File: `backend/tests/test_enrichment.py`

- Mock osquery client returning fixture data
- Test query selection logic (auth alert → logged_in_users selected)
- Test graceful degradation (osquery timeout)
- Test enrichment persistence

---

## Block 2 — Correlation Engine

**Satisfies:** Ковригина ТЗ — event correlation with context data

### 2.1 Correlation service

File: `backend/app/services/correlation_service.py`

Three correlation strategies:

**Temporal correlation:**
- Given an alert, find other alerts from the same host within ±N minutes
  (configurable, default 15).
- Query: `SELECT * FROM alerts WHERE agent_name = :host AND timestamp BETWEEN :start AND :end AND id != :current_id`
- Output: list of temporally related alerts with time deltas.

**Context correlation (enrichment-based):**
- Cross-reference enrichment data with alert fields:
  - Alert mentions a process name → check if that process appears in
    `running_processes` enrichment
  - Alert mentions a source IP → check if that IP appears in
    `open_connections` enrichment
  - Alert mentions a user → check if that user appears in `logged_in_users`
- Output: list of matched context entries with match type and confidence.

**MITRE ATT&CK correlation:**
- Group alerts by MITRE tactic/technique (already extracted by normalizer).
- If multiple alerts share the same tactic on the same host, flag as
  potential attack chain.
- Output: tactic chain with ordered alerts.

### 2.2 Correlation result schema

File: `backend/app/schemas/correlation.py`

```python
class CorrelatedAlert(BaseModel):
    alert_id: UUID
    rule_description: str
    severity: str
    timestamp: datetime
    time_delta_seconds: int

class ContextMatch(BaseModel):
    query_name: str          # e.g. "running_processes"
    matched_field: str       # e.g. "process_name"
    alert_value: str         # value from the alert
    host_value: dict         # matching row from osquery
    match_type: str          # "exact" | "partial" | "ip_match"

class MitreChain(BaseModel):
    tactic: str
    technique_ids: list[str]
    alert_ids: list[UUID]
    chain_length: int

class CorrelationResult(BaseModel):
    alert_id: UUID
    temporal_alerts: list[CorrelatedAlert]
    context_matches: list[ContextMatch]
    mitre_chains: list[MitreChain]
    correlation_summary: str  # one-line human-readable summary
```

### 2.3 Integration with analysis

The `CorrelationResult` is serialized and injected into the LLM prompt
(see Block 4). It is also displayed in the UI on the alert detail page.

### 2.4 Tests

File: `backend/tests/test_correlation.py`

- Temporal: seed 5 alerts on same host, verify window filtering
- Context: mock enrichment with known process, verify match detection
- MITRE: seed alerts with overlapping tactics, verify chain detection

---

## Block 3 — Enhanced Assessment & Response Module

**Satisfies:** Полищук ТЗ — intelligent analysis, criticality assessment,
response recommendations

### 3.1 Extended analysis schema

File: `backend/app/schemas/analysis.py` — extend `AnalysisResult`:

```python
class CriticalityAssessment(BaseModel):
    score: int                    # 1-10
    level: str                    # "info" | "low" | "medium" | "high" | "critical"
    justification: str            # why this score
    contributing_factors: list[str]

class ResponseRecommendation(BaseModel):
    action: str                   # from taxonomy: ignore | monitor | investigate | contain | escalate
    urgency: str                  # "immediate" | "within_1h" | "within_24h" | "scheduled"
    specific_steps: list[str]     # concrete actions for the analyst
    escalation_needed: bool
    escalation_reason: str | None

class AnalysisResult(BaseModel):
    # existing fields
    summary: str
    hypothesis: str
    possible_causes: list[str]
    key_indicators: list[str]
    recommended_checks: list[str]
    confidence_note: str
    # new fields
    criticality: CriticalityAssessment
    response: ResponseRecommendation
```

### 3.2 Updated prompts

File: `backend/app/prompts/system.txt`

Add to the required JSON schema:
- `criticality` object with score/level/justification/contributing_factors
- `response` object with action/urgency/specific_steps/escalation_needed/escalation_reason
- Define the response taxonomy in the system prompt so the LLM picks from a
  fixed set of actions

File: `backend/app/prompts/analysis.txt`

Add optional sections (filled only when enrichment data is available):
```
{host_context_section}
{correlated_alerts_section}
```

### 3.3 Updated LLM response parser

File: `backend/app/services/llm_service.py`

- `parse_llm_response` must handle the new fields
- Graceful fallback: if LLM omits `criticality` or `response`, fill with
  defaults derived from Wazuh severity (not crash)
- Validation: `action` must be from the taxonomy, `score` must be 1-10

### 3.4 Rule-based baseline service

File: `backend/app/services/baseline_service.py`

A **non-LLM** baseline for comparison in experiments:

```python
def baseline_assessment(alert) -> AnalysisResult:
    """
    Deterministic rule-based assessment using only Wazuh alert fields.
    No LLM involved. Serves as Mode A baseline in evaluation.
    """
    severity = alert.severity
    rule_level = alert.rule_level

    # Map severity → criticality
    criticality = SEVERITY_TO_CRITICALITY[severity]

    # Map rule groups → response action
    action = RULE_GROUP_TO_ACTION.get(primary_group, "investigate")

    # Template-based summary
    summary = f"Alert {alert.rule_id}: {alert.rule_description} on {alert.agent_name}"

    return AnalysisResult(
        summary=summary,
        hypothesis="Rule-based assessment, no LLM analysis performed",
        possible_causes=[alert.rule_description],
        key_indicators=[...extracted from normalized_data...],
        recommended_checks=STANDARD_CHECKS[primary_group],
        confidence_note="Low — rule-based only, no contextual analysis",
        criticality=criticality,
        response=ResponseRecommendation(action=action, ...),
    )
```

### 3.5 DB model update

File: `backend/app/models/analysis.py`

Add columns (or store within existing JSONB — decide based on whether we need
to query by criticality_score):

```python
criticality_score: int | None
criticality_level: str | None
response_action: str | None
response_urgency: str | None
```

New Alembic migration: `add_criticality_and_response_fields`.

### 3.6 UI updates

File: `frontend/templates/partials/analysis_result.html`

- Criticality badge (color-coded by level)
- Response recommendation card with action, urgency, steps
- Escalation warning if `escalation_needed`

### 3.7 Tests

File: `backend/tests/test_assessment.py`

- Test baseline service produces valid AnalysisResult for each alert type
- Test LLM parser handles new fields
- Test fallback when LLM omits new fields
- Test response taxonomy validation

---

## Block 4 — Enrichment → Analysis Integration

**Satisfies:** Both ТЗs — connecting Ковригина's enrichment to Полищук's analysis

### 4.1 Multi-mode analysis

File: `backend/app/services/analysis_service.py` — refactor `analyze_alert`:

```python
async def analyze_alert(
    alert_id: UUID,
    session: AsyncSession,
    mode: AnalysisMode = AnalysisMode.LLM_WITH_ENRICHMENT,
) -> Analysis:
    """
    mode:
      BASELINE        — rule-based only (Block 3.4)
      LLM_ONLY        — current behavior, no enrichment
      LLM_WITH_ENRICHMENT — enrich first, then analyze with full context
    """
```

### 4.2 Prompt construction with context

File: `backend/app/services/llm_service.py` — extend `build_analysis_prompt`:

```python
def build_analysis_prompt(
    alert_data: dict,
    enrichment: EnrichmentResult | None = None,
    correlation: CorrelationResult | None = None,
) -> str:
    # base prompt (existing)
    prompt = template.format(...)

    if enrichment:
        prompt += "\n\n## Host Context (from osquery)\n"
        prompt += format_enrichment_for_prompt(enrichment)

    if correlation:
        prompt += "\n\n## Correlated Events\n"
        prompt += format_correlation_for_prompt(correlation)

    return prompt
```

### 4.3 API changes

File: `backend/app/api/alerts.py`

- `POST /api/alerts/{id}/analyze` gains optional query param `mode`:
  `baseline` | `llm` | `llm_enriched` (default: `llm_enriched`)
- For `llm_enriched`: auto-runs enrichment + correlation before analysis
- HTMX: mode selector dropdown on alert detail page

### 4.4 UI updates

File: `frontend/templates/alert_detail.html`

- Mode selector (radio buttons or dropdown) before the "Analyze" button
- Display which mode was used in the analysis result
- Side-by-side comparison view (stretch goal — show baseline vs LLM result)

### 4.5 Tests

File: `backend/tests/test_integration.py`

- Test full pipeline: alert → enrich (mocked) → correlate → analyze (mocked LLM)
- Test each mode produces valid output
- Test that enrichment data actually appears in the prompt

---

## Block 5 — Evaluation Framework

**Satisfies:** Both ТЗs §3.7 — "проверка эффективности"

### 5.1 Alert corpus

Directory: `experiments/corpus/`

Create 20-30 labeled alerts covering the major Wazuh rule categories:

| # | Category | Count | Examples |
|---|---|---|---|
| 1 | SSH brute force | 3-4 | Failed auth, successful after failures, different IPs |
| 2 | Privilege escalation | 3-4 | sudo abuse, SUID exploitation, su to root |
| 3 | File integrity (syscheck) | 3-4 | /etc/passwd modified, binary replaced, config changed |
| 4 | Web attacks | 3-4 | SQL injection attempt, path traversal, XSS |
| 5 | Rootkit detection | 2-3 | Hidden process, suspicious file |
| 6 | Audit events | 2-3 | Policy violation, unauthorized access |
| 7 | Malware / anomaly | 2-3 | Known hash, suspicious behavior |
| 8 | Benign / false positive | 3-4 | Routine cron, legitimate admin action |

Each alert file: `experiments/corpus/alert_NNN.json`

```json
{
  "wazuh_alert": { ... raw Wazuh JSON ... },
  "ground_truth": {
    "is_true_positive": true,
    "expected_severity": "high",
    "expected_response": "contain",
    "expected_key_indicators": ["source IP has 47 failed attempts", ...],
    "expected_mitre_tactic": "credential-access",
    "notes": "Classic SSH brute-force pattern"
  },
  "simulated_enrichment": {
    "running_processes": [ ... ],
    "open_connections": [ ... ],
    "logged_in_users": [ ... ]
  }
}
```

The `simulated_enrichment` field allows evaluation without live osquery —
the enrichment service can load this data instead of querying a real host.

### 5.2 Evaluation runner

File: `experiments/run_evaluation.py`

```
Usage: python experiments/run_evaluation.py --mode baseline|llm|llm_enriched --model <model_name> --output results/

For each alert in corpus/:
  1. Load alert + ground truth + simulated enrichment
  2. Run analysis in the specified mode
  3. Collect:
     - raw LLM response
     - parsed AnalysisResult
     - latency (ms)
     - token count (prompt + completion)
     - schema validity (did JSON parse succeed?)
  4. Score against ground truth:
     - severity_match: LLM criticality.level == expected_severity
     - response_match: LLM response.action == expected_response
     - indicator_coverage: % of expected_key_indicators mentioned in LLM output
     - false_positive_detection: for benign alerts, did LLM correctly assess low criticality?
  5. Write per-alert result to results/<mode>_<model>_<alert_NNN>.json
```

### 5.3 Results analysis

File: `experiments/analyze_results.py`

Reads all result files and computes:

| Metric | Description |
|---|---|
| Schema conformance rate | % of responses that parsed into valid AnalysisResult |
| Severity accuracy | % where criticality.level matches ground truth |
| Response accuracy | % where response.action matches ground truth |
| Indicator coverage (mean) | Average % of expected indicators mentioned |
| False positive detection rate | % of benign alerts correctly scored as low/info |
| Mean latency | Average processing time |
| Mean token usage | Average prompt + completion tokens |

Output:
- `experiments/results/summary.json` — raw metric values
- `experiments/results/comparison_table.md` — formatted for thesis inclusion
- (optional) `experiments/results/charts/` — matplotlib/seaborn bar charts

### 5.4 Experiment execution plan

Run the evaluation in these configurations:

| Run | Mode | Model | Enrichment | Purpose |
|---|---|---|---|---|
| 1 | baseline | — | — | Rule-only baseline (Mode A) |
| 2 | llm | model_1 | No | LLM without context (Mode B) |
| 3 | llm_enriched | model_1 | Yes (simulated) | LLM with context (Mode C) |
| 4 | llm | model_2 | No | Cross-model comparison |
| 5 | llm_enriched | model_2 | Yes (simulated) | Cross-model + enrichment |

(model_1 and model_2 are whichever models you select from LM Studio — this
is where the separate LLM benchmarking research feeds in)

### 5.5 Tests

File: `backend/tests/test_evaluation.py`

- Test that evaluation runner loads corpus correctly
- Test scoring logic against a known alert/result pair

---

## Block 6 — Engineering Quality

**Satisfies:** Both ТЗs §3.2 (reliability) + thesis credibility

### 6.1 Test suite

Files in `backend/tests/`:

| File | Tests |
|---|---|
| `conftest.py` | Async session fixture (SQLite in-memory), mock LLM client, mock osquery client, sample alert factory |
| `test_normalizer.py` | Wazuh JSON → normalized format; edge cases (missing fields, malformed JSON, empty alert) |
| `test_llm_parser.py` | Valid JSON, fenced markdown, partial JSON, garbage input, missing new fields, fallback behavior |
| `test_enrichment.py` | Query selection by alert type, graceful degradation, data persistence |
| `test_correlation.py` | Temporal window, context matching, MITRE chain detection |
| `test_assessment.py` | Baseline service, response taxonomy validation, criticality scoring |
| `test_integration.py` | Full pipeline with mocks: alert → enrich → correlate → analyze → verify output |
| `test_api.py` | HTTP endpoint tests (FastAPI TestClient): status codes, response shapes, error handling |

### 6.2 Input sanitization

File: `backend/app/services/llm_service.py`

- Sanitize alert fields before prompt inclusion: strip potential prompt
  injection patterns (e.g., "ignore previous instructions"), truncate
  oversized fields (`full_log` > 4KB), escape special characters.
- Document this as a security measure in the thesis (Полищук can frame this
  as part of "надёжность" requirements).

### 6.3 Audit logging

File: `backend/app/services/audit.py`

- Log every analysis request: who (future: user ID), when, which alert,
  which mode, which model, success/failure.
- Store in a simple `audit_log` table or structured log file.
- Thesis value: demonstrates governance awareness for LLM in SOC.

### 6.4 Graceful degradation

Across all services — already partially exists, but formalize:

- LM Studio down → clear error in UI, alert stays in previous status
- osquery unreachable → partial enrichment, analysis proceeds without
- DB connection lost → health endpoint reports, requests return 503
- Document these scenarios in architecture docs

### 6.5 .env.example

File: `.env.example`

Currently referenced in docs but missing from the repo. Create it with all
config variables and sensible defaults/placeholders.

---

## Block 7 — Documentation Artifacts

**Satisfies:** Both ТЗs §3.6 — architecture, algorithms, user description

### 7.1 Formal architecture document

File: `docs/architecture.md` — rewrite/extend:

- Component diagram (ASCII or Mermaid): Wazuh → Backend → LLM, osquery → Backend
- Trust boundaries: what data crosses which boundary
- Data flow diagram: alert lifecycle from Wazuh event to analyst-visible analysis
- Sequence diagrams: sync flow, enrichment flow, analysis flow (all three modes)

### 7.2 Algorithm descriptions

File: `docs/algorithms.md` (new)

- Alert normalization algorithm (existing, document formally)
- Enrichment query selection algorithm (new)
- Temporal correlation algorithm (new)
- Context correlation algorithm (new)
- MITRE chain detection algorithm (new)
- Criticality scoring logic (new)
- Response selection logic (new, rule-based baseline)
- LLM prompt construction algorithm (existing + extensions)
- LLM response parsing and validation (existing + extensions)

Each algorithm: inputs, outputs, pseudocode or flowchart, complexity notes.

### 7.3 User documentation

File: `docs/user-guide.md` (new)

- How to access the UI
- How to sync alerts from Wazuh
- How to enrich an alert
- How to run analysis (each mode)
- How to interpret the analysis result
- How to run the evaluation framework

### 7.4 Updated README

File: `README.md`

- Update project structure section with new files
- Update Stage 2 section (no longer "planned" — "implemented")
- Add evaluation section

---

## Block 8 — Not in scope (done separately)

These are tracked here for completeness but are **not implementation tasks
in this codebase**:

| Item | Where it happens |
|---|---|
| LLM model comparison and benchmarks | Separate research, feeds model_1/model_2 into Block 5 |
| Literature review | Thesis text |
| Related work analysis | Thesis text |
| Thesis text writing (both Полищук and Ковригина) | Separate documents |
| Presentation preparation | Separate |

---

## Implementation order and dependencies

```
Block 1 (osquery enrichment) ──┐
                                ├─→ Block 4 (integration) ─→ Block 5 (evaluation)
Block 2 (correlation engine) ──┘          │
                                          │
Block 3 (assessment & response) ─────────┘

Block 6 (engineering quality) — parallel with Blocks 1-4
Block 7 (documentation) — after Blocks 1-4, parallel with Block 5
```

Blocks 1, 2, 3 can be developed in parallel (they are independent).
Block 4 requires 1+2+3 to be complete.
Block 5 requires Block 4.
Block 6 is continuous.
Block 7 starts after the feature code is stable.

---

## Suggested timeline

Assuming ~33 days (Apr 9 → May 12).

| Period | Focus | Blocks |
|---|---|---|
| Apr 9-12 (4d) | osquery enrichment + correlation engine | 1, 2 |
| Apr 13-15 (3d) | Assessment & response module | 3 |
| Apr 16-18 (3d) | Integration (enrichment → analysis pipeline) | 4 |
| Apr 19-22 (4d) | Evaluation framework + corpus creation | 5 |
| Apr 23-25 (3d) | Run experiments, collect results | 5 (cont.) |
| Apr 19-25 | Tests (parallel with evaluation work) | 6 |
| Apr 26-28 (3d) | Documentation artifacts + architecture | 7 |
| Apr 26 → May 9 | Thesis writing (both documents) | 8 (separate) |
| May 10-12 (3d) | Polish, review, final submission | All |

---

## Task checklist

### Block 1: osquery Enrichment
- [ ] Add osquery config variables to `config.py`
- [ ] Implement `integrations/osquery/client.py` (HTTP + SSH modes)
- [ ] Implement `integrations/osquery/queries.py` (query catalog)
- [ ] Implement `services/enrichment_service.py`
- [ ] Create `models/enrichment.py` + Alembic migration
- [ ] Add `POST /api/alerts/{id}/enrich` endpoint
- [ ] Add enrichment UI section to `alert_detail.html`
- [ ] Add `partials/enrichment_result.html`
- [ ] Write `tests/test_enrichment.py`

### Block 2: Correlation Engine
- [ ] Implement `services/correlation_service.py` (temporal + context + MITRE)
- [ ] Create `schemas/correlation.py`
- [ ] Add correlation display to `alert_detail.html`
- [ ] Write `tests/test_correlation.py`

### Block 3: Assessment & Response Module
- [ ] Extend `schemas/analysis.py` (CriticalityAssessment, ResponseRecommendation)
- [ ] Update `prompts/system.txt` (new JSON fields + response taxonomy)
- [ ] Update `prompts/analysis.txt` (enrichment/correlation sections)
- [ ] Update `services/llm_service.py` (parser for new fields + fallbacks)
- [ ] Implement `services/baseline_service.py` (rule-based Mode A)
- [ ] Update `models/analysis.py` + Alembic migration
- [ ] Update `partials/analysis_result.html` (criticality badge, response card)
- [ ] Write `tests/test_assessment.py`

### Block 4: Integration
- [ ] Refactor `services/analysis_service.py` (multi-mode: baseline / llm / llm_enriched)
- [ ] Extend `services/llm_service.py` `build_analysis_prompt` with context sections
- [ ] Update `POST /api/alerts/{id}/analyze` (mode parameter)
- [ ] Add mode selector to `alert_detail.html`
- [ ] Write `tests/test_integration.py`

### Block 5: Evaluation Framework
- [ ] Create `experiments/corpus/` with 20-30 labeled alerts
- [ ] Implement `experiments/run_evaluation.py`
- [ ] Implement `experiments/analyze_results.py`
- [ ] Run experiments (5 configurations)
- [ ] Generate summary tables and charts
- [ ] Write `experiments/README.md` (methodology, reproduction steps)

### Block 6: Engineering Quality
- [ ] Write `tests/conftest.py` (fixtures, factories, mocks)
- [ ] Write `tests/test_normalizer.py`
- [ ] Write `tests/test_llm_parser.py`
- [ ] Write `tests/test_api.py`
- [ ] Implement input sanitization in `llm_service.py`
- [ ] Create `.env.example`
- [ ] (Optional) Implement `services/audit.py` + migration

### Block 7: Documentation
- [ ] Rewrite `docs/architecture.md` (components, trust boundaries, data flows)
- [ ] Create `docs/algorithms.md`
- [ ] Create `docs/user-guide.md`
- [ ] Update `README.md`

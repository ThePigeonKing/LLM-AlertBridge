# Algorithms

## 1. Alert Normalization

**Module:** `backend/app/integrations/wazuh/normalizer.py`

**Input:** Raw Wazuh alert JSON (from OpenSearch)

**Output:** Unified normalized dict with stable field names

**Algorithm:**
```
function normalize_wazuh_alert(raw):
    rule  ← raw["rule"]   or {}
    agent ← raw["agent"]  or {}
    data  ← raw["data"]   or {}
    level ← int(rule["level"]) or 0

    severity ← map_severity(level)
        where: 0-3→info, 4-6→low, 7-9→medium, 10-12→high, 13-15→critical

    return {
        rule_id, rule_description, rule_level, severity,
        rule_groups, rule_mitre,
        agent_id, agent_name, agent_ip,
        timestamp, location,
        source_ip, source_port, destination_user, destination_ip,
        full_log
    }
```

**Complexity:** O(1) per alert — fixed field extraction

---

## 2. Enrichment Query Selection

**Module:** `backend/app/integrations/osquery/queries.py`

**Input:** `normalized_data.rule_groups` (list of strings)

**Output:** Dict of `{query_name: SQL}` pairs relevant to the alert type

**Algorithm:**
```
function select_queries_for_alert(normalized_data):
    groups ← normalized_data["rule_groups"]
    selected_type ← "default"

    for each group in groups:
        if group matches keywords for "authentication" → selected_type ← "authentication"
        if group matches keywords for "syscheck"       → selected_type ← "syscheck"
        if group matches keywords for "web"            → selected_type ← "web"
        if group matches keywords for "rootcheck"      → selected_type ← "rootcheck"
        if group matches keywords for "audit"          → selected_type ← "audit"
        break on first match

    return ALERT_TYPE_QUERIES[selected_type]
```

**Query mapping:**

| Alert type | Queries selected |
|---|---|
| authentication | running_processes, logged_in_users, open_connections |
| syscheck | running_processes, file_events, crontabs |
| web | running_processes, open_connections, listening_ports |
| rootcheck | running_processes, suid_binaries, crontabs |
| audit | running_processes, open_connections, logged_in_users |
| default | running_processes, open_connections, logged_in_users |

---

## 3. Temporal Correlation

**Module:** `backend/app/services/correlation_service.py`

**Input:** Alert A, time window W (default 15 min)

**Output:** List of alerts from the same host within [A.time - W, A.time + W]

**Algorithm:**
```
function temporal_correlation(alert, window_minutes=15):
    start ← alert.created_at - window_minutes
    end   ← alert.created_at + window_minutes

    related ← SELECT * FROM alerts
               WHERE agent_name = alert.agent_name
                 AND id != alert.id
                 AND created_at BETWEEN start AND end
               ORDER BY created_at
               LIMIT 20

    return [{alert_id, rule_id, severity, timestamp, time_delta_seconds} for each in related]
```

**Complexity:** O(n) where n = alerts in window (bounded by LIMIT 20)

---

## 4. Context Correlation

**Module:** `backend/app/services/correlation_service.py`

**Input:** Alert A, Enrichment E (osquery data)

**Output:** List of `ContextMatch` objects

**Algorithm:**
```
function context_correlation(alert, enrichment):
    matches ← []
    alert_src_ip   ← alert.normalized_data["source_ip"]
    alert_dst_user ← alert.normalized_data["destination_user"]
    alert_full_log ← alert.normalized_data["full_log"]

    for each row in enrichment.data["open_connections"]:
        if row.remote_address == alert_src_ip:
            matches.append(ContextMatch(type="exact", field="source_ip ↔ remote_address"))

    for each row in enrichment.data["logged_in_users"]:
        if row.user == alert_dst_user:
            matches.append(ContextMatch(type="exact", field="destination_user ↔ logged_in_user"))
        if row.host == alert_src_ip:
            matches.append(ContextMatch(type="ip_match", field="source_ip ↔ login_host"))

    for each row in enrichment.data["running_processes"]:
        if row.name IN alert_full_log:
            matches.append(ContextMatch(type="partial", field="process_name in full_log"))

    return matches
```

---

## 5. MITRE ATT&CK Chain Detection

**Module:** `backend/app/services/correlation_service.py`

**Input:** Alert A with MITRE tactic/technique, all alerts on the same host

**Output:** List of `MitreChain` objects (multi-alert tactic patterns)

**Algorithm:**
```
function mitre_correlation(alert):
    tactics ← alert.normalized_data["rule_mitre"]["tactic"]
    if tactics is empty: return []

    all_alerts ← SELECT * FROM alerts WHERE agent_name = alert.agent_name LIMIT 100

    tactic_map ← {}
    for each a in all_alerts:
        for each tactic in a.rule_mitre.tactic:
            tactic_map[tactic].alert_ids.append(a.id)
            tactic_map[tactic].technique_ids.update(a.rule_mitre.id)

    chains ← []
    for each tactic in alert's tactics:
        if tactic_map[tactic].alert_count > 1:
            chains.append(MitreChain(tactic, technique_ids, alert_ids, chain_length))

    return chains
```

---

## 6. Criticality Scoring (Baseline)

**Module:** `backend/app/services/baseline_service.py`

**Input:** Alert with severity and rule groups

**Output:** CriticalityAssessment (score 1-10, level, justification)

**Algorithm:**
```
SEVERITY_MAP = {critical: (9, "critical"), high: (7, "high"), medium: (5, "medium"),
                low: (3, "low"), info: (1, "info")}

function baseline_criticality(alert):
    (score, level) ← SEVERITY_MAP[alert.severity]
    justification ← "Based on Wazuh rule level {rule_level}"
    return CriticalityAssessment(score, level, justification)
```

---

## 7. Response Selection (Baseline)

**Module:** `backend/app/services/baseline_service.py`

**Input:** Alert with rule groups and criticality level

**Output:** ResponseRecommendation (action, urgency, steps)

**Taxonomy:**

| Action | When used |
|---|---|
| ignore | Info-level, routine events |
| monitor | Low-risk, known benign patterns |
| investigate | Medium-risk, requires analyst review |
| contain | High-risk, active threats |
| escalate | Critical, requires immediate team response |

**Algorithm:**
```
function baseline_response(alert, criticality_level):
    action ← GROUP_TO_ACTION[primary_rule_group] or "investigate"

    if criticality_level == "critical":
        action ← "escalate", urgency ← "immediate"
    elif criticality_level == "high":
        urgency ← "within_1h"
    elif criticality_level == "medium":
        urgency ← "within_24h"
    else:
        urgency ← "scheduled"

    return ResponseRecommendation(action, urgency, steps, escalation_needed)
```

---

## 8. LLM Prompt Construction

**Module:** `backend/app/services/llm_service.py`

**Input:** Normalized alert, optional enrichment, optional correlation

**Output:** Formatted prompt string for the LLM

**Algorithm:**
```
function build_analysis_prompt(alert_fields, enrichment_data?, correlation_data?):
    prompt ← analysis_template.format(
        rule_id, rule_description, severity, agent_name, timestamp,
        alert_data = sanitize(json.dumps(normalized_data))
    )

    if enrichment_data:
        prompt += "\n== Host Context ==\n"
        for each (query_name, rows) in enrichment_data:
            prompt += format_rows(query_name, rows[:15])

    if correlation_data:
        prompt += "\n== Correlated Events ==\n"
        prompt += correlation_summary + temporal + context_matches + mitre_chains

    return prompt
```

**Security:** All input fields pass through `_sanitize()` which:
- Truncates fields > 4KB
- Strips prompt-injection patterns via regex

---

## 9. LLM Response Parsing

**Module:** `backend/app/services/llm_service.py`

**Input:** Raw LLM text output

**Output:** Validated `AnalysisResult` object

**Algorithm:**
```
function parse_llm_response(raw_text):
    text ← strip(raw_text)

    # Attempt 1: direct JSON parse
    try: return validate(json.loads(text))

    # Attempt 2: extract from markdown fences
    match ← regex_search("```json?\s*(.*?)```", text)
    if match: try: return validate(json.loads(match[1]))

    # Fallback: treat as plain text summary
    return AnalysisResult(summary=text[:500], confidence_note="WARNING: unparsed")
```

**Validation:** Pydantic validators clamp score to 1-10, normalize level to valid values, validate action against taxonomy.

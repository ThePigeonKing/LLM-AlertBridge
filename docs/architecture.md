# Architecture

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Yandex Cloud (10.128.0.0/24)                            │
│                                                                             │
│  ┌─────────────────────────────── core-compute ──────────────────────────┐  │
│  │                                                                       │  │
│  │  ┌───────────────┐   ┌───────────────────────────────────────────┐   │  │
│  │  │  PostgreSQL    │   │         FastAPI Backend (:8000)           │   │  │
│  │  │  (:5432)       │   │                                           │   │  │
│  │  │  ┌──────────┐  │   │  ┌──────────────┐  ┌──────────────────┐  │   │  │
│  │  │  │ alerts   │  │◄──┤  │ Alert Service │  │ Analysis Service │  │   │  │
│  │  │  │ analyses │  │   │  └──────┬───────┘  └───────┬──────────┘  │   │  │
│  │  │  │enrichments│  │   │         │                  │             │   │  │
│  │  │  └──────────┘  │   │  ┌──────▼───────┐  ┌───────▼──────────┐  │   │  │
│  │  └───────────────┘   │  │ Wazuh Client  │  │ Enrichment Svc   │  │   │  │
│  │                       │  │ (Indexer API) │  │ (osquery client) │  │   │  │
│  │  ┌───────────────┐   │  └──────┬───────┘  └───────┬──────────┘  │   │  │
│  │  │ Wazuh Stack   │   │         │                  │             │   │  │
│  │  │ ┌───────────┐ │   │  ┌──────▼───────┐  ┌───────▼──────────┐  │   │  │
│  │  │ │ Indexer   │◄├───┤  │ Correlation  │  │ Baseline Service │  │   │  │
│  │  │ │ (OS:9200) │ │   │  │ Service      │  │ (rule-based)     │  │   │  │
│  │  │ ├───────────┤ │   │  └──────────────┘  └──────────────────┘  │   │  │
│  │  │ │ Manager   │ │   │                                           │   │  │
│  │  │ │ (:55000)  │ │   │  ┌──────────────┐  ┌──────────────────┐  │   │  │
│  │  │ ├───────────┤ │   │  │ LLM Service  │  │ Jinja2 Templates │  │   │  │
│  │  │ │ Dashboard │ │   │  │ (prompts +   │  │ (alerts, detail, │  │   │  │
│  │  │ │ (:443)    │ │   │  │  parsing)    │  │  analysis, ...)  │  │   │  │
│  │  │ └───────────┘ │   │  └──────┬───────┘  └──────────────────┘  │   │  │
│  │  └───────────────┘   │         │                                 │   │  │
│  │                       └─────────┼─────────────────────────────────┘   │  │
│  └───────────────────────────────┼───────────────────────────────────────┘  │
│                                   │                                         │
│  ┌──────────────┐  ┌──────────────┤──────────────┐                          │
│  │ target-1     │  │ target-2     │              │                          │
│  │ (.35)        │  │ (.14)        │              │                          │
│  │ ┌──────────┐ │  │ ┌──────────┐ │              │                          │
│  │ │ Wazuh    │ │  │ │ Wazuh    │ │              │                          │
│  │ │ agent    │ │  │ │ agent    │ │              │                          │
│  │ │ osqueryd │ │  │ │ osqueryd │ │              │                          │
│  │ └──────────┘ │  │ └──────────┘ │              │                          │
│  └──────────────┘  └──────────────┘              │                          │
│                                                   │                          │
│  ┌──────────────┐  ┌──────────────┐              │                          │
│  │ attacker     │  │ openvpn      │              │                          │
│  │ (.36)        │  │ (.7)         │              │                          │
│  └──────────────┘  └──────┬───────┘              │                          │
└───────────────────────────┼──────────────────────┼──────────────────────────┘
                            │ VPN tunnel           │ OpenAI-compat API
                   ┌────────▼──────────────────────▼───────┐
                   │        Analyst Laptop                  │
                   │  ┌──────────────┐  ┌────────────────┐ │
                   │  │ Browser      │  │ LM Studio      │ │
                   │  │ → :8000/alerts│  │ (:1234/v1)     │ │
                   │  └──────────────┘  └────────────────┘ │
                   └───────────────────────────────────────┘
```

## Trust Boundaries

| Boundary | What crosses it | Protection |
|---|---|---|
| VPN tunnel (laptop ↔ cloud) | Alert data to LLM, analysis results to browser | WireGuard/OpenVPN encryption |
| Backend ↔ Wazuh Indexer | Alert queries (HTTPS :9200) | TLS + basic auth |
| Backend ↔ LM Studio | Prompt + response (HTTP :1234) | VPN encapsulation; input sanitization |
| Backend ↔ PostgreSQL | SQL queries (:5432) | Docker internal network |
| Backend ↔ osquery on targets | SSH + osquery SQL | SSH key auth |

## Data Flow

### Alert Lifecycle

```
1. Security event occurs on target host
       │
2. Wazuh agent detects and forwards to Wazuh Manager
       │
3. Manager processes, enriches with rules, stores in Indexer (OpenSearch)
       │
4. Analyst triggers "Sync from Wazuh" in UI
       │
5. Backend fetches from Indexer → normalizes → dedupes by wazuh_id → stores in PostgreSQL
       │
6. Alert appears in UI with status=PENDING
       │
7. [Optional] Analyst clicks "Enrich with osquery"
       │  Backend → SSH → osquery on target host → stores Enrichment
       │
8. Analyst selects mode and clicks "Analyze"
       │
       ├─ BASELINE: rule-based assessment (no LLM)
       ├─ LLM: prompt from alert data → LM Studio → parse response
       └─ LLM_ENRICHED: auto-enrich → correlate → extended prompt → LM Studio → parse
       │
9. Analysis persisted in PostgreSQL, displayed in UI
```

### Analysis Modes

| Mode | Data used | LLM call | Use case |
|---|---|---|---|
| `baseline` | Alert metadata only | No | Fast triage, evaluation baseline |
| `llm` | Alert data | Yes | Standard LLM analysis |
| `llm_enriched` | Alert + osquery context + correlation | Yes | Full enriched analysis |

## Sequence Diagram: LLM-Enriched Analysis

```
Analyst          UI              API             Enrichment       Correlation     LLM Service      LM Studio
  │               │               │               │                │               │               │
  ├──click───────►│               │               │                │               │               │
  │               ├──POST /analyze?mode=llm_enriched              │               │               │
  │               │               ├──get_enrichment()             │               │               │
  │               │               │  (check existing)             │               │               │
  │               │               ├──enrich_alert()──►│           │               │               │
  │               │               │               ├──SSH/osquery──┤               │               │
  │               │               │               │◄──host data───┤               │               │
  │               │               │◄──enrichment───┤              │               │               │
  │               │               ├──correlate_alert()────────────►│               │               │
  │               │               │               │               ├──temporal───► │               │
  │               │               │               │               ├──context────► │               │
  │               │               │               │               ├──MITRE─────► │               │
  │               │               │◄──correlation──────────────────┤              │               │
  │               │               ├──build_prompt(alert+enrichment+correlation)──►│               │
  │               │               │               │               │              ├──chat.create──►│
  │               │               │               │               │              │◄──JSON────────┤
  │               │               │               │               │◄──parsed──────┤               │
  │               │               ├──save Analysis │               │               │               │
  │               │◄──HTML partial─┤               │               │               │               │
  │◄──rendered─────┤               │               │               │               │               │
```

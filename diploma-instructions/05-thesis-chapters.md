# Step 5: Thesis Chapter Outline and Content Mapping

## For Полищук (your thesis)

**Topic:** Программный модуль оценки событий ИБ и выбора способа реагирования на инциденты с использованием LLM

### Chapter outline

#### Введение (Introduction)
- Problem: SOC alert fatigue, manual triage bottleneck
- Goal: develop an intelligent assessment module using local LLM
- Scope: assessment + response recommendation + evaluation

#### Глава 1: Анализ предметной области (Domain Analysis)
- 1.1 SIEM systems and alert triage in SOC
- 1.2 LLM applications in cybersecurity (literature review — **you do this separately**)
- 1.3 Local vs cloud LLM deployment for security data
- 1.4 Problem statement and requirements

#### Глава 2: Проектирование модуля (Module Design)
- 2.1 System architecture — use `docs/architecture.md` diagrams
- 2.2 Assessment methodology — criticality scoring, response taxonomy
- 2.3 LLM prompt engineering approach — reference `prompts/system.txt`
- 2.4 Multi-mode analysis design (baseline / LLM / LLM + enrichment)
- 2.5 Input sanitization and security considerations

#### Глава 3: Реализация (Implementation)
- 3.1 Technology stack justification — reference README tech stack table
- 3.2 Alert normalization — reference `docs/algorithms.md` §1
- 3.3 LLM integration — `lm_studio/client.py`, prompt construction, response parsing
- 3.4 Baseline assessment — `baseline_service.py` logic
- 3.5 Analysis pipeline — `analysis_service.py` multi-mode orchestration
- 3.6 Web interface — show screenshots of alert detail page

#### Глава 4: Экспериментальная оценка (Experimental Evaluation)
- 4.1 Methodology — corpus, ground truth, metrics
- 4.2 Results — paste `comparison_table.md` content
- 4.3 Per-category analysis
- 4.4 Multi-model comparison (if done)
- 4.5 Discussion — strengths, weaknesses, limitations

#### Заключение (Conclusion)
- Summary of contributions
- Limitations
- Future work (interactive dialogue, feedback loop, larger corpus)

---

## For Ковригина (your girlfriend's thesis)

**Topic:** Подсистема контекстного обогащения и корреляции данных

### Chapter outline

#### Введение
- Same problem framing, focused on context gap in alert triage

#### Глава 1: Анализ предметной области
- 1.1 Context enrichment in security monitoring
- 1.2 osquery as a host telemetry source
- 1.3 Event correlation methods
- 1.4 Requirements for the enrichment subsystem

#### Глава 2: Проектирование подсистемы
- 2.1 System architecture — use `docs/architecture.md`, focus on enrichment flow
- 2.2 osquery query catalog design — reference `docs/algorithms.md` §2
- 2.3 Correlation algorithms — temporal, context-based, MITRE chain (§3-5)
- 2.4 Data model for enrichment storage

#### Глава 3: Реализация
- 3.1 osquery client (SSH + mock transports) — `osquery/client.py`
- 3.2 Query selection algorithm — `osquery/queries.py`
- 3.3 Enrichment service — `enrichment_service.py`
- 3.4 Correlation engine — `correlation_service.py`
- 3.5 Integration with analysis module
- 3.6 UI for enrichment and correlation display

#### Глава 4: Экспериментальная оценка
- 4.1 Methodology — same corpus, focus on enrichment impact
- 4.2 Results — compare LLM vs LLM + enrichment
- 4.3 Context match analysis — which enrichment data improved analysis?
- 4.4 Discussion

#### Заключение
- Contributions
- Limitations (mock vs real osquery, limited target hosts)
- Future work (more data sources, automated enrichment triggers)

---

## Shared content between both theses

The following sections can be written once and adapted:
- System architecture overview (different focus per thesis)
- Test environment description (Yandex Cloud setup)
- Evaluation methodology (same corpus and metrics)
- Technology stack justification

**Important:** The theses must NOT be identical. Each focuses on a different subsystem within the same overall system. Use different diagrams, emphasize different code modules, and frame the contribution differently.

## Source material from the codebase

| Thesis section | Source in codebase |
|---|---|
| Architecture diagrams | `docs/architecture.md` |
| Algorithm descriptions | `docs/algorithms.md` |
| Evaluation results | `experiments/results/comparison_table.md` |
| Code fragments | Relevant `.py` files (include key functions, not entire files) |
| UI screenshots | Run the app and take screenshots of alert list, detail page, analysis result |
| Test results | `uv run pytest -v` output — shows 63 passing tests |

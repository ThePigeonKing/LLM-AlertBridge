"""Multi-mode alert analysis pipeline.

Modes:
    baseline       — deterministic rule-based assessment (no LLM)
    llm            — LLM analysis using only alert data
    llm_enriched   — LLM analysis with osquery enrichment + correlation
"""

import enum
import logging
import time
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.integrations.lm_studio.client import lm_studio_client
from backend.app.integrations.wazuh.normalizer import alert_data_for_prompt
from backend.app.models.alert import AlertStatus
from backend.app.models.analysis import Analysis
from backend.app.services import alert_service
from backend.app.services.baseline_service import baseline_assessment
from backend.app.services.llm_service import (
    build_analysis_prompt,
    get_system_prompt,
    parse_llm_response,
)

logger = logging.getLogger(__name__)

MAX_RETRIES = 2


class AnalysisMode(enum.StrEnum):
    BASELINE = "baseline"
    LLM = "llm"
    LLM_ENRICHED = "llm_enriched"


def _build_analysis_record(
    alert_id: uuid.UUID,
    parsed: "AnalysisResult",  # noqa: F821
    *,
    mode: AnalysisMode,
    raw_response: str = "",
    model_name: str = "",
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
    processing_time_ms: int = 0,
) -> Analysis:
    return Analysis(
        alert_id=alert_id,
        summary=parsed.summary,
        hypothesis=parsed.hypothesis,
        possible_causes=parsed.possible_causes,
        key_indicators=parsed.key_indicators,
        recommended_checks=parsed.recommended_checks,
        confidence_note=parsed.confidence_note,
        criticality_score=parsed.criticality.score,
        criticality_level=parsed.criticality.level,
        criticality_justification=parsed.criticality.justification,
        response_action=parsed.response.action,
        response_urgency=parsed.response.urgency,
        analysis_mode=mode.value,
        raw_response=raw_response,
        model_name=model_name,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        processing_time_ms=processing_time_ms,
    )


async def analyze_alert(
    session: AsyncSession,
    alert_id: uuid.UUID,
    mode: AnalysisMode = AnalysisMode.LLM_ENRICHED,
) -> Analysis:
    """Run the analysis pipeline for a single alert in the specified mode."""
    alert = await alert_service.get_alert(session, alert_id)
    if alert is None:
        raise ValueError(f"Alert {alert_id} not found")

    if mode == AnalysisMode.BASELINE:
        return await _run_baseline(session, alert)
    elif mode == AnalysisMode.LLM:
        return await _run_llm(session, alert, mode=AnalysisMode.LLM)
    else:
        return await _run_llm_enriched(session, alert)


async def _run_baseline(session: AsyncSession, alert) -> Analysis:
    start = time.monotonic()
    parsed = baseline_assessment(alert)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    analysis = _build_analysis_record(
        alert.id, parsed,
        mode=AnalysisMode.BASELINE,
        raw_response="[baseline — no LLM call]",
        model_name="baseline_rules",
        processing_time_ms=elapsed_ms,
    )
    session.add(analysis)
    alert.status = AlertStatus.COMPLETED
    await session.commit()
    return analysis


async def _run_llm(
    session: AsyncSession,
    alert,
    *,
    mode: AnalysisMode,
    enrichment_data: dict | None = None,
    correlation_data: dict | None = None,
) -> Analysis:
    alert.status = AlertStatus.ANALYZING
    await session.commit()

    normalized = alert.normalized_data
    user_prompt = build_analysis_prompt(
        rule_id=alert.rule_id,
        rule_description=alert.rule_description,
        severity=alert.severity,
        agent_name=alert.agent_name,
        timestamp=normalized.get("timestamp", ""),
        alert_data=alert_data_for_prompt(normalized),
        enrichment_data=enrichment_data,
        correlation_data=correlation_data,
    )
    system_prompt = get_system_prompt()

    last_error: Exception | None = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            start = time.monotonic()
            result = lm_studio_client.analyze(user_prompt, system_prompt)
            elapsed_ms = int((time.monotonic() - start) * 1000)

            parsed = parse_llm_response(result["content"])

            analysis = _build_analysis_record(
                alert.id, parsed,
                mode=mode,
                raw_response=result["content"],
                model_name=result.get("model", ""),
                prompt_tokens=result.get("prompt_tokens"),
                completion_tokens=result.get("completion_tokens"),
                processing_time_ms=elapsed_ms,
            )
            session.add(analysis)
            alert.status = AlertStatus.COMPLETED
            await session.commit()

            logger.info(
                "Alert %s analyzed (mode=%s) in %dms (attempt %d)",
                alert.id, mode, elapsed_ms, attempt,
            )
            return analysis

        except Exception as e:
            last_error = e
            logger.warning(
                "Analysis attempt %d/%d failed for alert %s: %s",
                attempt, MAX_RETRIES, alert.id, e,
            )

    alert.status = AlertStatus.FAILED
    await session.commit()
    raise RuntimeError(
        f"Analysis failed after {MAX_RETRIES} attempts for alert {alert.id}"
    ) from last_error


async def _run_llm_enriched(session: AsyncSession, alert) -> Analysis:
    from backend.app.services.correlation_service import correlate_alert
    from backend.app.services.enrichment_service import enrich_alert, get_enrichment

    enrichment = await get_enrichment(session, alert.id)
    if enrichment is None:
        enrichment = await enrich_alert(session, alert.id)

    correlation = await correlate_alert(session, alert.id, enrichment=enrichment)

    return await _run_llm(
        session,
        alert,
        mode=AnalysisMode.LLM_ENRICHED,
        enrichment_data=enrichment.data,
        correlation_data=correlation.model_dump(),
    )

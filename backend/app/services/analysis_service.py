import logging
import time
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.integrations.lm_studio.client import lm_studio_client
from backend.app.integrations.wazuh.normalizer import alert_data_for_prompt
from backend.app.models.alert import AlertStatus
from backend.app.models.analysis import Analysis
from backend.app.services import alert_service
from backend.app.services.llm_service import (
    build_analysis_prompt,
    get_system_prompt,
    parse_llm_response,
)

logger = logging.getLogger(__name__)

MAX_RETRIES = 2


async def analyze_alert(
    session: AsyncSession,
    alert_id: uuid.UUID,
) -> Analysis:
    """Run the full analysis pipeline for a single alert.

    1. Load alert from DB
    2. Set status to ANALYZING
    3. Build prompt
    4. Call LM Studio
    5. Parse and validate response
    6. Store Analysis record
    7. Update alert status
    """
    alert = await alert_service.get_alert(session, alert_id)
    if alert is None:
        raise ValueError(f"Alert {alert_id} not found")

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
    )
    system_prompt = get_system_prompt()

    last_error: Exception | None = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            start = time.monotonic()
            result = lm_studio_client.analyze(user_prompt, system_prompt)
            elapsed_ms = int((time.monotonic() - start) * 1000)

            parsed = parse_llm_response(result["content"])

            analysis = Analysis(
                alert_id=alert.id,
                summary=parsed.summary,
                hypothesis=parsed.hypothesis,
                possible_causes=parsed.possible_causes,
                key_indicators=parsed.key_indicators,
                recommended_checks=parsed.recommended_checks,
                confidence_note=parsed.confidence_note,
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
                "Alert %s analyzed in %dms (attempt %d)",
                alert_id, elapsed_ms, attempt,
            )
            return analysis

        except Exception as e:
            last_error = e
            logger.warning(
                "Analysis attempt %d/%d failed for alert %s: %s",
                attempt, MAX_RETRIES, alert_id, e,
            )

    alert.status = AlertStatus.FAILED
    await session.commit()
    raise RuntimeError(
        f"Analysis failed after {MAX_RETRIES} attempts for alert {alert_id}"
    ) from last_error

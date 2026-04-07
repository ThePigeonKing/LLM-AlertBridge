import logging
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.integrations.wazuh.client import wazuh_client
from backend.app.integrations.wazuh.normalizer import (
    extract_alert_fields,
    normalize_wazuh_alert,
)
from backend.app.models.alert import Alert, AlertStatus

logger = logging.getLogger(__name__)


async def ingest_from_wazuh(
    session: AsyncSession,
    limit: int = 50,
) -> list[Alert]:
    """Fetch new alerts from Wazuh, normalize, and store them.

    Skips alerts that already exist in the database (matched by wazuh_id).
    """
    raw_alerts = await wazuh_client.get_alerts(limit=limit)
    logger.info("Fetched %d alerts from Wazuh", len(raw_alerts))

    new_alerts: list[Alert] = []

    for raw in raw_alerts:
        wazuh_id = raw.get("id") or raw.get("_id")
        if not wazuh_id:
            continue

        existing = await session.execute(
            select(Alert).where(Alert.wazuh_id == str(wazuh_id))
        )
        if existing.scalar_one_or_none() is not None:
            continue

        normalized = normalize_wazuh_alert(raw)
        fields = extract_alert_fields(raw)

        alert = Alert(
            wazuh_id=str(wazuh_id),
            raw_data=raw,
            normalized_data=normalized,
            severity=fields["severity"],
            rule_id=fields["rule_id"],
            rule_description=fields["rule_description"],
            agent_name=fields["agent_name"],
            status=AlertStatus.PENDING,
        )
        session.add(alert)
        new_alerts.append(alert)

    if new_alerts:
        await session.commit()
        logger.info("Stored %d new alerts", len(new_alerts))

    return new_alerts


async def get_alert(
    session: AsyncSession, alert_id: uuid.UUID
) -> Alert | None:
    result = await session.execute(
        select(Alert)
        .options(selectinload(Alert.analyses))
        .where(Alert.id == alert_id)
    )
    return result.scalar_one_or_none()


async def list_alerts(
    session: AsyncSession,
    page: int = 1,
    size: int = 20,
    status_filter: AlertStatus | None = None,
) -> tuple[list[Alert], int]:
    """Return a paginated list of alerts and total count."""
    query = select(Alert).order_by(Alert.created_at.desc())
    count_query = select(func.count()).select_from(Alert)

    if status_filter is not None:
        query = query.where(Alert.status == status_filter)
        count_query = count_query.where(Alert.status == status_filter)

    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    offset = (page - 1) * size
    result = await session.execute(query.offset(offset).limit(size))
    alerts = list(result.scalars().all())

    return alerts, total

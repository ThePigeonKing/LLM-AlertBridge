"""Orchestrates host context enrichment for a given alert via osquery."""

import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.integrations.osquery.client import OsqueryError, osquery_client
from backend.app.integrations.osquery.queries import select_queries_for_alert
from backend.app.models.enrichment import Enrichment
from backend.app.services import alert_service

logger = logging.getLogger(__name__)


async def enrich_alert(
    session: AsyncSession,
    alert_id: uuid.UUID,
    *,
    override_data: dict | None = None,
) -> Enrichment:
    """Collect host context for an alert and persist the result.

    If *override_data* is provided (e.g. simulated enrichment from the
    evaluation corpus), it is stored directly without querying osquery.
    """
    alert = await alert_service.get_alert(session, alert_id)
    if alert is None:
        raise ValueError(f"Alert {alert_id} not found")

    host = alert.agent_name
    normalized = alert.normalized_data

    if override_data is not None:
        enrichment = Enrichment(
            alert_id=alert.id,
            host=host,
            data=override_data,
            queries_run=list(override_data.keys()),
            queries_failed=[],
        )
        session.add(enrichment)
        await session.commit()
        return enrichment

    relevant = select_queries_for_alert(normalized)
    results: dict = {}
    failed: list[str] = []

    host_address = normalized.get("agent_ip") or host

    for qname, qsql in relevant.items():
        try:
            rows = await osquery_client.query(host_address, qsql)
            results[qname] = rows
        except OsqueryError as exc:
            logger.warning("osquery %s on %s failed: %s", qname, host_address, exc)
            results[qname] = []
            failed.append(qname)

    enrichment = Enrichment(
        alert_id=alert.id,
        host=host,
        data=results,
        queries_run=list(relevant.keys()),
        queries_failed=failed,
    )
    session.add(enrichment)
    await session.commit()

    logger.info(
        "Enriched alert %s from host %s: %d queries, %d failed",
        alert_id, host, len(relevant), len(failed),
    )
    return enrichment


async def get_enrichment(
    session: AsyncSession,
    alert_id: uuid.UUID,
) -> Enrichment | None:
    """Return the latest enrichment for an alert, if any."""
    result = await session.execute(
        select(Enrichment)
        .where(Enrichment.alert_id == alert_id)
        .order_by(Enrichment.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()

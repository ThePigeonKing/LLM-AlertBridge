"""Alert correlation engine: temporal, context-based, and MITRE chain analysis."""

import logging
import uuid
from collections import defaultdict
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config import settings
from backend.app.models.alert import Alert
from backend.app.models.enrichment import Enrichment
from backend.app.schemas.correlation import (
    ContextMatch,
    CorrelatedAlert,
    CorrelationResult,
    MitreChain,
)

logger = logging.getLogger(__name__)


async def correlate_alert(
    session: AsyncSession,
    alert_id: uuid.UUID,
    enrichment: Enrichment | None = None,
) -> CorrelationResult:
    """Run all correlation strategies for a given alert."""
    result = await session.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise ValueError(f"Alert {alert_id} not found")

    temporal = await _temporal_correlation(session, alert)
    context = _context_correlation(alert, enrichment) if enrichment else []
    mitre = await _mitre_correlation(session, alert)

    parts: list[str] = []
    if temporal:
        parts.append(f"{len(temporal)} related alert(s) on the same host within time window")
    if context:
        parts.append(f"{len(context)} host-context match(es)")
    if mitre:
        tactics = ", ".join(c.tactic for c in mitre)
        parts.append(f"MITRE chain(s): {tactics}")
    summary = "; ".join(parts) if parts else "No correlations found"

    return CorrelationResult(
        alert_id=alert_id,
        temporal_alerts=temporal,
        context_matches=context,
        mitre_chains=mitre,
        correlation_summary=summary,
    )


async def _temporal_correlation(
    session: AsyncSession,
    alert: Alert,
) -> list[CorrelatedAlert]:
    """Find alerts from the same host within a configurable time window."""
    window = timedelta(minutes=settings.correlation_time_window_minutes)
    start = alert.created_at - window
    end = alert.created_at + window

    result = await session.execute(
        select(Alert)
        .where(
            Alert.agent_name == alert.agent_name,
            Alert.id != alert.id,
            Alert.created_at.between(start, end),
        )
        .order_by(Alert.created_at)
        .limit(20)
    )
    related = result.scalars().all()

    return [
        CorrelatedAlert(
            alert_id=a.id,
            rule_id=a.rule_id,
            rule_description=a.rule_description,
            severity=a.severity,
            timestamp=a.created_at,
            time_delta_seconds=int((a.created_at - alert.created_at).total_seconds()),
        )
        for a in related
    ]


def _context_correlation(
    alert: Alert,
    enrichment: Enrichment,
) -> list[ContextMatch]:
    """Cross-reference alert fields with osquery enrichment data."""
    matches: list[ContextMatch] = []
    normalized = alert.normalized_data
    enrichment_data = enrichment.data or {}

    alert_src_ip = normalized.get("source_ip", "")
    alert_dst_user = normalized.get("destination_user", "")
    alert_full_log = normalized.get("full_log", "")

    for row in enrichment_data.get("open_connections", []):
        remote = row.get("remote_address", "")
        if alert_src_ip and remote and alert_src_ip == remote:
            matches.append(ContextMatch(
                query_name="open_connections",
                matched_field="source_ip ↔ remote_address",
                alert_value=alert_src_ip,
                host_value=row,
                match_type="exact",
            ))

    for row in enrichment_data.get("logged_in_users", []):
        user = row.get("user", "")
        host = row.get("host", "")
        if alert_dst_user and user and alert_dst_user == user:
            matches.append(ContextMatch(
                query_name="logged_in_users",
                matched_field="destination_user ↔ logged_in_user",
                alert_value=alert_dst_user,
                host_value=row,
                match_type="exact",
            ))
        if alert_src_ip and host and alert_src_ip == host:
            matches.append(ContextMatch(
                query_name="logged_in_users",
                matched_field="source_ip ↔ login_host",
                alert_value=alert_src_ip,
                host_value=row,
                match_type="ip_match",
            ))

    for row in enrichment_data.get("running_processes", []):
        cmdline = row.get("cmdline", "")
        process_name = row.get("name", "")
        if cmdline and alert_full_log and process_name in alert_full_log:
            matches.append(ContextMatch(
                query_name="running_processes",
                matched_field="process_name in full_log",
                alert_value=process_name,
                host_value=row,
                match_type="partial",
            ))

    return matches


async def _mitre_correlation(
    session: AsyncSession,
    alert: Alert,
) -> list[MitreChain]:
    """Group alerts by shared MITRE ATT&CK tactic on the same host."""
    mitre = alert.normalized_data.get("rule_mitre", {})
    tactics = mitre.get("tactic", [])
    if not tactics:
        return []

    result = await session.execute(
        select(Alert)
        .where(Alert.agent_name == alert.agent_name)
        .order_by(Alert.created_at)
        .limit(100)
    )
    all_alerts = result.scalars().all()

    tactic_map: dict[str, dict] = defaultdict(lambda: {"technique_ids": set(), "alert_ids": []})
    for a in all_alerts:
        a_mitre = a.normalized_data.get("rule_mitre", {})
        for tactic in a_mitre.get("tactic", []):
            tactic_map[tactic]["alert_ids"].append(a.id)
            for tid in a_mitre.get("id", []):
                tactic_map[tactic]["technique_ids"].add(tid)

    chains: list[MitreChain] = []
    for tactic in tactics:
        info = tactic_map.get(tactic)
        if info and len(info["alert_ids"]) > 1:
            chains.append(MitreChain(
                tactic=tactic,
                technique_ids=sorted(info["technique_ids"]),
                alert_ids=info["alert_ids"],
                chain_length=len(info["alert_ids"]),
            ))

    return chains

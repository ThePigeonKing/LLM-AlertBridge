import uuid
from datetime import datetime

from pydantic import BaseModel


class CorrelatedAlert(BaseModel):
    alert_id: uuid.UUID
    rule_id: str
    rule_description: str
    severity: str
    timestamp: datetime
    time_delta_seconds: int


class ContextMatch(BaseModel):
    query_name: str
    matched_field: str
    alert_value: str
    host_value: dict
    match_type: str  # "exact" | "partial" | "ip_match"


class MitreChain(BaseModel):
    tactic: str
    technique_ids: list[str]
    alert_ids: list[uuid.UUID]
    chain_length: int


class CorrelationResult(BaseModel):
    alert_id: uuid.UUID
    temporal_alerts: list[CorrelatedAlert] = []
    context_matches: list[ContextMatch] = []
    mitre_chains: list[MitreChain] = []
    correlation_summary: str = ""

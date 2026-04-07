import uuid
from datetime import datetime

from pydantic import BaseModel

from backend.app.models.alert import AlertStatus


class AlertCreate(BaseModel):
    wazuh_id: str | None = None
    raw_data: dict
    normalized_data: dict
    severity: str = "unknown"
    rule_id: str = ""
    rule_description: str = ""
    agent_name: str = ""


class AlertBrief(BaseModel):
    id: uuid.UUID
    wazuh_id: str | None
    severity: str
    rule_id: str
    rule_description: str
    agent_name: str
    status: AlertStatus
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertRead(AlertBrief):
    raw_data: dict
    normalized_data: dict
    updated_at: datetime

    model_config = {"from_attributes": True}


class AlertList(BaseModel):
    items: list[AlertBrief]
    total: int
    page: int
    size: int

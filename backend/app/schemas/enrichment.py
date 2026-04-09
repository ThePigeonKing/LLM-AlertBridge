import uuid
from datetime import datetime

from pydantic import BaseModel


class EnrichmentRead(BaseModel):
    id: uuid.UUID
    alert_id: uuid.UUID
    host: str
    data: dict
    queries_run: list[str]
    queries_failed: list[str]
    created_at: datetime

    model_config = {"from_attributes": True}

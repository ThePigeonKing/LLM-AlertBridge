import uuid
from datetime import datetime

from pydantic import BaseModel


class AnalysisResult(BaseModel):
    """The structured JSON output expected from the LLM."""

    summary: str = ""
    hypothesis: str = ""
    possible_causes: list[str] = []
    key_indicators: list[str] = []
    recommended_checks: list[str] = []
    confidence_note: str = ""


class AnalysisRead(AnalysisResult):
    id: uuid.UUID
    alert_id: uuid.UUID
    raw_response: str
    model_name: str
    prompt_tokens: int | None
    completion_tokens: int | None
    processing_time_ms: int
    created_at: datetime

    model_config = {"from_attributes": True}

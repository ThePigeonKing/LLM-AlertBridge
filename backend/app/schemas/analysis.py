import uuid
from datetime import datetime

from pydantic import BaseModel, field_validator


class CriticalityAssessment(BaseModel):
    score: int = 5
    level: str = "medium"
    justification: str = ""
    contributing_factors: list[str] = []

    @field_validator("score")
    @classmethod
    def clamp_score(cls, v: int) -> int:
        return max(1, min(10, v))

    @field_validator("level")
    @classmethod
    def normalize_level(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in ("info", "low", "medium", "high", "critical"):
            return "medium"
        return v


RESPONSE_ACTIONS = ("ignore", "monitor", "investigate", "contain", "escalate")
URGENCY_LEVELS = ("immediate", "within_1h", "within_24h", "scheduled")


class ResponseRecommendation(BaseModel):
    action: str = "investigate"
    urgency: str = "within_24h"
    specific_steps: list[str] = []
    escalation_needed: bool = False
    escalation_reason: str | None = None

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in RESPONSE_ACTIONS:
            return "investigate"
        return v

    @field_validator("urgency")
    @classmethod
    def validate_urgency(cls, v: str) -> str:
        v = v.lower().strip().replace(" ", "_")
        if v not in URGENCY_LEVELS:
            return "within_24h"
        return v


class AnalysisResult(BaseModel):
    """The structured JSON output expected from the LLM."""

    summary: str = ""
    hypothesis: str = ""
    possible_causes: list[str] = []
    key_indicators: list[str] = []
    recommended_checks: list[str] = []
    confidence_note: str = ""
    criticality: CriticalityAssessment = CriticalityAssessment()
    response: ResponseRecommendation = ResponseRecommendation()


class AnalysisRead(BaseModel):
    id: uuid.UUID
    alert_id: uuid.UUID
    summary: str
    hypothesis: str
    possible_causes: list[str]
    key_indicators: list[str]
    recommended_checks: list[str]
    confidence_note: str
    criticality_score: int | None
    criticality_level: str | None
    criticality_justification: str | None
    response_action: str | None
    response_urgency: str | None
    analysis_mode: str | None
    raw_response: str
    model_name: str
    prompt_tokens: int | None
    completion_tokens: int | None
    processing_time_ms: int
    created_at: datetime

    model_config = {"from_attributes": True}

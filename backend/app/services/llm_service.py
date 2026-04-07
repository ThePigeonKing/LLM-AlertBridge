import json
import logging
import re
from pathlib import Path

from backend.app.schemas.analysis import AnalysisResult

logger = logging.getLogger(__name__)

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"

_system_prompt: str | None = None
_analysis_template: str | None = None


def _load_prompt(name: str) -> str:
    return (PROMPTS_DIR / name).read_text(encoding="utf-8").strip()


def get_system_prompt() -> str:
    global _system_prompt
    if _system_prompt is None:
        _system_prompt = _load_prompt("system.txt")
    return _system_prompt


def get_analysis_template() -> str:
    global _analysis_template
    if _analysis_template is None:
        _analysis_template = _load_prompt("analysis.txt")
    return _analysis_template


def build_analysis_prompt(
    *,
    rule_id: str,
    rule_description: str,
    severity: str,
    agent_name: str,
    timestamp: str,
    alert_data: str,
) -> str:
    template = get_analysis_template()
    return template.format(
        rule_id=rule_id,
        rule_description=rule_description,
        severity=severity,
        agent_name=agent_name,
        timestamp=timestamp,
        alert_data=alert_data,
    )


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```")


def parse_llm_response(raw: str) -> AnalysisResult:
    """Parse the LLM response into a validated AnalysisResult.

    Handles both raw JSON and JSON wrapped in markdown code fences.
    """
    text = raw.strip()

    try:
        data = json.loads(text)
        return AnalysisResult.model_validate(data)
    except (json.JSONDecodeError, ValueError):
        pass

    match = _JSON_FENCE_RE.search(text)
    if match:
        try:
            data = json.loads(match.group(1))
            return AnalysisResult.model_validate(data)
        except (json.JSONDecodeError, ValueError):
            pass

    logger.warning("Failed to parse LLM response as JSON, returning raw text as summary")
    return AnalysisResult(
        summary=text[:500],
        confidence_note="WARNING: LLM response could not be parsed as structured JSON.",
    )

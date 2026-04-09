import json
import logging
import re
from pathlib import Path
from typing import Any

from backend.app.schemas.analysis import AnalysisResult

logger = logging.getLogger(__name__)

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"

_system_prompt: str | None = None
_analysis_template: str | None = None

_MAX_FIELD_LENGTH = 4096
_INJECTION_PATTERNS = re.compile(
    r"(ignore\s+(all\s+)?previous\s+instructions|"
    r"you\s+are\s+now\s+|"
    r"system\s*:\s*|"
    r"<\|im_start\|>|"
    r"<\|endoftext\|>)",
    re.IGNORECASE,
)


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


def _sanitize(value: str) -> str:
    """Truncate oversized fields and strip potential prompt-injection patterns."""
    if len(value) > _MAX_FIELD_LENGTH:
        value = value[:_MAX_FIELD_LENGTH] + " [truncated]"
    return _INJECTION_PATTERNS.sub("[REDACTED]", value)


def _format_enrichment_for_prompt(enrichment_data: dict[str, Any]) -> str:
    if not enrichment_data:
        return ""
    parts = ["\n== Host Context (osquery) =="]
    for query_name, rows in enrichment_data.items():
        if not rows:
            continue
        parts.append(f"\n--- {query_name} ---")
        if isinstance(rows, list):
            for row in rows[:15]:
                parts.append(json.dumps(row, ensure_ascii=False))
        else:
            parts.append(str(rows))
    return "\n".join(parts)


def _format_correlation_for_prompt(correlation: dict[str, Any]) -> str:
    if not correlation:
        return ""
    parts = ["\n== Correlated Events =="]
    summary = correlation.get("correlation_summary", "")
    if summary:
        parts.append(f"Summary: {summary}")

    for ta in correlation.get("temporal_alerts", [])[:5]:
        parts.append(
            f"- [{ta.get('severity', '?')}] {ta.get('rule_description', '?')} "
            f"(Δ{ta.get('time_delta_seconds', '?')}s)"
        )

    for cm in correlation.get("context_matches", [])[:5]:
        parts.append(
            f"- Context match: {cm.get('matched_field', '?')} = "
            f"{cm.get('alert_value', '?')} ({cm.get('match_type', '?')})"
        )

    for mc in correlation.get("mitre_chains", []):
        parts.append(
            f"- MITRE chain: {mc.get('tactic', '?')} "
            f"({mc.get('chain_length', '?')} alerts)"
        )

    return "\n".join(parts)


def build_analysis_prompt(
    *,
    rule_id: str,
    rule_description: str,
    severity: str,
    agent_name: str,
    timestamp: str,
    alert_data: str,
    enrichment_data: dict[str, Any] | None = None,
    correlation_data: dict[str, Any] | None = None,
) -> str:
    template = get_analysis_template()

    host_context_section = ""
    if enrichment_data:
        host_context_section = _format_enrichment_for_prompt(enrichment_data)

    correlated_alerts_section = ""
    if correlation_data:
        correlated_alerts_section = _format_correlation_for_prompt(correlation_data)

    return template.format(
        rule_id=_sanitize(rule_id),
        rule_description=_sanitize(rule_description),
        severity=severity,
        agent_name=_sanitize(agent_name),
        timestamp=timestamp,
        alert_data=_sanitize(alert_data),
        host_context_section=host_context_section,
        correlated_alerts_section=correlated_alerts_section,
    )


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```")


def parse_llm_response(raw: str) -> AnalysisResult:
    """Parse the LLM response into a validated AnalysisResult.

    Handles raw JSON, JSON in markdown fences, and graceful fallback.
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

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    range(0, 4): "info",
    range(4, 7): "low",
    range(7, 10): "medium",
    range(10, 13): "high",
    range(13, 16): "critical",
}


def _map_severity(level: int) -> str:
    for rng, label in SEVERITY_MAP.items():
        if level in rng:
            return label
    return "unknown"


def normalize_wazuh_alert(raw: dict[str, Any]) -> dict[str, Any]:
    """Transform a raw Wazuh alert into a unified internal format.

    Returns a dict suitable for storing as `normalized_data` in the Alert model.
    """
    rule = raw.get("rule", {})
    agent = raw.get("agent", {})
    data = raw.get("data", {})

    level = rule.get("level", 0)
    if isinstance(level, str):
        level = int(level)

    normalized = {
        "rule_id": str(rule.get("id", "")),
        "rule_description": rule.get("description", ""),
        "rule_level": level,
        "severity": _map_severity(level),
        "rule_groups": rule.get("groups", []),
        "rule_mitre": rule.get("mitre", {}),

        "agent_id": agent.get("id", ""),
        "agent_name": agent.get("name", ""),
        "agent_ip": agent.get("ip", ""),

        "timestamp": raw.get("timestamp", ""),
        "location": raw.get("location", ""),

        "source_ip": data.get("srcip", ""),
        "source_port": data.get("srcport", ""),
        "destination_user": data.get("dstuser", ""),
        "destination_ip": data.get("dstip", ""),

        "full_log": raw.get("full_log", ""),
    }

    return normalized


def extract_alert_fields(raw: dict[str, Any]) -> dict[str, str]:
    """Extract top-level fields for the Alert model from a raw Wazuh alert."""
    rule = raw.get("rule", {})
    agent = raw.get("agent", {})
    level = rule.get("level", 0)
    if isinstance(level, str):
        level = int(level)

    return {
        "rule_id": str(rule.get("id", "")),
        "rule_description": rule.get("description", ""),
        "severity": _map_severity(level),
        "agent_name": agent.get("name", ""),
    }


def alert_data_for_prompt(normalized: dict[str, Any]) -> str:
    """Serialize normalized alert data into a readable string for the LLM prompt."""
    return json.dumps(normalized, indent=2, ensure_ascii=False, default=str)

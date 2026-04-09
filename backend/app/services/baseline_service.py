"""Rule-based baseline assessment — no LLM, deterministic.

Used as Mode A in the evaluation framework to compare against LLM-based analysis.
"""

from backend.app.models.alert import Alert
from backend.app.schemas.analysis import (
    AnalysisResult,
    CriticalityAssessment,
    ResponseRecommendation,
)

_SEVERITY_TO_CRITICALITY: dict[str, tuple[int, str]] = {
    "critical": (9, "critical"),
    "high": (7, "high"),
    "medium": (5, "medium"),
    "low": (3, "low"),
    "info": (1, "info"),
    "unknown": (5, "medium"),
}

_GROUP_TO_ACTION: dict[str, str] = {
    "authentication_failures": "investigate",
    "authentication_failed": "investigate",
    "authentication_success": "monitor",
    "syscheck": "investigate",
    "syscheck_entry_modified": "investigate",
    "rootcheck": "contain",
    "web_scan": "monitor",
    "audit_command": "monitor",
    "sudo": "monitor",
}

_GROUP_TO_CHECKS: dict[str, list[str]] = {
    "authentication_failures": [
        "Check source IP reputation",
        "Review failed login count in the last hour",
        "Verify target account is not compromised",
    ],
    "authentication_failed": [
        "Check source IP reputation",
        "Review failed login count in the last hour",
        "Verify target account is not compromised",
    ],
    "syscheck_entry_modified": [
        "Compare file hashes against known-good baseline",
        "Check which user/process modified the file",
        "Review recent login activity on the host",
    ],
    "rootcheck": [
        "Verify binary integrity against package manager checksums",
        "Check for other indicators of rootkit activity",
        "Consider isolating the host for forensic analysis",
    ],
    "web_scan": [
        "Check source IP for known scanner signatures",
        "Review web server access logs for similar requests",
        "Verify WAF rules are up to date",
    ],
    "audit_command": [
        "Verify the command was executed by an authorized user",
        "Check the destination URL/host against threat intel",
        "Review the user's recent command history",
    ],
    "sudo": [
        "Verify the sudo action was expected",
        "Check the command executed with elevated privileges",
        "Review recent sudo usage by the same user",
    ],
}


def baseline_assessment(alert: Alert) -> AnalysisResult:
    """Generate a deterministic assessment using only Wazuh alert fields."""
    normalized = alert.normalized_data
    severity = alert.severity
    groups = normalized.get("rule_groups", [])

    score, level = _SEVERITY_TO_CRITICALITY.get(severity, (5, "medium"))

    action = "investigate"
    checks: list[str] = []
    for group in groups:
        if group in _GROUP_TO_ACTION:
            action = _GROUP_TO_ACTION[group]
            checks = _GROUP_TO_CHECKS.get(group, [])
            break

    mitre = normalized.get("rule_mitre", {})
    mitre_tactics = mitre.get("tactic", [])
    mitre_ids = mitre.get("id", [])

    causes = [alert.rule_description]
    if mitre_tactics:
        causes.append(f"MITRE ATT&CK tactic: {', '.join(mitre_tactics)}")

    indicators = []
    if normalized.get("source_ip"):
        indicators.append(f"Source IP: {normalized['source_ip']}")
    if normalized.get("destination_user"):
        indicators.append(f"Target user: {normalized['destination_user']}")
    if mitre_ids:
        indicators.append(f"MITRE techniques: {', '.join(mitre_ids)}")
    if normalized.get("full_log"):
        indicators.append(f"Log excerpt: {normalized['full_log'][:120]}")

    urgency = "scheduled"
    if level == "critical":
        urgency = "immediate"
        action = "escalate"
    elif level == "high":
        urgency = "within_1h"
    elif level == "medium":
        urgency = "within_24h"

    return AnalysisResult(
        summary=f"[Baseline] {alert.rule_description} on {alert.agent_name}",
        hypothesis=(
            f"Rule-based assessment: {alert.rule_description}. "
            f"Severity {severity} suggests {action} action."
        ),
        possible_causes=causes,
        key_indicators=indicators,
        recommended_checks=checks or ["Review alert details manually"],
        confidence_note=(
            "Low confidence — rule-based baseline without LLM contextual analysis. "
            "This assessment uses only Wazuh metadata and predefined heuristics."
        ),
        criticality=CriticalityAssessment(
            score=score,
            level=level,
            justification=f"Based on Wazuh rule level ({normalized.get('rule_level', '?')}), "
                          f"severity mapping: {severity} → {level}",
            contributing_factors=[
                f"Wazuh rule level: {normalized.get('rule_level', 'N/A')}",
                f"Rule groups: {', '.join(groups)}",
            ] + ([f"MITRE tactics: {', '.join(mitre_tactics)}"] if mitre_tactics else []),
        ),
        response=ResponseRecommendation(
            action=action,
            urgency=urgency,
            specific_steps=checks or ["Review alert details manually"],
            escalation_needed=(level in ("critical", "high")),
            escalation_reason=(
                f"Severity {level} requires attention" if level in ("critical", "high") else None
            ),
        ),
    )

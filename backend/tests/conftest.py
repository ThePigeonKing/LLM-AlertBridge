"""Shared fixtures for the test suite."""

import uuid
from datetime import UTC, datetime

import pytest

from backend.app.integrations.wazuh.normalizer import (
    extract_alert_fields,
    normalize_wazuh_alert,
)
from backend.app.models.alert import Alert, AlertStatus


def _make_raw_alert(**overrides) -> dict:
    base = {
        "id": f"test-{uuid.uuid4().hex[:8]}",
        "timestamp": "2026-04-06T14:22:01.000+0000",
        "rule": {
            "id": "5710",
            "level": 5,
            "description": "sshd: Attempt to login using a denied user.",
            "groups": ["syslog", "sshd", "authentication_failed"],
            "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]},
        },
        "agent": {"id": "001", "name": "target-1-compute", "ip": "10.128.0.35"},
        "data": {"srcip": "203.0.113.42", "srcport": "44231", "dstuser": "root"},
        "location": "/var/log/auth.log",
        "full_log": "Failed password for invalid user root from 203.0.113.42 port 44231 ssh2",
    }
    base.update(overrides)
    return base


@pytest.fixture
def raw_ssh_alert():
    return _make_raw_alert()


@pytest.fixture
def raw_syscheck_alert():
    return _make_raw_alert(
        rule={
            "id": "550",
            "level": 7,
            "description": "Integrity checksum changed.",
            "groups": ["ossec", "syscheck", "syscheck_entry_modified"],
            "mitre": {"id": ["T1565.001"], "tactic": ["Impact"]},
        },
        data={"path": "/etc/passwd", "mode": "realtime",
              "changed_attributes": ["content", "mtime"]},
        location="syscheck",
        full_log="File '/etc/passwd' modified.",
    )


@pytest.fixture
def raw_rootcheck_alert():
    return _make_raw_alert(
        rule={
            "id": "510",
            "level": 7,
            "description": "Host-based anomaly detection event (rootcheck).",
            "groups": ["ossec", "rootcheck"],
            "mitre": {"id": ["T1014"], "tactic": ["Defense Evasion"]},
        },
        data={"title": "Trojaned version of file detected.", "file": "/usr/bin/ls"},
        location="rootcheck",
        full_log="Trojaned version of file '/usr/bin/ls' detected.",
    )


@pytest.fixture
def raw_web_alert():
    return _make_raw_alert(
        rule={
            "id": "31104",
            "level": 6,
            "description": "Web server 400 error code.",
            "groups": ["web", "accesslog", "web_scan"],
            "mitre": {"id": ["T1190"], "tactic": ["Initial Access"]},
        },
        data={"srcip": "198.51.100.77", "url": "/admin/../../etc/passwd",
              "httpmethod": "GET", "response_code": "400"},
        location="/var/log/nginx/access.log",
        full_log='198.51.100.77 "GET /admin/../../etc/passwd HTTP/1.1" 400',
    )


@pytest.fixture
def raw_benign_alert():
    return _make_raw_alert(
        rule={
            "id": "502",
            "level": 3,
            "description": "Ossec server started.",
            "groups": ["ossec", "service_start"],
            "mitre": {},
        },
        data={},
        location="ossec-monitord",
        full_log="ossec-monitord: Manager started.",
    )


def _make_alert_model(raw: dict) -> Alert:
    normalized = normalize_wazuh_alert(raw)
    fields = extract_alert_fields(raw)
    return Alert(
        id=uuid.uuid4(),
        wazuh_id=raw.get("id", str(uuid.uuid4())),
        raw_data=raw,
        normalized_data=normalized,
        severity=fields["severity"],
        rule_id=fields["rule_id"],
        rule_description=fields["rule_description"],
        agent_name=fields["agent_name"],
        status=AlertStatus.PENDING,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


@pytest.fixture
def ssh_alert_model(raw_ssh_alert):
    return _make_alert_model(raw_ssh_alert)


@pytest.fixture
def syscheck_alert_model(raw_syscheck_alert):
    return _make_alert_model(raw_syscheck_alert)


@pytest.fixture
def rootcheck_alert_model(raw_rootcheck_alert):
    return _make_alert_model(raw_rootcheck_alert)


@pytest.fixture
def web_alert_model(raw_web_alert):
    return _make_alert_model(raw_web_alert)


@pytest.fixture
def benign_alert_model(raw_benign_alert):
    return _make_alert_model(raw_benign_alert)


@pytest.fixture
def sample_enrichment_data():
    return {
        "running_processes": [
            {"pid": "512", "name": "sshd", "path": "/usr/sbin/sshd",
             "cmdline": "/usr/sbin/sshd -D", "uid": "0", "start_time": "1712300010"},
        ],
        "logged_in_users": [
            {"user": "root", "host": "10.128.0.29", "time": "1712430000",
             "tty": "pts/0", "type": "user"},
        ],
        "open_connections": [
            {"pid": "512", "local_address": "0.0.0.0", "local_port": "22",
             "remote_address": "203.0.113.42", "remote_port": "44231",
             "state": "ESTABLISHED", "protocol": "6"},
        ],
    }


@pytest.fixture
def mock_llm_response_valid():
    """A well-formed LLM JSON response."""
    import json
    return json.dumps({
        "summary": "SSH brute-force attempt detected from 203.0.113.42",
        "hypothesis": "Attacker is attempting credential-based access",
        "possible_causes": ["Brute-force SSH attack", "Credential stuffing"],
        "key_indicators": ["Source IP 203.0.113.42", "Target user root"],
        "recommended_checks": ["Check IP reputation", "Review auth logs"],
        "confidence_note": "Medium confidence",
        "criticality": {
            "score": 6, "level": "medium",
            "justification": "Single failed attempt, not yet a pattern",
            "contributing_factors": ["External IP", "Root target"],
        },
        "response": {
            "action": "investigate", "urgency": "within_24h",
            "specific_steps": ["Block IP if repeated", "Monitor for escalation"],
            "escalation_needed": False, "escalation_reason": None,
        },
    })


@pytest.fixture
def mock_llm_response_legacy():
    """Old-format LLM response without criticality/response fields."""
    import json
    return json.dumps({
        "summary": "SSH login attempt",
        "hypothesis": "Brute force attempt",
        "possible_causes": ["Attack"],
        "key_indicators": ["IP 203.0.113.42"],
        "recommended_checks": ["Check logs"],
        "confidence_note": "Low",
    })

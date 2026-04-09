"""Tests for correlation logic."""

import uuid
from datetime import UTC, datetime

from backend.app.models.alert import Alert, AlertStatus
from backend.app.models.enrichment import Enrichment
from backend.app.services.correlation_service import _context_correlation


class TestContextCorrelation:
    def _make_alert(self, **overrides) -> Alert:
        defaults = {
            "id": uuid.uuid4(),
            "wazuh_id": f"test-{uuid.uuid4().hex[:6]}",
            "raw_data": {},
            "normalized_data": {
                "source_ip": "203.0.113.42",
                "destination_user": "root",
                "full_log": "Failed password for root from 203.0.113.42 sshd",
                "rule_groups": [],
                "rule_mitre": {},
            },
            "severity": "low",
            "rule_id": "5710",
            "rule_description": "Test alert",
            "agent_name": "target-1",
            "status": AlertStatus.PENDING,
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        }
        defaults.update(overrides)
        return Alert(**defaults)

    def _make_enrichment(self, alert_id: uuid.UUID, data: dict) -> Enrichment:
        return Enrichment(
            id=uuid.uuid4(),
            alert_id=alert_id,
            host="target-1",
            data=data,
            queries_run=list(data.keys()),
            queries_failed=[],
            created_at=datetime.now(UTC),
        )

    def test_ip_match_in_connections(self):
        alert = self._make_alert()
        enrichment = self._make_enrichment(alert.id, {
            "open_connections": [
                {"pid": "512", "remote_address": "203.0.113.42", "remote_port": "44231",
                 "local_address": "0.0.0.0", "local_port": "22", "state": "ESTABLISHED"},
            ],
        })
        matches = _context_correlation(alert, enrichment)
        assert len(matches) >= 1
        ip_matches = [m for m in matches if m.match_type == "exact"]
        assert len(ip_matches) >= 1
        assert ip_matches[0].alert_value == "203.0.113.42"

    def test_user_match_in_logged_in(self):
        alert = self._make_alert()
        enrichment = self._make_enrichment(alert.id, {
            "logged_in_users": [
                {"user": "root", "host": "10.128.0.29", "time": "1712430000",
                 "tty": "pts/0", "type": "user"},
            ],
        })
        matches = _context_correlation(alert, enrichment)
        user_matches = [m for m in matches if "destination_user" in m.matched_field]
        assert len(user_matches) >= 1

    def test_process_match_in_full_log(self):
        alert = self._make_alert()
        enrichment = self._make_enrichment(alert.id, {
            "running_processes": [
                {"pid": "512", "name": "sshd", "path": "/usr/sbin/sshd",
                 "cmdline": "/usr/sbin/sshd -D", "uid": "0", "start_time": "1712300010"},
            ],
        })
        matches = _context_correlation(alert, enrichment)
        proc_matches = [m for m in matches if m.query_name == "running_processes"]
        assert len(proc_matches) >= 1

    def test_no_matches_when_no_overlap(self):
        alert = self._make_alert(normalized_data={
            "source_ip": "10.0.0.1",
            "destination_user": "nobody",
            "full_log": "something unrelated",
            "rule_groups": [],
            "rule_mitre": {},
        })
        enrichment = self._make_enrichment(alert.id, {
            "open_connections": [
                {"pid": "1", "remote_address": "192.168.1.1", "remote_port": "80",
                 "local_address": "0.0.0.0", "local_port": "80", "state": "ESTABLISHED"},
            ],
            "logged_in_users": [
                {"user": "admin", "host": "10.128.0.29",
                 "time": "0", "tty": "pts/0", "type": "user"},
            ],
            "running_processes": [
                {"pid": "1", "name": "nginx", "path": "/usr/sbin/nginx",
                 "cmdline": "nginx", "uid": "0", "start_time": "0"},
            ],
        })
        matches = _context_correlation(alert, enrichment)
        assert len(matches) == 0

    def test_empty_enrichment(self):
        alert = self._make_alert()
        enrichment = self._make_enrichment(alert.id, {})
        matches = _context_correlation(alert, enrichment)
        assert matches == []

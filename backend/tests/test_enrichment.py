"""Tests for osquery enrichment logic."""

from backend.app.integrations.osquery.client import OsqueryClient
from backend.app.integrations.osquery.queries import select_queries_for_alert


class TestQuerySelection:
    def test_ssh_alert_selects_auth_queries(self):
        normalized = {"rule_groups": ["syslog", "sshd", "authentication_failed"]}
        queries = select_queries_for_alert(normalized)
        assert "running_processes" in queries
        assert "logged_in_users" in queries
        assert "open_connections" in queries
        assert "suid_binaries" not in queries

    def test_syscheck_alert_selects_file_queries(self):
        normalized = {"rule_groups": ["ossec", "syscheck", "syscheck_entry_modified"]}
        queries = select_queries_for_alert(normalized)
        assert "running_processes" in queries
        assert "file_events" in queries
        assert "crontabs" in queries

    def test_web_alert_selects_network_queries(self):
        normalized = {"rule_groups": ["web", "accesslog", "web_scan"]}
        queries = select_queries_for_alert(normalized)
        assert "running_processes" in queries
        assert "open_connections" in queries
        assert "listening_ports" in queries

    def test_rootcheck_selects_suid_queries(self):
        normalized = {"rule_groups": ["ossec", "rootcheck"]}
        queries = select_queries_for_alert(normalized)
        assert "suid_binaries" in queries
        assert "crontabs" in queries

    def test_unknown_groups_get_default(self):
        normalized = {"rule_groups": ["something_unknown"]}
        queries = select_queries_for_alert(normalized)
        assert "running_processes" in queries
        assert "open_connections" in queries
        assert "logged_in_users" in queries

    def test_empty_groups_get_default(self):
        normalized = {"rule_groups": []}
        queries = select_queries_for_alert(normalized)
        assert len(queries) == 3  # default has 3 queries


class TestOsqueryClientMock:
    async def test_mock_returns_processes(self):
        client = OsqueryClient()
        client._transport = "mock"
        result = await client.query("any-host", "SELECT * FROM processes")
        assert isinstance(result, list)
        assert len(result) > 0
        assert "name" in result[0]

    async def test_mock_returns_connections(self):
        client = OsqueryClient()
        client._transport = "mock"
        result = await client.query(
            "any-host", "SELECT * FROM open_connections WHERE state = 'ESTABLISHED'"
        )
        assert isinstance(result, list)

    async def test_mock_unknown_table_returns_empty(self):
        client = OsqueryClient()
        client._transport = "mock"
        result = await client.query("any-host", "SELECT * FROM nonexistent_table")
        assert result == []

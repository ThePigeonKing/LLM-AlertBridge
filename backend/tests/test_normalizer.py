"""Tests for Wazuh alert normalization."""

from backend.app.integrations.wazuh.normalizer import (
    _map_severity,
    alert_data_for_prompt,
    extract_alert_fields,
    normalize_wazuh_alert,
)


class TestSeverityMapping:
    def test_info_range(self):
        assert _map_severity(0) == "info"
        assert _map_severity(3) == "info"

    def test_low_range(self):
        assert _map_severity(4) == "low"
        assert _map_severity(6) == "low"

    def test_medium_range(self):
        assert _map_severity(7) == "medium"
        assert _map_severity(9) == "medium"

    def test_high_range(self):
        assert _map_severity(10) == "high"
        assert _map_severity(12) == "high"

    def test_critical_range(self):
        assert _map_severity(13) == "critical"
        assert _map_severity(15) == "critical"

    def test_out_of_range(self):
        assert _map_severity(99) == "unknown"
        assert _map_severity(-1) == "unknown"


class TestNormalizeWazuhAlert:
    def test_basic_fields(self, raw_ssh_alert):
        result = normalize_wazuh_alert(raw_ssh_alert)
        assert result["rule_id"] == "5710"
        assert result["rule_description"] == "sshd: Attempt to login using a denied user."
        assert result["severity"] == "low"
        assert result["agent_name"] == "target-1-compute"
        assert result["source_ip"] == "203.0.113.42"
        assert result["destination_user"] == "root"

    def test_mitre_preserved(self, raw_ssh_alert):
        result = normalize_wazuh_alert(raw_ssh_alert)
        assert result["rule_mitre"]["id"] == ["T1110"]
        assert result["rule_mitre"]["tactic"] == ["Credential Access"]

    def test_string_level_coerced(self):
        raw = {"rule": {"id": "1", "level": "7"}, "agent": {}, "data": {}}
        result = normalize_wazuh_alert(raw)
        assert result["rule_level"] == 7
        assert result["severity"] == "medium"

    def test_missing_fields_graceful(self):
        result = normalize_wazuh_alert({})
        assert result["rule_id"] == ""
        assert result["severity"] == "info"
        assert result["agent_name"] == ""

    def test_empty_mitre(self, raw_benign_alert):
        result = normalize_wazuh_alert(raw_benign_alert)
        assert result["rule_mitre"] == {}


class TestExtractAlertFields:
    def test_extracts_all_fields(self, raw_ssh_alert):
        fields = extract_alert_fields(raw_ssh_alert)
        assert fields["rule_id"] == "5710"
        assert fields["severity"] == "low"
        assert fields["agent_name"] == "target-1-compute"
        assert "rule_description" in fields

    def test_empty_input(self):
        fields = extract_alert_fields({})
        assert fields["rule_id"] == ""
        assert fields["severity"] == "info"


class TestAlertDataForPrompt:
    def test_produces_json_string(self, raw_ssh_alert):
        normalized = normalize_wazuh_alert(raw_ssh_alert)
        result = alert_data_for_prompt(normalized)
        assert isinstance(result, str)
        assert "5710" in result
        assert "203.0.113.42" in result

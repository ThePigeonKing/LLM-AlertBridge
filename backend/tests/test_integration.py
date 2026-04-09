"""Integration tests for the full analysis pipeline with mocked externals."""

import json

from backend.app.integrations.wazuh.normalizer import (
    alert_data_for_prompt,
    normalize_wazuh_alert,
)
from backend.app.services.baseline_service import baseline_assessment
from backend.app.services.llm_service import build_analysis_prompt, parse_llm_response


class TestFullPipeline:
    """Test the data flow from raw alert to final analysis result."""

    def test_normalize_then_baseline(self, raw_ssh_alert, ssh_alert_model):
        normalized = normalize_wazuh_alert(raw_ssh_alert)
        assert normalized["source_ip"] == "203.0.113.42"

        result = baseline_assessment(ssh_alert_model)
        assert result.summary != ""
        assert result.criticality.level in ("info", "low", "medium", "high", "critical")

    def test_normalize_then_prompt_then_parse(
        self, raw_ssh_alert, mock_llm_response_valid
    ):
        normalized = normalize_wazuh_alert(raw_ssh_alert)
        prompt = build_analysis_prompt(
            rule_id=normalized["rule_id"],
            rule_description=normalized["rule_description"],
            severity=normalized["severity"],
            agent_name=normalized["agent_name"],
            timestamp=normalized["timestamp"],
            alert_data=alert_data_for_prompt(normalized),
        )
        assert "5710" in prompt

        result = parse_llm_response(mock_llm_response_valid)
        assert result.criticality.score == 6
        assert result.response.action == "investigate"

    def test_enriched_prompt_includes_context(
        self, raw_ssh_alert, sample_enrichment_data
    ):
        normalized = normalize_wazuh_alert(raw_ssh_alert)
        prompt = build_analysis_prompt(
            rule_id=normalized["rule_id"],
            rule_description=normalized["rule_description"],
            severity=normalized["severity"],
            agent_name=normalized["agent_name"],
            timestamp=normalized["timestamp"],
            alert_data=alert_data_for_prompt(normalized),
            enrichment_data=sample_enrichment_data,
        )
        assert "Host Context" in prompt
        assert "running_processes" in prompt
        assert "sshd" in prompt

    def test_all_alert_types_through_baseline(
        self,
        ssh_alert_model,
        syscheck_alert_model,
        rootcheck_alert_model,
        web_alert_model,
        benign_alert_model,
    ):
        for alert in [ssh_alert_model, syscheck_alert_model, rootcheck_alert_model,
                      web_alert_model, benign_alert_model]:
            result = baseline_assessment(alert)
            assert result.summary != ""
            assert result.criticality.score >= 1
            assert result.criticality.score <= 10

    def test_evaluation_corpus_loadable(self):
        from pathlib import Path
        corpus_path = Path(__file__).resolve().parents[2] / "experiments" / "corpus.json"
        with open(corpus_path, encoding="utf-8") as f:
            corpus = json.load(f)
        assert len(corpus) == 20
        for entry in corpus:
            assert "wazuh_alert" in entry
            assert "ground_truth" in entry
            assert "simulated_enrichment" in entry

    def test_evaluation_corpus_normalizable(self):
        from pathlib import Path
        corpus_path = Path(__file__).resolve().parents[2] / "experiments" / "corpus.json"
        with open(corpus_path, encoding="utf-8") as f:
            corpus = json.load(f)
        for entry in corpus:
            normalized = normalize_wazuh_alert(entry["wazuh_alert"])
            assert normalized["rule_id"] != ""
            assert normalized["severity"] in ("info", "low", "medium", "high", "critical")

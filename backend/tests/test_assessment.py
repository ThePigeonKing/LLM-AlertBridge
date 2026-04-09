"""Tests for baseline assessment and analysis result schemas."""

from backend.app.schemas.analysis import (
    AnalysisResult,
    CriticalityAssessment,
    ResponseRecommendation,
)
from backend.app.services.baseline_service import baseline_assessment


class TestBaselineAssessment:
    def test_ssh_alert_produces_valid_result(self, ssh_alert_model):
        result = baseline_assessment(ssh_alert_model)
        assert isinstance(result, AnalysisResult)
        assert result.summary != ""
        assert result.criticality.level in ("info", "low", "medium", "high", "critical")
        assert result.response.action in ("ignore", "monitor", "investigate", "contain", "escalate")

    def test_high_severity_gets_contain_or_escalate(self, rootcheck_alert_model):
        result = baseline_assessment(rootcheck_alert_model)
        assert result.response.action in ("contain", "escalate")

    def test_benign_alert_gets_low_criticality(self, benign_alert_model):
        result = baseline_assessment(benign_alert_model)
        assert result.criticality.level in ("info", "low")
        assert result.criticality.score <= 4

    def test_all_fields_populated(self, ssh_alert_model):
        result = baseline_assessment(ssh_alert_model)
        assert len(result.possible_causes) > 0
        assert len(result.key_indicators) > 0
        assert len(result.recommended_checks) > 0
        assert result.confidence_note != ""
        assert result.criticality.justification != ""

    def test_mitre_info_included(self, ssh_alert_model):
        result = baseline_assessment(ssh_alert_model)
        text = str(result.model_dump())
        assert "T1110" in text or "Credential Access" in text

    def test_web_alert_assessment(self, web_alert_model):
        result = baseline_assessment(web_alert_model)
        assert isinstance(result, AnalysisResult)
        assert result.response.urgency in ("immediate", "within_1h", "within_24h", "scheduled")


class TestCriticalityAssessment:
    def test_score_clamped_low(self):
        c = CriticalityAssessment(score=-5, level="low")
        assert c.score == 1

    def test_score_clamped_high(self):
        c = CriticalityAssessment(score=100, level="high")
        assert c.score == 10

    def test_invalid_level_normalized(self):
        c = CriticalityAssessment(score=5, level="EXTREME")
        assert c.level == "medium"

    def test_valid_levels(self):
        for level in ("info", "low", "medium", "high", "critical"):
            c = CriticalityAssessment(score=5, level=level)
            assert c.level == level


class TestResponseRecommendation:
    def test_invalid_action_normalized(self):
        r = ResponseRecommendation(action="destroy")
        assert r.action == "investigate"

    def test_invalid_urgency_normalized(self):
        r = ResponseRecommendation(urgency="right now!")
        assert r.urgency == "within_24h"

    def test_valid_actions(self):
        for action in ("ignore", "monitor", "investigate", "contain", "escalate"):
            r = ResponseRecommendation(action=action)
            assert r.action == action

"""Regression tests for risk scoring and fallback compliance reporting."""

import math

import pytest

from reporting.compliance_reporter import ComplianceReporter
from risk.risk_manager import RiskManager
from scoring.risk_scorer import RiskScorer


def test_heat_map_uses_exploitability_score_scale():
    risk = {
        "type": "password_not_required",
        "severity": "critical",
        "exploitability": {"exploitability_score": 8.5},
    }

    heat_map = RiskManager().generate_risk_heat_map([risk])["heat_map"]

    assert len(heat_map["critical_high"]) == 1
    assert heat_map["critical_medium"] == []


@pytest.mark.parametrize("hourly_rate", [0, -1, math.inf, math.nan])
def test_risk_manager_rejects_invalid_hourly_rate(hourly_rate):
    with pytest.raises(ValueError):
        RiskManager(hourly_rate)


def test_domain_controller_detection_uses_account_type_flag():
    scorer = RiskScorer()
    risk = {
        "type": "inactive_computer",
        "severity": "medium",
        "affected_object": "ACDC-PC",
        "object_type": "computer",
    }

    scored = scorer.score_risks(
        [risk],
        computers=[{"name": "ACDC-PC", "userAccountControl": 0x1000}],
    )

    assert scored[0]["object_type_multiplier"] == 1.2


def test_domain_controller_flag_receives_domain_controller_multiplier():
    scorer = RiskScorer()
    risk = {
        "type": "inactive_computer",
        "severity": "medium",
        "affected_object": "SERVER01",
        "object_type": "computer",
    }

    scored = scorer.score_risks(
        [risk],
        computers=[{"name": "SERVER01", "userAccountControl": 0x2000}],
    )

    assert scored[0]["object_type_multiplier"] == 2.0


def test_fallback_nist_report_scores_all_mapped_checks():
    report = ComplianceReporter().analyze_nist_csf([])

    assert report["compliance_score"] == 100.0
    assert report["functions"]["PR"]["status"] == "passed"
    assert report["functions"]["DE"]["status"] == "not_assessed"
    assert report["functions"]["DE"]["score"] is None


def test_current_and_legacy_risk_names_map_to_compliance_checks():
    reporter = ComplianceReporter()

    current = reporter.analyze_cis_benchmark([{"type": "password_policy_weak"}])
    legacy = reporter.analyze_cis_benchmark([{"type": "weak_password_policy"}])

    assert current["failed_controls"] == legacy["failed_controls"]
    assert current["failed_controls"][0]["risk_type"] == "password_policy_weak"


def test_iso_report_groups_controls_by_actual_domain():
    report = ComplianceReporter().analyze_iso_27001([])

    assert set(report["domains"]) == {"A.9", "A.12"}

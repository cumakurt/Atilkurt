"""Regression tests for incomplete-assessment scoring and stale privilege."""

from reporting.ciso_dashboard import CISODashboardGenerator
from reporting.html_report import HTMLReportGenerator
from reporting.localization import localize_report_structure
from scoring.risk_scorer import RiskScorer


def test_empty_incomplete_assessment_is_not_a_perfect_score():
    scorer = RiskScorer()
    assert scorer.calculate_domain_score([], evidence_complete=False) is None
    assert scorer.calculate_domain_score([], evidence_complete=True) == 100.0


def test_stale_admin_count_does_not_use_the_privileged_multiplier():
    former = {"sAMAccountName": "former_admin", "adminCount": "1", "memberOf": []}
    current = {
        "sAMAccountName": "da",
        "adminCount": "1",
        "memberOf": ["CN=Domain Admins,CN=Users,DC=example,DC=com"],
    }
    risk = {
        "type": "user_password_never_expires",
        "severity": "high",
        "affected_object": "former_admin",
        "object_type": "user",
    }
    former_score = RiskScorer().score_risks([dict(risk)], users=[former])
    current_score = RiskScorer().score_risks(
        [{**risk, "affected_object": "da"}], users=[current],
    )
    assert former_score[0]["object_type_multiplier"] == 1.0
    assert current_score[0]["object_type_multiplier"] == 1.5


def test_ciso_summary_does_not_call_an_incomplete_empty_scan_clean():
    summary = CISODashboardGenerator()._generate_ciso_summary([], {}, evidence_complete=False)
    assert "appears to be in good standing" not in summary
    assert "did not finish" in summary
    localized = localize_report_structure({"ciso_summary": summary}, "tr")["ciso_summary"]
    assert "iyi durumda olduğunun kanıtı değildir" in localized


def test_ciso_privileged_count_ignores_stale_admin_count():
    data = CISODashboardGenerator().generate_dashboard_data(
        [],
        [{"sAMAccountName": "former", "adminCount": "1", "memberOf": []}],
        [],
        [],
        80.0,
        {"top_critical_risks": []},
    )
    assert data["kpis"]["privileged_accounts"]["value"] == 0


def test_incomplete_report_withholds_a_perfect_score(tmp_path):
    from types import SimpleNamespace
    from core.product_workflow import prepare_product_workspace

    output = tmp_path / "report.html"
    data = {
        "users": [], "computers": [], "groups": [], "gpos": [],
        "collection_health": {"status": "partial", "queries": []},
    }
    workspace = prepare_product_workspace(
        SimpleNamespace(domain="example.com"), data, {}, {"scored_risks": [], "domain_score": None, "scan_coverage": {}},
    )
    HTMLReportGenerator().generate(
        users=[],
        computers=[],
        groups=[],
        gpos=[],
        risks=[],
        misconfig_findings=[],
        domain_score=None,
        executive_summary={"top_critical_risks": []},
        output_file=str(output),
        domain="example.com",
        scan_coverage={"summary": {"execution_percent": 100.0, "partial_steps": 0, "collection_status": "partial"}},
        product_workspace=workspace,
    )
    report = output.read_text(encoding="utf-8")
    assert "Not assessed" in report
    assert "appears to be in good standing" not in report


def test_machine_quota_alone_is_not_scored_as_confirmed_certifried():
    from unittest.mock import MagicMock
    from analysis.ad_cs_extended_analyzer import ADCSExtendedAnalyzer
    from core.finding_evidence import is_score_excluded

    ldap = MagicMock()
    ldap.base_dn = "DC=example,DC=com"
    ldap.search.return_value = [{"ms-DS-MachineAccountQuota": 10}]
    risks = ADCSExtendedAnalyzer(ldap)._check_certifried()
    assert len(risks) == 1
    assert risks[0]["type"] == "certificate_certifried"
    assert is_score_excluded(risks[0])


def test_alt_security_identities_without_write_proof_are_not_esc14():
    from unittest.mock import MagicMock
    from analysis.ad_cs_extended_analyzer import ADCSExtendedAnalyzer

    ldap = MagicMock()
    ldap.base_dn = "DC=example,DC=com"
    ldap.search.return_value = [{"sAMAccountName": "mapper", "altSecurityIdentities": ["X509:<I>CN=CA"]}]
    risks = ADCSExtendedAnalyzer(ldap)._check_esc10_esc14()
    assert len(risks) == 1
    assert risks[0]["type"] == "alt_security_identities_unverified"
    assert risks[0]["evidence"]["writability_observed"] is False


def test_directory_descriptions_redact_password_assignments():
    from core.directory_redaction import redact_assessment_secrets

    data = {
        "users": [{"sAMAccountName": "alice", "description": "password=SecretValue other text"}],
        "computers": [],
        "groups": [{"name": "ops", "info": ["pwd: hunter2"]}],
        "gpos": [],
    }
    analysis = {"incremental_diff": {"collections": {"users": {"changed": [
        {"previous": {"description": "pass=old-secret"}, "current": data["users"][0]},
    ]}}}}
    redact_assessment_secrets(data, analysis)
    assert data["users"][0]["description"] == "password=[REDACTED] other text"
    assert data["groups"][0]["info"] == ["pwd: [REDACTED]"]
    assert analysis["incremental_diff"]["collections"]["users"]["changed"][0]["previous"]["description"] == "pass=[REDACTED]"

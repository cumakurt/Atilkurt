"""Regressions found while tracing collection, rescoring, and report publication."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from xml.etree import ElementTree

import pytest

from core.cache import TimedCache
from analysis.compliance_analyzer import ComplianceAnalyzer
from analysis.baseline_comparator import BaselineComparator
from core.finding_review import FindingReviewManager
from reporting.compliance_reporter import ComplianceReporter
from reporting.export_formats import ExportFormats
from reporting.html_report import HTMLReportGenerator
from scoring.risk_scorer import RiskScorer


@pytest.mark.parametrize("reviewed", [False, True])
def test_rescoring_keeps_original_severity_and_score(reviewed):
    risk = {
        "type": "protocol_smb_signing_required",
        "severity": "medium",
        "object_type": "computer",
        "affected_object": "host",
    }
    if reviewed:
        FindingReviewManager().apply([risk], {}, "example.com")
    scorer = RiskScorer()
    first = deepcopy(scorer.score_risks([risk]))
    for _ in range(3):
        if reviewed:
            FindingReviewManager().apply([risk], {}, "example.com")
        assert scorer.score_risks([risk]) == first


def test_rescoring_clears_obsolete_combination_bonus():
    risks = [{"type": kind, "severity": "medium", "affected_object": "host"} for kind in ("custom_a", "custom_b")]
    scorer = RiskScorer()
    scorer.score_risks(risks)
    assert "combination_bonus" in risks[0]
    scorer.score_risks(risks[:1])
    assert "combination_bonus" not in risks[0]


def test_zero_ttl_invalidates_existing_value():
    cache = TimedCache(default_ttl=60)
    cache.set("key", "old")
    cache.set("key", "new", ttl=0)
    assert cache.get("key") is None


def test_expired_recent_entry_is_evicted_before_live_lru(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("core.cache.time.monotonic", lambda: clock[0])
    cache = TimedCache(maxsize=2)
    cache.set("live", 1, ttl=60)
    cache.set("expired", 2, ttl=1)
    clock[0] += 2
    cache.set("new", 3)
    assert cache.get("live") == 1
    assert cache.get("expired") is None
    assert cache.size() == 2


@pytest.mark.parametrize("framework", ["cis", "nist", "iso", "gdpr"])
def test_compliance_details_escape_directory_values(framework):
    payload = '<img src=x onerror="alert(1)">'
    control = {
        "control_id": "test",
        "control_name": payload,
        "status": "failed",
        "ldap_query": payload,
        "recommendation": payload,
        "description": payload,
        "details": {"affected_users": [payload], "affected_computers": [payload], "value": payload},
    }
    report = {"compliance_score": 0}
    if framework == "cis":
        report["controls"] = [control]
    elif framework == "nist":
        report["functions"] = {"PR": {"score": 0, "name": payload, "controls": [control]}}
    elif framework == "iso":
        report["domains"] = {"A.9": [control]}
    else:
        report["articles"] = {"Article 32": [control]}
    original = deepcopy(report)
    html = getattr(HTMLReportGenerator(), f"_generate_{framework}_compliance_html")(report)
    assert payload not in html
    assert "&lt;img" in html
    assert report == original


def test_html_compliance_uses_exported_overall_score():
    report = {key: {"compliance_score": 100} for key in ("cis_benchmark", "nist_csf", "iso_27001", "gdpr")}
    report["cis_controls_v8"] = {"compliance_score": 0}
    report["overall_compliance_score"] = 80
    html = HTMLReportGenerator()._generate_compliance_section(report)
    assert "80.0%" in html


def test_external_report_copies_nested_font_assets(tmp_path):
    HTMLReportGenerator()._copy_vendor_to_output(str(tmp_path / "report.html"))
    assert (tmp_path / "vendor/webfonts/fa-solid-900.woff2").is_file()
    assert (tmp_path / "vendor/fonts/DejaVuSans.ttf").is_file()


def test_nessus_export_has_numeric_severity_and_deterministic_ids(tmp_path):
    risk = {"type": "password_not_required", "severity": "high", "title": "Password required"}
    output = tmp_path / "report.nessus"
    ExportFormats.export_nessus_xml([risk], str(output), "example.com")
    item = ElementTree.parse(output).find(".//ReportItem")
    assert item.attrib["severity"] == "3"
    script = (
        "from reporting.export_formats import ExportFormats; "
        f"ExportFormats.export_nessus_xml([{risk!r}], {str(output)!r}, 'example.com')"
    )
    identifiers = []
    for seed in ("1", "2"):
        subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            cwd=Path(__file__).resolve().parents[1],
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        identifiers.append(ElementTree.parse(output).find(".//ReportItem").attrib["pluginID"])
    assert identifiers[0] == identifiers[1]


def test_snapshot_roundtrip_preserves_risk_score():
    risk = {"type": "protocol_smb_signing_required", "severity": "medium", "affected_object": "host"}
    FindingReviewManager().apply([risk], {}, "example.com")
    RiskScorer().score_risks([risk])
    restored = json.loads(json.dumps(risk))
    FindingReviewManager().apply([restored], {}, "example.com")
    RiskScorer().score_risks([restored])
    assert restored["final_score"] == risk["final_score"]


def test_findings_only_report_never_claims_unobserved_compliance():
    report = ComplianceReporter().generate_compliance_report([])
    assert report["assessment_status"] == "not_assessed"
    html = HTMLReportGenerator()._generate_compliance_section(report)
    assert "100.0%" not in html
    assert "Not assessed" in html
    assert report["cis_benchmark"]["passed_controls"] == []
    assert report["cis_controls_v8"]["passed_safeguards"] == []


@pytest.mark.parametrize(
    "age,passed",
    [
        (0, False),
        ("0", False),
        (timedelta(days=-180), False),
        (-180 * 864000000000, False),
        (timedelta(days=-30), True),
    ],
)
def test_password_age_checks_use_decoded_ldap_intervals(age, passed):
    analyzer = ComplianceAnalyzer(SimpleNamespace(base_dn="DC=example,DC=com"))
    policy = {"minPwdLength": 14, "maxPwdAge": age, "pwdProperties": 1}
    result = analyzer.analyze_iso_27001([], [], [], policy)
    control = next(row for row in result["domains"]["A.9.4"] if row["control_id"] == "A.9.4.3")
    assert (control["status"] == "passed") is passed


def test_compliance_identifies_renamed_domain_admins_by_sid():
    analyzer = ComplianceAnalyzer(SimpleNamespace(base_dn="DC=example,DC=com"))
    group = {"name": "Renamed admins", "objectSid": "S-1-5-21-1-2-3-512", "member": list("abcdef")}
    result = analyzer.analyze_gdpr([], [group], [])
    control = next(row for row in result["articles"]["Article 32"] if "Privilege management" in row["control_name"])
    assert control["status"] == "warning"
    assert control["details"]["domain_admin_count"] == 6


def test_cis_v8_counts_only_implemented_safeguards_and_deduplicates_failures():
    analyzer = ComplianceAnalyzer(SimpleNamespace(base_dn="DC=example,DC=com"))
    result = analyzer._analyze_cis_controls_v8_from_data(
        [{"userAccountControl": 0x20 | 0x400000 | 0x10000}], [], [{"userAccountControl": 0x80000}]
    )
    assert result["total_safeguards"] == 3
    assert result["failed_safeguards"] == ["4.3", "5.2"]
    assert result["passed_safeguards"] == 0
    assert result["unknown_safeguards"] == ["5.1"]


def test_checkpoint_baseline_reads_nested_directory_collections():
    objects = {"users": [{"sAMAccountName": "alice", "memberOf": ["CN=Users,DC=example,DC=com"]}]}
    checkpoint = {
        "checkpoint_id": "scan",
        "data": {"domain": "example.com", "data": objects, "analysis": {}, "scoring": {"scored_risks": []}},
    }
    result = BaselineComparator().compare_snapshot(objects, {}, [], "unused", baseline_document=checkpoint)
    assert result["collections"]["users"] == {"added": [], "removed": [], "modified": []}


def test_baseline_compares_acl_targets_separately_and_ignores_name_case():
    prior = {"type": "acl_grant", "affected_object": "Alice", "target_object": "group-a", "permission": "WriteDacl"}
    current = {**prior, "target_object": "group-b"}
    result = BaselineComparator().compare([current], [prior])
    assert result["new_risks"] == [current]
    same = {**prior, "affected_object": "ALICE"}
    assert BaselineComparator().compare([same], [prior])["new_risks"] == []


def test_partial_snapshot_absence_does_not_claim_remediation():
    previous = {"risks": [{"type": "password_not_required", "affected_object": "alice"}]}
    result = BaselineComparator().compare_snapshot(
        {"collection_health": {"status": "partial"}}, {}, [], "unused", baseline_document=previous
    )
    assert result["summary"]["resolved_risks"] == 0
    assert result["summary"]["unobserved_risks"] == 1
    assert result["risk_comparison"]["unobserved_risks"] == previous["risks"]


@pytest.mark.parametrize(
    "attributes,direction,status",
    [(4, 3, "passed"), (0, 3, "failed"), (8, 3, "unknown"), (32, 3, "passed"), (0, 1, "passed"), (None, 3, "unknown")],
)
def test_compliance_trust_filtering_matches_quarantine_semantics(attributes, direction, status):
    def search(**kwargs):
        if kwargs["search_filter"] == "(objectClass=trustedDomain)":
            return [{"name": "other.example", "trustAttributes": attributes, "trustDirection": direction}]
        return []

    analyzer = ComplianceAnalyzer(SimpleNamespace(base_dn="DC=example,DC=com", search=search))
    report = analyzer.analyze_cis_benchmark([], [], [])
    control = next(row for row in report["controls"] if row["control_id"] == "CIS 2.3.7.1")
    assert control["status"] == status


def test_compliance_handles_timezone_aware_inactive_accounts():
    analyzer = ComplianceAnalyzer(SimpleNamespace(base_dn="DC=example,DC=com"))
    user = {"userAccountControl": 512, "lastLogonTimestamp": datetime.now(timezone.utc) - timedelta(days=120)}
    result = analyzer.analyze_nist_csf([user], [], [])
    assert result["functions"]["DE"]["controls"][0]["details"]["inactive_accounts_count"] == 1


@pytest.mark.parametrize("users,failures", [([], 0), ([{}], 0), ([{"userAccountControl": 512}], 1)])
def test_incomplete_inventory_cannot_pass_user_controls(users, failures):
    analyzer = ComplianceAnalyzer(SimpleNamespace(base_dn="DC=example,DC=com", query_failure_count=failures))
    result = analyzer.analyze_gdpr(users, [], [])
    control = next(row for row in result["articles"]["Article 32"] if "Access control" in row["control_name"])
    assert control["status"] == "unknown"


def test_default_fallback_score_remains_stable():
    risk = {"type": "custom_rule"}
    scorer = RiskScorer()
    assert scorer.score_risks([risk])[0]["base_score"] == 50
    assert scorer.score_risks([risk])[0]["base_score"] == 50


def test_failed_trust_query_remains_visible_as_unknown():
    def search(**kwargs):
        from core.exceptions import LDAPSearchError

        raise LDAPSearchError("Read failed")

    analyzer = ComplianceAnalyzer(SimpleNamespace(base_dn="DC=example,DC=com", search=search))
    result = analyzer.analyze_cis_benchmark([], [], [])
    control = next(row for row in result["controls"] if row["control_id"] == "CIS 2.3.7.1")
    assert control["status"] == "unknown"


def test_partial_collection_cannot_pass_cis_v8_safeguards():
    analyzer = ComplianceAnalyzer(SimpleNamespace(base_dn="DC=example,DC=com", query_failure_count=1))
    result = analyzer._analyze_cis_controls_v8_from_data(
        [{"userAccountControl": 512}], [{"name": "Domain Admins", "member": []}], [{"userAccountControl": 4096}]
    )
    assert result["passed_safeguards"] == 0
    assert len(result["unknown_safeguards"]) == 3

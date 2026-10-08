"""End-to-end evidence review, risk acceptance, coverage and what-if regressions."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import subprocess

import pytest

from AtilKurt import build_parser, generate_offline_report, score_and_consolidate, validate_cli_arguments
from analysis.remediation_simulator import edge_id, simulate_remediation
from analysis.scan_coverage import build_scan_coverage
from core.exceptions import ValidationError
from core.finding_evidence import is_score_excluded, requires_validation
from core.finding_review import FindingReviewManager, empty_review_document, load_review_document
from core.validation_collector import build_validation_script
from reporting.compliance_reporter import ComplianceReporter
from reporting.html_report import HTMLReportGenerator
from scoring.risk_scorer import RiskScorer

NOW = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)
DOMAIN = "example.com"
DATA = {"users": [], "groups": [], "computers": [], "gpos": []}
ROOT = Path(__file__).resolve().parents[1]


def candidate():
    return {
        "type": "printnightmare_vulnerable",
        "severity": "critical",
        "title": "Potential print exposure",
        "affected_object": "dc01",
        "object_type": "computer",
        "cve": "CVE-2021-34527",
        "evidence": {"operating_system": "Windows Server"},
    }


def bind(risk=None):
    risk = risk or candidate()
    center = FindingReviewManager().apply([risk], DATA, DOMAIN, now=NOW)
    return risk, center


def decision(risk, status="confirmed"):
    return {
        "finding_id": risk["finding_id"],
        "evidence_fingerprint": risk["evidence_fingerprint"],
        "rule_version": risk["rule_version"],
        "status": status,
        "reason": "Verified against host evidence",
        "reviewer": "security-team",
        "reviewed_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(days=14)).isoformat(),
        "checks": [
            {
                "name": name,
                "result": "pass",
                "target": risk["affected_object"],
                "source": "host-policy-export.json",
                "collected_at": NOW.isoformat(),
            }
            for name in risk["required_checks"]
        ],
    }


def apply_review(risk, review, *, now=NOW):
    doc = empty_review_document(DOMAIN)
    doc["reviews"] = [review]
    return FindingReviewManager().apply([risk], DATA, DOMAIN, doc, now=now)


def test_complete_fresh_review_confirms_candidate_and_restores_score():
    risk, _ = bind()
    apply_review(risk, decision(risk))
    assert risk["finding_status"] == "confirmed"
    assert not requires_validation(risk)
    scored = RiskScorer().score_risks([risk])
    assert scored[0]["final_score"] > 0
    assert scored[0]["severity"] == "critical"


@pytest.mark.parametrize(
    "change,expected",
    [
        ("missing_check", "missing_prerequisites"),
        ("wrong_target", "unbound_evidence"),
        ("stale", "stale_evidence"),
        ("rule", "rule_changed"),
        ("configuration", "configuration_changed"),
        ("future", "invalid_timestamp"),
        ("timezone", "invalid_timestamp"),
        ("duplicate", "conflicting_checks"),
        ("unhashable", "invalid_checks"),
    ],
)
def test_invalid_review_cannot_promote_candidate(change, expected):
    risk, _ = bind()
    review = decision(risk)
    if change == "missing_check":
        review["checks"].pop()
    if change == "wrong_target":
        review["checks"][0]["target"] = "other-host"
    if change == "stale":
        review["checks"][0]["collected_at"] = (NOW - timedelta(days=31)).isoformat()
    if change == "rule":
        review["rule_version"] = "old"
    if change == "configuration":
        review["evidence_fingerprint"] = "other"
    if change == "future":
        review["reviewed_at"] = (NOW + timedelta(days=1)).isoformat()
    if change == "timezone":
        review["reviewed_at"] = "2026-10-08T12:00:00"
    if change == "duplicate":
        review["checks"].append(deepcopy(review["checks"][0]))
    if change == "unhashable":
        review["checks"][0]["name"] = []
    apply_review(risk, review)
    assert risk["review_status"] == expected
    assert requires_validation(risk)


def test_disproof_requires_a_failed_prerequisite_and_expires_on_replay():
    risk, _ = bind()
    review = decision(risk, "false_positive")
    apply_review(risk, review)
    assert risk["review_status"] == "missing_disproof"
    review["checks"][0]["result"] = "fail"
    apply_review(risk, review)
    assert risk["finding_status"] == "false_positive"
    assert is_score_excluded(risk)
    apply_review(risk, review, now=NOW + timedelta(days=15))
    assert risk["review_status"] == "expired"
    assert requires_validation(risk)
    assert risk["severity"] == "critical"


def test_conflicting_decisions_do_not_pick_an_arbitrary_result():
    risk, _ = bind()
    doc = empty_review_document(DOMAIN)
    doc["reviews"] = [decision(risk), decision(risk, "false_positive")]
    FindingReviewManager().apply([risk], DATA, DOMAIN, doc, now=NOW)
    assert risk["review_status"] == "conflicting_reviews"
    assert requires_validation(risk)


def test_configuration_change_invalidates_account_exception():
    data = deepcopy(DATA)
    data["users"] = [{"sAMAccountName": "alice", "userAccountControl": 66048}]
    risk = {"type": "user_password_never_expires", "severity": "high", "affected_object": "alice"}
    manager = FindingReviewManager()
    manager.apply([risk], data, DOMAIN, now=NOW)
    old_id = risk["finding_id"]
    doc = empty_review_document(DOMAIN)
    doc["exceptions"] = [
        {key: risk[key] for key in ("finding_id", "evidence_fingerprint", "rule_version")}
        | {
            "owner": "identity-team",
            "reason": "Approved temporary service dependency",
            "created_at": NOW.isoformat(),
            "expires_at": (NOW + timedelta(days=2)).isoformat(),
        }
    ]
    manager.apply([risk], data, DOMAIN, doc, now=NOW)
    assert risk["exception_status"] == "active"
    assert is_score_excluded(risk)
    data["users"][0]["memberOf"] = ["CN=Domain Admins,DC=example,DC=com"]
    manager.apply([risk], data, DOMAIN, doc, now=NOW)
    assert risk["finding_id"] == old_id
    assert risk["exception_status"] == "configuration_changed"
    assert not is_score_excluded(risk)
    assert "risk_exception" not in risk


def test_accepted_risk_still_fails_risk_based_compliance_and_keeps_attack_path():
    risk, _ = bind({"type": "dcsync_rights", "severity": "critical", "affected_object": "delegate"})
    doc = empty_review_document(DOMAIN)
    doc["exceptions"] = [
        {key: risk[key] for key in ("finding_id", "evidence_fingerprint", "rule_version")}
        | {
            "owner": "identity-team",
            "reason": "Temporary replication dependency",
            "created_at": NOW.isoformat(),
            "expires_at": (NOW + timedelta(days=2)).isoformat(),
        }
    ]
    FindingReviewManager().apply([risk], DATA, DOMAIN, doc, now=NOW)
    from analysis.domain_admin_takeover_analyzer import DomainAdminTakeoverAnalyzer

    assert DomainAdminTakeoverAnalyzer().analyze([risk])["summary"]["open_path_count"] > 0
    assert ComplianceReporter._risk_type_counts([risk])["dcsync_rights"] == 1
    assert RiskScorer().score_risks([risk])[0]["final_score"] == 0


def test_review_fingerprint_survives_json_roundtrip_and_binary_context():
    data = deepcopy(DATA)
    data["computers"] = [{"name": "dc01", "nTSecurityDescriptor": b"\x00\xff"}]
    risk = candidate()
    FindingReviewManager().apply([risk], data, DOMAIN, now=NOW)
    fingerprint = risk["evidence_fingerprint"]
    risk, data = json.loads(json.dumps([risk, data], default=str))
    FindingReviewManager().apply([risk], data, DOMAIN, now=NOW)
    assert risk["evidence_fingerprint"] == fingerprint


def test_distinct_conditions_on_one_object_cannot_share_a_review():
    minimum = {
        "type": "password_policy_weak",
        "title": "Weak Password Policy: Minimum length is 8",
        "affected_object": "Domain Password Policy",
        "severity": "high",
    }
    complexity = {**minimum, "title": "Weak Password Policy: Complexity disabled"}
    changed_minimum = {**minimum, "title": "Weak Password Policy: Minimum length is 10"}
    manager = FindingReviewManager()
    manager.apply([minimum, complexity, changed_minimum], DATA, DOMAIN, now=NOW)
    assert minimum["finding_id"] != complexity["finding_id"]
    assert minimum["finding_id"] == changed_minimum["finding_id"]
    assert minimum["evidence_fingerprint"] != changed_minimum["evidence_fingerprint"]


def test_expired_exception_returns_to_scoring_without_recollection():
    risk, _ = bind(
        {"type": "dcsync_rights", "severity": "critical", "title": "DCSync Rights", "affected_object": "delegate"}
    )
    doc = empty_review_document(DOMAIN)
    doc["exceptions"] = [
        {key: risk[key] for key in ("finding_id", "evidence_fingerprint", "rule_version")}
        | {
            "owner": "identity-team",
            "reason": "Temporary replication dependency",
            "created_at": NOW.isoformat(),
            "expires_at": (NOW + timedelta(days=2)).isoformat(),
        }
    ]
    manager = FindingReviewManager()
    manager.apply([risk], DATA, DOMAIN, doc, now=NOW)
    assert RiskScorer().score_risks([risk])[0]["final_score"] == 0
    manager.apply([risk], DATA, DOMAIN, doc, now=NOW + timedelta(days=3))
    assert risk["exception_status"] == "expired"
    assert RiskScorer().score_risks([risk])[0]["final_score"] > 0


def test_disproved_acl_refreshes_derived_graph_paths():
    from analysis.attack_graph_v2_analyzer import AttackGraphV2Analyzer
    from core.finding_review import utc_now
    from core.ad_security import sid_text

    data = deepcopy(DATA)
    data["users"] = [{"sAMAccountName": "alice", "objectSid": "S-1-5-21-100-200-300-1100"}]
    data["groups"] = [{"name": "Domain Admins", "objectSid": "S-1-5-21-100-200-300-512"}]
    acl = {
        "type": "acl_generic_all",
        "title": "Unexpected full control",
        "severity": "critical",
        "affected_object": "Domain Admins",
        "object_type": "group",
        "trustee": sid_text(data["users"][0]["objectSid"]),
        "permission": "GenericAll",
        "evidence": {"trustee_sid": data["users"][0]["objectSid"], "permission": "GenericAll"},
    }
    analysis = {"comprehensive_acl_risks": [acl]}
    graph = AttackGraphV2Analyzer().analyze(data["users"], data["groups"], [], analysis)
    analysis.update(attack_graph_v2=graph["graph"], attack_graph_v2_risks=graph["risks"])
    assert graph["graph"]["summary"]["open_path_count"] == 1
    scored = score_and_consolidate(analysis, data, domain=DOMAIN)
    reviewed_acl = next(risk for risk in scored["scored_risks"] if risk["type"] == "acl_generic_all")
    review = decision(reviewed_acl, "false_positive")
    current = utc_now()
    review["reviewed_at"] = current.isoformat()
    review["expires_at"] = (current + timedelta(days=14)).isoformat()
    for check in review["checks"]:
        check["collected_at"] = current.isoformat()
    review["checks"][0]["result"] = "fail"
    document = empty_review_document(DOMAIN)
    document["reviews"] = [review]
    result = score_and_consolidate(analysis, data, domain=DOMAIN, review_document=document)
    assert analysis["attack_graph_v2"]["summary"]["open_path_count"] == 0
    assert not any(risk["type"] == "attack_graph_tier0_path" for risk in result["scored_risks"])
    assert result["remediation_simulation"]["before"]["exposed_sources"] == 0


def test_cross_domain_and_malformed_documents_are_rejected(tmp_path):
    path = tmp_path / "review.json"
    path.write_text(json.dumps(empty_review_document("other.example")))
    with pytest.raises(ValidationError):
        load_review_document(str(path), DOMAIN)
    path.write_text("[]")
    with pytest.raises(ValidationError):
        load_review_document(str(path), DOMAIN)


def test_offline_binary_restore_is_safe_and_preserves_sid_evidence(tmp_path):
    from AtilKurt import _restore_snapshot_binary_attributes

    data = {"users": [{"objectSid": "b'\\x01\\x02'", "nTSecurityDescriptor": ["b'\\x00\\xff'"]}]}
    _restore_snapshot_binary_attributes(data)
    assert data["users"][0]["objectSid"] == b"\x01\x02"
    assert data["users"][0]["nTSecurityDescriptor"] == [b"\x00\xff"]
    marker = tmp_path / "must-not-exist"
    data = {"users": [{"objectSid": f"b'' + __import__('pathlib').Path({str(marker)!r}).touch()"}]}
    with pytest.raises(ValidationError):
        _restore_snapshot_binary_attributes(data)
    assert not marker.exists()


def test_observation_age_and_conflicting_host_values_are_visible():
    doc = empty_review_document(DOMAIN)
    base = {"target": "dc01", "name": "LDAPServerIntegrity", "source": "registry", "collected_at": NOW.isoformat()}
    doc["observations"] = [
        {**base, "value": 0},
        {**base, "value": 2},
        {**base, "target": "dc02", "value": 2, "collected_at": (NOW - timedelta(days=31)).isoformat()},
    ]
    result = FindingReviewManager().apply([], DATA, DOMAIN, doc, now=NOW)
    assert [row["status"] for row in result["observations"]] == [
        "conflicting_evidence",
        "conflicting_evidence",
        "stale_evidence",
    ]


def test_different_services_are_not_conflicting_host_observations():
    doc = empty_review_document(DOMAIN)
    base = {"target": "dc01", "name": "service", "source": "Get-Service", "collected_at": NOW.isoformat()}
    doc["observations"] = [
        {**base, "value": {"name": "Spooler", "status": "Running"}},
        {**base, "value": {"name": "WebClient", "status": "Stopped"}},
        {**base, "value": {"name": "spooler", "status": "Stopped"}},
    ]
    result = FindingReviewManager().apply([], DATA, DOMAIN, doc, now=NOW)
    assert [row["status"] for row in result["observations"]] == [
        "conflicting_evidence",
        "available",
        "conflicting_evidence",
    ]


def graph_fixture():
    return {
        "nodes": [
            {"id": "a", "label": "alice", "kind": "user"},
            {"id": "g", "kind": "group"},
            {"id": "b", "label": "bob", "kind": "user"},
            {"id": "t", "label": "Tier 0", "kind": "group", "privileged": True},
        ],
        "edges": [
            {"source": "a", "target": "t", "type": "Controls", "permission": "WriteDACL"},
            {"source": "a", "target": "g", "type": "MemberOf"},
            {"source": "g", "target": "t", "type": "Controls"},
            {"source": "b", "target": "g", "type": "MemberOf"},
            {"source": "b", "target": "t", "type": "InboundTrust"},
        ],
    }


def test_simulator_recomputes_alternate_paths_and_preserves_original_graph():
    graph = graph_fixture()
    original = deepcopy(graph)
    result = simulate_remediation(graph, [edge_id(graph["edges"][0])])
    assert result["before"]["exposed_sources"] == result["after"]["exposed_sources"] == 2
    assert result["closed_sources"] == []
    result = simulate_remediation(graph, [edge_id(graph["edges"][0]), edge_id(graph["edges"][2])])
    assert result["after"]["exposed_sources"] == 0
    assert result["closed_sources"] == ["a", "b"]
    assert graph == original
    with pytest.raises(ValidationError):
        simulate_remediation(graph, [edge_id(graph["edges"][4])])


def test_simulator_keeps_parallel_permission_grants_and_cycles():
    graph = graph_fixture()
    graph["edges"].extend(
        [
            {"source": "a", "target": "t", "type": "Controls", "permission": "GenericAll"},
            {"source": "g", "target": "a", "type": "MemberOf"},
        ]
    )
    assert edge_id(graph["edges"][0]) != edge_id(graph["edges"][-2])
    result = simulate_remediation(graph, [edge_id(graph["edges"][0]), edge_id(graph["edges"][2])])
    assert result["after"]["exposed_sources"] == 2


def test_large_graph_does_not_abort_report_or_claim_zero_exposure():
    from analysis.remediation_simulator import MAX_NODES

    graph = {"nodes": [{"id": str(index)} for index in range(MAX_NODES + 1)], "edges": []}
    result = simulate_remediation(graph)
    assert result["available"] is False
    assert result["before"]["exposed_sources"] is None
    with pytest.raises(ValidationError):
        simulate_remediation(graph, ["selected-edge"])


def test_coverage_does_not_infer_execution_from_empty_default_results():
    _, center = bind()
    assert build_scan_coverage({}, [], center)["summary"]["execution_percent"] is None
    result = build_scan_coverage(
        {"analysis_execution": {"completed_steps": ["user_risks"], "skipped_steps": {"acl_security": "fast_profile"}}},
        [],
        center,
    )
    assert result["summary"]["completed_steps"] == 1
    assert result["summary"]["skipped_steps"] == 1
    assert all(row["status"] == "not_verified" for row in result["controls"])


def test_generated_collector_keeps_host_names_out_of_executable_source():
    risk = candidate()
    risk["affected_object"] = "'; Start-Process calc; # </script>"
    _, center = bind(risk)
    script = build_validation_script(center)
    assert risk["affected_object"] not in script
    assert "Get-Service" in script and "gpresult.exe /scope computer /x" in script
    assert "Set-AD" not in script and "Set-ItemProperty" not in script


@pytest.mark.parametrize("language,expected", [("en", "Finding Validation"), ("tr", "Bulgu Doğrulama")])
def test_report_workspace_is_localized_and_escapes_untrusted_reviews(language, expected):
    risk = candidate()
    risk["title"] = "</script><script>window.pwned=1</script>"
    risk, center = bind(risk)
    center["document"]["observations"] = [
        {"target": "<img src=x onerror=alert(1)>", "name": "test", "value": "<script>x</script>"}
    ]
    report = HTMLReportGenerator(language)._generate_html(
        [],
        [],
        [],
        [],
        [risk],
        [],
        100,
        None,
        inline_assets=False,
        review_center=center,
    )
    assert expected in report
    assert risk["title"] not in report
    assert "<img src=x onerror=alert(1)>" not in report
    match = re.search(r'<script type="application/json" id="assessment-workspace-data">(.*?)</script>', report, re.S)
    embedded = json.loads(match.group(1))
    assert embedded["center"]["findings"][0]["finding_id"] == risk["finding_id"]
    assert embedded["labels"]["confirmed"] == ("Confirmed" if language == "en" else "Doğrulandı")


def test_offline_report_roundtrip_needs_no_username_or_ldap(tmp_path, monkeypatch):
    scoring = score_and_consolidate({"zerologon_risks": [candidate()]}, deepcopy(DATA), domain=DOMAIN)
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text(
        json.dumps(
            {**DATA, "domain": DOMAIN, "risks": scoring["scored_risks"], "review_center": scoring["review_center"]},
            default=str,
        )
    )
    parser = build_parser()
    args = parser.parse_args(
        [
            "-d",
            DOMAIN,
            "--offline-snapshot",
            str(snapshot),
            "--output",
            str(tmp_path / "report.html"),
            "--json-export",
            str(tmp_path / "result.json"),
        ]
    )
    validate_cli_arguments(parser, args)
    monkeypatch.setattr("AtilKurt.LDAPConnection", lambda **kwargs: pytest.fail("Offline must not connect to LDAP"))
    generate_offline_report(args, empty_review_document(DOMAIN), [])
    result = json.loads((tmp_path / "result.json").read_text())
    assert result["review_center"]["findings"][0]["finding_id"] == scoring["scored_risks"][0]["finding_id"]
    assert (tmp_path / "report.html").is_file()


def test_installer_reuses_environment_is_quiet_and_preserves_commands(tmp_path):
    command_dir = tmp_path / "commands with spaces"
    command_dir.mkdir()
    environment = {
        **os.environ,
        "ATILKURT_BIN_DIR": str(command_dir),
        "ATILKURT_VENV_DIR": str(ROOT / ".venv"),
        "PATH": str(command_dir) + os.pathsep + os.environ["PATH"],
    }
    result = subprocess.run(
        ["bash", str(ROOT / "install.sh")], env=environment, capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert "Existing environment and dependencies are ready." in result.stdout
    assert "--review-file" in result.stdout and "--offline-snapshot" in result.stdout
    assert '--scope-file' in result.stdout and '--pdf-export' in result.stdout and '--sysvol-host' in result.stdout
    assert "Collecting " not in result.stdout
    commands = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in command_dir.iterdir()}
    result = subprocess.run(
        ["bash", str(ROOT / "install.sh")], env=environment, capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert commands == {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in command_dir.iterdir()}
    result = subprocess.run([str(command_dir / "Atilkurt"), "--version"], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0 and "AtilKurt" in result.stdout


def test_installer_does_not_overwrite_an_unrelated_existing_command(tmp_path):
    command = tmp_path / "Atilkurt"
    command.write_text("# unrelated existing command\n")
    environment = {**os.environ, "ATILKURT_BIN_DIR": str(tmp_path), "ATILKURT_VENV_DIR": str(ROOT / ".venv")}
    result = subprocess.run(
        ["bash", str(ROOT / "install.sh")], env=environment, capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 1
    assert "instead of overwriting" in result.stderr
    assert command.read_text() == "# unrelated existing command\n"


def test_installer_configures_shell_path_once_and_preserves_existing_settings(tmp_path):
    command_dir = tmp_path / "commands with spaces"
    profile = tmp_path / ".zshrc"
    existing = "# existing user setting\nexport EXISTING_SETTING=keep\n"
    profile.write_text(existing)
    environment = {
        **os.environ,
        "ATILKURT_BIN_DIR": str(command_dir),
        "ATILKURT_VENV_DIR": str(ROOT / ".venv"),
        "SHELL": "/bin/zsh",
        "ZDOTDIR": str(tmp_path),
    }
    for _ in range(2):
        result = subprocess.run(
            ["bash", str(ROOT / "install.sh")], env=environment, capture_output=True, text=True, timeout=60
        )
        assert result.returncode == 0, result.stderr
    assert profile.read_text().startswith(existing)
    assert profile.read_text().count("# AtilKurt command path") == 1
    result = subprocess.run(
        ["bash", "-c", 'source "$1"; command -v Atilkurt', "test", str(profile)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0 and result.stdout.strip() == str(command_dir / "Atilkurt")

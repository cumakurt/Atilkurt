"""Accuracy, evidence integrity, retest, history, task and integration regressions."""

from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import base64
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

from Crypto.PublicKey import RSA
import pytest

from AtilKurt import build_parser, generate_offline_report, load_workflow_inputs, validate_cli_arguments
from analysis.dcsync_analyzer import DCSyncAnalyzer
from analysis.registry import get_analysis_step_keys
from analysis.remediation_verifier import verify_remediation
from analysis.root_cause_analyzer import group_root_causes
from analysis.rule_quality import SID, _descriptor, builtin_cases, evaluate_quality
from analysis.scan_coverage import build_scan_coverage
from core.ad_security import principal_group_tokens
from core.assessment_history import AssessmentHistory
from core.diagnostics import collection_health, run_doctor
from core.effective_access import collect_effective_tokens
from core.evidence_signing import read_json, sign_document, unwrap_document, write_document
from core.exceptions import LDAPSearchError, ValidationError
from core.finding_review import FindingReviewManager, empty_review_document, load_review_document
from core.ldap_connection import LDAPConnection
from core.product_workflow import export_product_workspace, prepare_product_workspace
from core.utility_cli import run_watch, utility_main
from reporting.export_formats import ExportFormats
from reporting.html_report import HTMLReportGenerator

DOMAIN = "example.com"
NOW = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]


def sample():
    directory = {"users": [], "groups": [], "computers": [], "gpos": []}
    risk = {
        "type": "password_policy_weak",
        "severity": "critical",
        "title": "Minimum password length is 6",
        "affected_object": DOMAIN,
        "object_type": "domain",
        "evidence": {"minPwdLength": 6},
    }
    center = FindingReviewManager().apply([risk], directory, DOMAIN, now=NOW)
    coverage = build_scan_coverage(
        {"analysis_execution": {"completed_steps": list(get_analysis_step_keys())}}, [risk], center
    )
    return directory, risk, center, coverage


@pytest.fixture(scope="module")
def signing_keys(tmp_path_factory):
    directory = tmp_path_factory.mktemp("signing")
    key = RSA.generate(2048)
    private, public = directory / "private.pem", directory / "public.pem"
    private.write_bytes(key.export_key(pkcs=8))
    public.write_bytes(key.public_key().export_key())
    return str(private), str(public)


def test_builtin_quality_cases_measure_real_rule_predictions():
    result = evaluate_quality()
    assert result["summary"] == {"cases": 49, "passed": 49, "failed": 0, "evaluated_families": 9}
    assert all(row["false_positive"] == row["false_negative"] == 0 for row in result["rules"])
    assert next(row for row in result["rules"] if row["rule"] == "zerologon")["precision"] is None


def test_quality_counts_missed_positive_abstentions_and_false_promotions():
    cases = [
        {"id": "miss", "rule": "dcsync", "expected": "positive", "input": {"grants": []}},
        {"id": "false", "rule": "dcsync", "expected": "negative", "input": {"grants": [{"mask": 0x100}]}},
        {
            "id": "unknown_miss",
            "rule": "zerologon",
            "expected": "positive",
            "input": {
                "computers": [{"name": "dc01", "userAccountControl": 8192, "operatingSystem": "Windows Server 2016"}]
            },
        },
    ]
    result = evaluate_quality(cases)
    assert result["summary"]["failed"] == 3
    assert result["rules"][0]["false_negative"] == result["rules"][0]["false_positive"] == 1
    assert result["rules"][1]["false_negative"] == result["rules"][1]["abstained"] == 1
    assert result["rules"][1]["recall"] == 0


def test_quality_registry_adapter_can_evaluate_other_registered_analyzers():
    cases = [
        {
            "id": "policy",
            "rule": "registry",
            "expected": "positive",
            "input": {"steps": ["password_policy"], "ldap_rows": [{"minPwdLength": 6}]},
        }
    ]
    assert evaluate_quality(cases)["summary"]["passed"] == 1
    with pytest.raises(ValidationError):
        evaluate_quality([*builtin_cases(), builtin_cases()[0]])


def test_doctor_runs_locally_without_a_domain_or_credentials():
    result = run_doctor()
    assert result["summary"]["fail"] == 0
    assert {"python", "ldap3", "pycryptodome", "impacket", "reportlab", "ca_store"} == {check["name"] for check in result["checks"]}


def test_query_health_records_completion_missing_visibility_and_failed_reads():
    connection = LDAPConnection(DOMAIN, "auditor", "test-only-password", "dc01.example.com", max_retries=1)
    connection.connection = SimpleNamespace(result={"result": 0})
    rows = [{"objectSid": SID, "description": "sensitive-value"}]
    assert connection._audited_query(lambda: rows, "root", "(x=y)", ["objectSid", "msLAPS-Password"], 0, "BASE") == rows

    def fail():
        raise LDAPSearchError("denied")

    with pytest.raises(LDAPSearchError):
        connection._audited_query(fail, "root", "(x=y)", ["nTSecurityDescriptor"], 0, "BASE")
    health = collection_health(connection)
    assert health["status"] == "partial" and health["failed_queries"] == 1
    assert health["queries"][0]["unobserved_attributes"] == ["msLAPS-Password"]
    assert "sensitive-value" not in json.dumps(health)
    assert collection_health()["status"] == "unknown"


def test_empty_and_partially_missing_attributes_are_not_visible_values():
    connection = LDAPConnection(DOMAIN, "auditor", "test-only-password", "dc01.example.com", max_retries=1)
    connection.connection = SimpleNamespace(result={"result": 0})
    connection._audited_query(
        lambda: [{"nTSecurityDescriptor": b"descriptor", "minPwdLength": 0}, {"nTSecurityDescriptor": None}],
        "root",
        "(x=y)",
        ["nTSecurityDescriptor", "minPwdLength"],
        0,
        "BASE",
    )
    record = collection_health(connection)["queries"][0]
    assert record["unobserved_attribute_counts"] == {"nTSecurityDescriptor": 1, "minPwdLength": 1}
    connection._audited_query(lambda: [{"minPwdLength": None}], "root", "(x=y)", ["minPwdLength"], 0, "BASE")
    assert collection_health(connection)["queries"][1]["unobserved_attributes"] == ["minPwdLength"]


def test_token_collection_is_bounded_and_validates_principal_identity():
    directory, _, _, _ = sample()
    directory["users"] = [
        {
            "sAMAccountName": f"user{index}",
            "objectSid": SID + str(index),
            "distinguishedName": f"CN=user{index},DC=example,DC=com",
        }
        for index in range(3)
    ]
    risks = [{"trustee": row["objectSid"]} for row in directory["users"]]
    ldap = Mock()
    ldap.base_search.return_value = [{"objectSid": SID + "0", "tokenGroups": [SID + "9"]}]
    result = collect_effective_tokens(ldap, directory, risks, limit=1, delay=0)
    assert result["collected"] == 1 and result["limited"] == 2
    assert ldap.base_search.call_count == 1
    assert SID + "9" in principal_group_tokens(directory["users"], [])[SID + "0"]
    ldap.base_search.return_value = [{"objectSid": SID + "99", "tokenGroups": [SID + "9"]}]
    fresh = deepcopy(directory)
    result = collect_effective_tokens(ldap, fresh, risks, limit=1, delay=0)
    assert result["collected"] == 0
    assert fresh["users"][0]["token_group_evidence"]["status"] == "unknown"
    assert SID + "9" not in principal_group_tokens(fresh["users"], [])[SID + "0"]


def test_collected_deny_group_blocks_replication_without_promoting_unknown_access():
    deny_sid = SID + "9"
    account = {
        "sAMAccountName": "delegate",
        "objectSid": SID,
        "userAccountControl": 512,
        "tokenGroups": [deny_sid],
        "token_group_evidence": {"status": "collected"},
    }
    grants = [{"mask": 0x100, "denied": True, "sid": deny_sid}, {"mask": 0x100, "sid": SID}]
    ldap = SimpleNamespace(
        base_dn="DC=example,DC=com", search=lambda **_: [{"nTSecurityDescriptor": _descriptor(grants)}]
    )
    assert DCSyncAnalyzer(ldap).analyze_dcsync_rights([account], []) == []
    account.pop("token_group_evidence")
    assert len(DCSyncAnalyzer(ldap).analyze_dcsync_rights([account], [])) == 1


def test_signed_reviews_verify_only_with_explicit_trusted_keys(tmp_path, signing_keys):
    private, public = signing_keys
    document = empty_review_document(DOMAIN)
    wrapped = sign_document(document, private)
    path = tmp_path / "signed.json"
    write_document(str(path), wrapped)
    assert (
        load_review_document(str(path), DOMAIN, trusted_keys=[public], require_signed=True)["signature_verification"][
            "status"
        ]
        == "verified"
    )
    with pytest.raises(ValidationError):
        load_review_document(str(path), DOMAIN)
    wrapped["payload"] = wrapped["payload"][:-1] + ("A" if wrapped["payload"][-1] != "A" else "B")
    with pytest.raises(ValidationError):
        unwrap_document(wrapped, [public], True)


def test_unsigned_evidence_cannot_fake_signature_metadata(tmp_path):
    path = tmp_path / "unsigned.json"
    write_document(str(path), {**empty_review_document(DOMAIN), "signature_verification": {"status": "verified"}})
    assert load_review_document(str(path), DOMAIN)["signature_verification"]["status"] == "unsigned"
    with pytest.raises(ValidationError):
        load_review_document(str(path), DOMAIN, require_signed=True)


@pytest.mark.parametrize(
    "header", [b'{"alg":"HS256","typ":"ATILKURT-EVIDENCE","kid":"untrusted"}', b"[" * 1500 + b"0" + b"]" * 1500]
)
def test_invalid_signature_algorithms_and_nested_headers_are_rejected(header):
    wrapped = {"protected": base64.urlsafe_b64encode(header).rstrip(b"=").decode(), "payload": "e30", "signature": "AA"}
    with pytest.raises(ValidationError):
        unwrap_document(wrapped)


def test_retest_requires_fresh_full_coverage_and_retains_pending_results():
    directory, risk, center, coverage = sample()
    previous = {**directory, "domain": DOMAIN, "risks": [risk], "review_center": center}
    current = {
        **directory,
        "scan_context": {"fresh_ldap": True, "collected_at": NOW.isoformat()},
        "collection_health": {"status": "completed"},
    }
    assert verify_remediation(previous, [], current, coverage, DOMAIN, now=NOW)["findings"][0]["status"] == "resolved"
    for changed in (
        {**current, "scan_context": {"fresh_ldap": False, "collected_at": NOW.isoformat()}},
        {**current, "collection_health": {"status": "partial"}},
        {**current, "scan_context": {"fresh_ldap": True, "collected_at": (NOW - timedelta(days=2)).isoformat()}},
    ):
        assert (
            verify_remediation(previous, [], changed, coverage, DOMAIN, now=NOW)["findings"][0]["status"]
            == "insufficient_evidence"
        )
    partial = {"analysis_steps": [coverage["analysis_steps"][0]]}
    assert (
        verify_remediation(previous, [], current, partial, DOMAIN, now=NOW)["findings"][0]["status"]
        == "insufficient_evidence"
    )
    pending = {**risk, "finding_status": "needs_validation", "score_excluded": True}
    assert (
        verify_remediation(previous, [pending], current, coverage, DOMAIN, now=NOW)["findings"][0]["status"]
        == "insufficient_evidence"
    )
    assert (
        verify_remediation(previous, [risk], current, coverage, DOMAIN, now=NOW)["findings"][0]["status"]
        == "still_present"
    )


def test_retest_unknown_selection_and_changed_rules_cannot_close():
    directory, risk, center, coverage = sample()
    previous = {**directory, "domain": DOMAIN, "risks": [risk], "review_center": center}
    current = {
        **directory,
        "scan_context": {"fresh_ldap": True, "collected_at": NOW.isoformat()},
        "collection_health": {"status": "completed"},
    }
    with pytest.raises(ValidationError):
        verify_remediation(previous, [], current, coverage, DOMAIN, ["unknown"], now=NOW)
    previous["risks"][0]["rule_version"] = "old"
    assert (
        verify_remediation(previous, [], current, coverage, DOMAIN, now=NOW)["findings"][0]["status"]
        == "insufficient_evidence"
    )


def test_shared_grants_group_derived_paths_without_mutating_or_merging_unrelated_conditions():
    graph = {
        "nodes": [{"id": "a", "label": "alice", "sid": SID}, {"id": "t", "label": "Tier 0"}],
        "edges": [{"source": "a", "target": "t", "type": "Controls", "permission": "WriteDACL"}],
    }
    risks = [
        {"finding_id": "grant", "trustee": SID, "affected_object": "Tier 0", "permission": "WriteDACL"},
        {"finding_id": "path", "affected_object": "alice", "evidence": {"path": ["a", "t"]}},
        {"finding_id": "other", "affected_object": "alice", "title": "Separate condition"},
    ]
    original = deepcopy(risks)
    result = group_root_causes(risks, graph)
    assert result["groups"][0]["finding_ids"] == ["grant", "path"]
    assert result["summary"]["shared_causes"] == 1
    assert risks == original


def test_history_deduplicates_critical_alerts_and_tracks_fresh_vs_rebuilt_runs(tmp_path):
    directory, risk, _, coverage = sample()
    with AssessmentHistory(str(tmp_path / "history.db")) as history:
        first = history.record_scan(DOMAIN, [risk], 20, coverage, {"fresh_ldap": True}, {})
        second = history.record_scan(DOMAIN, [risk], 20, coverage, {"fresh_ldap": True}, {})
        assert [row["kind"] for row in first["notifications"]] == ["new_critical"]
        assert second["notifications"] == second["changed_finding_ids"] == []
        history.record_scan(DOMAIN, [risk], 20, coverage, {"fresh_ldap": False}, {})
        assert history.runs(DOMAIN)[0]["fresh"] == 0
        assert history.runs("other.example.com") == []
        assert history.tasks(DOMAIN)[0]["external_id"] == "AK-" + risk["finding_id"]
        assert history.audit_document()["entries"]
    if os.name == "posix":
        assert (tmp_path / "history.db").stat().st_mode & 0o777 == 0o600


def test_concurrent_history_scans_emit_one_critical_alert_and_keep_a_valid_chain(tmp_path):
    _, risk, _, coverage = sample()
    path = str(tmp_path / "history.db")
    with AssessmentHistory(path):
        pass

    def record(_):
        with AssessmentHistory(path) as history:
            return history.record_scan(DOMAIN, [risk], 20, coverage, {"fresh_ldap": True}, {})

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(record, range(8)))
    assert sum(len(result["notifications"]) for result in results) == 1
    with AssessmentHistory(path) as history:
        assert len(history.runs(DOMAIN)) == 8
        assert history.audit_document()["chain_head"] != "0" * 64


def test_history_does_not_resolve_missing_findings_without_fresh_verification(tmp_path):
    _, risk, _, coverage = sample()
    with AssessmentHistory(str(tmp_path / "history.db")) as history:
        history.record_scan(DOMAIN, [risk], 20, coverage, {"fresh_ldap": True}, {})
        history.record_scan(DOMAIN, [], 100, coverage, {"fresh_ldap": True}, {})
        state = history.connection.execute("SELECT state FROM findings").fetchone()[0]
        assert state == "unassessed"
        assert history.tasks(DOMAIN)[0]["status"] == "open"


def test_verified_closure_closes_task_and_reappearance_alerts_once(tmp_path):
    _, risk, _, coverage = sample()
    with AssessmentHistory(str(tmp_path / "history.db")) as history:
        history.record_scan(DOMAIN, [risk], 20, coverage, {"fresh_ldap": True}, {})
        proof = {"findings": [{"finding_id": risk["finding_id"], "status": "resolved"}]}
        history.record_scan(DOMAIN, [], 100, coverage, {"fresh_ldap": True}, proof)
        assert history.tasks(DOMAIN)[0]["status"] == "resolved"
        changed = history.record_scan(DOMAIN, [risk], 20, coverage, {"fresh_ldap": True}, {})
        assert [row["kind"] for row in changed["notifications"]] == ["reopened"]
        assert history.tasks(DOMAIN)[0]["status"] == "open"
        assert "verified_run_id" not in history.tasks(DOMAIN)[0]
        assert history.record_scan(DOMAIN, [risk], 20, coverage, {"fresh_ldap": True}, {})["notifications"] == []


def test_expired_exception_alert_is_emitted_once(tmp_path):
    _, risk, _, coverage = sample()
    with AssessmentHistory(str(tmp_path / "history.db")) as history:
        history.record_scan(DOMAIN, [{**risk, "exception_status": "active"}], 100, coverage, {"fresh_ldap": True}, {})
        expired = {**risk, "exception_status": "expired"}
        result = history.record_scan(DOMAIN, [expired], 20, coverage, {"fresh_ldap": True}, {})
        assert [row["kind"] for row in result["notifications"]] == ["exception_expired"]
        assert history.record_scan(DOMAIN, [expired], 20, coverage, {"fresh_ldap": True}, {})["notifications"] == []


def test_task_import_is_idempotent_and_cannot_claim_unverified_closure(tmp_path):
    _, risk, _, coverage = sample()
    with AssessmentHistory(str(tmp_path / "history.db")) as history:
        history.record_scan(DOMAIN, [risk], 20, coverage, {"fresh_ldap": True}, {})
        document = {
            "schema_version": 1,
            "domain": DOMAIN,
            "tickets": [
                {
                    "finding_id": risk["finding_id"],
                    "owner": "directory-team",
                    "status": "in_progress",
                    "due_at": (NOW + timedelta(days=7)).isoformat(),
                    "notes": "Review exact grant",
                }
            ],
        }
        history.apply_tasks(document, DOMAIN)
        count = len(history.audit_document()["entries"])
        history.apply_tasks(document, DOMAIN)
        assert len(history.audit_document()["entries"]) == count
        assert history.tasks(DOMAIN)[0]["owner"] == "directory-team"
        document["tickets"][0]["status"] = "resolved"
        with pytest.raises(ValidationError):
            history.apply_tasks(document, DOMAIN)


def test_audit_detects_changed_prior_entries(tmp_path):
    _, risk, _, coverage = sample()
    with AssessmentHistory(str(tmp_path / "history.db")) as history:
        history.record_scan(DOMAIN, [risk], 20, coverage, {"fresh_ldap": True}, {})
        history.connection.execute("UPDATE audit SET body='{}' WHERE seq=1")
        with pytest.raises(ValidationError):
            history.audit_document()


def test_cef_and_siem_exports_preserve_ids_states_and_escape_headers(tmp_path):
    _, risk, _, _ = sample()
    risk.update(type="risk|injected\nheader", finding_status="needs_validation", score_excluded=True)
    cef, siem = tmp_path / "events.cef", tmp_path / "events.jsonl"
    ExportFormats.export_cef([risk], str(cef), DOMAIN)
    ExportFormats.export_siem_json([risk], str(siem), DOMAIN)
    assert cef.read_text().count("\n") == 1
    assert r"risk\|injected header" in cef.read_text()
    assert "|10|" in cef.read_text() and risk["finding_id"] in cef.read_text()
    event = json.loads(siem.read_text())
    assert event["finding_id"] == risk["finding_id"] and event["score_excluded"] is True
    stale = tmp_path / "empty.csv"
    stale.write_text("old events")
    ExportFormats.export_csv([], str(stale))
    assert "old events" not in stale.read_text() and "finding_id" in stale.read_text()


def test_changes_only_exports_clear_old_output_on_unchanged_scan(tmp_path):
    directory, risk, center, coverage = sample()
    args = build_parser().parse_args(
        [
            "-d",
            DOMAIN,
            "-u",
            "auditor",
            "--history-db",
            str(tmp_path / "history.db"),
            "--siem-export",
            str(tmp_path / "events.jsonl"),
            "--export-changes-only",
        ]
    )
    scoring = {"scored_risks": [risk], "domain_score": 20, "review_center": center, "scan_coverage": coverage}
    directory["scan_context"] = {"fresh_ldap": True}
    first = prepare_product_workspace(args, directory, {}, scoring)
    export_product_workspace(args, first, [risk])
    assert read_json(str(tmp_path / "events.jsonl"))["finding_id"] == risk["finding_id"]
    second = prepare_product_workspace(args, directory, {}, scoring)
    export_product_workspace(args, second, [risk])
    assert (tmp_path / "events.jsonl").read_text() == ""


def test_changes_only_exports_include_verified_closure_records(tmp_path):
    _, risk, _, coverage = sample()
    args = SimpleNamespace(domain=DOMAIN, export_changes_only=True, siem_export=str(tmp_path / "events.jsonl"))
    with AssessmentHistory(str(tmp_path / "history.db")) as history:
        history.record_scan(DOMAIN, [risk], 20, coverage, {"fresh_ldap": True}, {})
        verification = {"findings": [{"finding_id": risk["finding_id"], "status": "resolved"}]}
        result = history.record_scan(DOMAIN, [], 100, coverage, {"fresh_ldap": True}, verification)
        export_product_workspace(args, {"history": result, "quality": {}, "verification": {}, "tickets": []}, [])
        event = read_json(args.siem_export)
        assert event["finding_id"] == risk["finding_id"]
        assert event["finding_status"] == "resolved" and event["score_excluded"] is True


@pytest.mark.parametrize("language,title", [("en", "Accuracy &amp; Evidence"), ("tr", "Doğruluk ve Kanıt")])
def test_product_panes_are_bilingual_and_escape_task_and_signature_inputs(language, title):
    directory, risk, center, coverage = sample()
    args = SimpleNamespace(domain=DOMAIN)
    workspace = prepare_product_workspace(
        args,
        directory,
        {},
        {"scored_risks": [risk], "domain_score": 20, "review_center": center, "scan_coverage": coverage},
    )
    workspace["tickets"] = [
        {
            "finding_id": risk["finding_id"],
            "owner": "<img src=x onerror=alert(1)>",
            "status": "open",
            "due_at": None,
            "notes": "</script><script>alert(1)</script>",
        }
    ]
    report = HTMLReportGenerator(language)._generate_html(
        [],
        [],
        [],
        [],
        [risk],
        [],
        20,
        None,
        domain=DOMAIN,
        review_center=center,
        scan_coverage=coverage,
        product_workspace=workspace,
    )
    assert title in report
    assert "<img src=x onerror=alert(1)>" not in report
    assert 'id="task-draft-form"' in report and 'id="product-workspace-data"' in report


def test_signed_snapshot_rebuild_and_collector_import_do_not_open_ldap(tmp_path, signing_keys, monkeypatch):
    private, public = signing_keys
    directory, risk, center, _ = sample()
    snapshot = tmp_path / "snapshot.signed.json"
    write_document(str(snapshot), {**directory, "domain": DOMAIN, "risks": [risk], "review_center": center}, private)
    collector = tmp_path / "collector.signed.json"
    evidence = empty_review_document(DOMAIN)
    evidence["observations"] = [
        {
            "target": "dc01",
            "name": "LDAPServerIntegrity",
            "value": 0,
            "source": "registry",
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }
    ]
    write_document(str(collector), evidence, private)
    parser = build_parser()
    args = parser.parse_args(
        [
            "-d",
            DOMAIN,
            "--offline-snapshot",
            str(snapshot),
            "--trusted-key",
            public,
            "--require-signed-evidence",
            "--validation-evidence",
            str(collector),
            "--output",
            str(tmp_path / "report.html"),
            "--json-export",
            str(tmp_path / "result.json"),
        ]
    )
    validate_cli_arguments(parser, args)
    document, removed = load_workflow_inputs(args)
    monkeypatch.setattr("AtilKurt.LDAPConnection", lambda **_: pytest.fail("Offline must not connect"))
    generate_offline_report(args, document, removed)
    result = read_json(str(tmp_path / "result.json"))
    assert result["product_workspace"]["signatures"][0]["status"] == "verified"
    assert any(row["type"] == "posture_ldap_signing_weak" for row in result["risks"])
    assert result["scan_context"]["fresh_ldap"] is False


def test_utility_quality_and_doctor_commands_need_no_scan_credentials(tmp_path):
    for command in ("quality", "doctor"):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "AtilKurt.py"),
                command,
                "--output",
                str(tmp_path / (command + ".json")),
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr
        assert (tmp_path / (command + ".json")).is_file()
        assert "Password" not in result.stdout


def test_wrapper_keeps_utility_command_first_with_environment_defaults():
    command = 'source "$1"; ATILKURT_DOMAIN=example.com; ATILKURT_USER=auditor; build_application_arguments quality; printf "%s\\n" "${APPLICATION_ARGUMENTS[@]}"'
    result = subprocess.run(
        ["bash", "-c", command, "test", str(ROOT / "run.sh")], capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0 and result.stdout.strip() == "quality"


def test_watch_runs_bounded_cycles_without_exposing_secret_or_scan_noise(tmp_path, monkeypatch, capsys):
    secret = "test-only-watcher-secret"
    monkeypatch.setenv("ATILKURT_PASS", secret)
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        assert kwargs["env"]["ATILKURT_PASS"] == secret
        notifications = command[command.index("--notifications-export") + 1]
        write_document(notifications, {"notifications": []})
        kwargs["stdout"].write("unnecessary scan output\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("core.utility_cli.subprocess.run", execute)
    monkeypatch.setattr("core.utility_cli.time.sleep", lambda _: None)
    assert run_watch(["-d", DOMAIN, "-u", "auditor"], str(tmp_path / "history.db"), 60, 2, 10) == 0
    assert len(calls) == 2 and "--history-db" in calls[0]
    output = capsys.readouterr()
    assert secret not in output.out and "unnecessary scan output" not in output.out
    assert "ATILKURT_PASS" not in os.environ


def test_watch_rejects_resume_and_command_line_credentials():
    with pytest.raises(SystemExit):
        utility_main(["watch", "--password=unsafe"], lambda _: pytest.fail("Must not request credentials"))


@pytest.mark.parametrize("confirmed", [False, True])
def test_runtime_conditions_cannot_close_from_ldap_absence(confirmed):
    directory, risk, _, coverage = sample()
    risk.update(type="zerologon_vulnerable", cve="CVE-2020-1472")
    risk.pop("review_basis")
    center = FindingReviewManager().apply([risk], directory, DOMAIN, now=NOW)
    if confirmed:
        risk["finding_status"] = "confirmed"
        risk["evidence"] = {"vulnerability_confirmed": True}
    previous = {**directory, "domain": DOMAIN, "risks": [risk], "review_center": center}
    current = {
        **directory,
        "scan_context": {"fresh_ldap": True, "collected_at": NOW.isoformat()},
        "collection_health": {"status": "completed"},
    }
    assert (
        verify_remediation(previous, [], current, coverage, DOMAIN, now=NOW)["findings"][0]["status"]
        == "insufficient_evidence"
    )


def test_acl_absence_with_hidden_descriptors_cannot_close():
    directory, risk, _, coverage = sample()
    risk.update(type="dcsync_permissions", title="Replication rights")
    risk.pop("review_basis")
    center = FindingReviewManager().apply([risk], directory, DOMAIN, now=NOW)
    previous = {**directory, "domain": DOMAIN, "risks": [risk], "review_center": center}
    current = {
        **directory,
        "scan_context": {"fresh_ldap": True, "collected_at": NOW.isoformat()},
        "collection_health": {
            "status": "completed",
            "queries": [{"returned_objects": 2, "unobserved_attributes": ["nTSecurityDescriptor"]}],
        },
    }
    result = verify_remediation(previous, [], current, coverage, DOMAIN, now=NOW)
    assert result["findings"][0]["status"] == "insufficient_evidence"


def test_missing_password_policy_values_cannot_prove_closure():
    directory, risk, center, coverage = sample()
    previous = {**directory, "domain": DOMAIN, "risks": [risk], "review_center": center}
    current = {
        **directory,
        "scan_context": {"fresh_ldap": True, "collected_at": NOW.isoformat()},
        "collection_health": {"status": "completed", "queries": [{"unobserved_attributes": ["minPwdLength"]}]},
    }
    assert (
        verify_remediation(previous, [], current, coverage, DOMAIN, now=NOW)["findings"][0]["status"]
        == "insufficient_evidence"
    )


def test_history_audit_records_review_attributions(tmp_path):
    directory, risk, center, coverage = sample()
    center["document"]["reviews"] = [
        {
            "finding_id": risk["finding_id"],
            "status": "insufficient_evidence",
            "reviewer": "directory-team",
            "reviewed_at": NOW.isoformat(),
        }
    ]
    args = SimpleNamespace(domain=DOMAIN, history_db=str(tmp_path / "history.db"))
    scoring = {"scored_risks": [risk], "domain_score": 20, "review_center": center, "scan_coverage": coverage}
    prepare_product_workspace(args, directory, {}, scoring)
    with AssessmentHistory(args.history_db) as history:
        entry = history.audit_document()["entries"][-1]["body"]
        assert entry["details"]["review_decisions"][0]["reviewer"] == "directory-team"


def test_watch_reports_signed_notifications(tmp_path, signing_keys, monkeypatch, capsys):
    private, _ = signing_keys
    monkeypatch.setenv("ATILKURT_PASS", "test-only-secret")

    def execute(command, **kwargs):
        path = command[command.index("--notifications-export") + 1]
        write_document(path, {"notifications": [{"kind": "new_critical"}]}, private)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("core.utility_cli.subprocess.run", execute)
    assert run_watch(["-d", DOMAIN, "-u", "auditor", "--signing-key=" + private], str(tmp_path / "history.db"), 60, 1, 10) == 0
    assert "Important changes: 1" in capsys.readouterr().out


def test_signed_envelope_limit_allows_encoding_overhead(tmp_path, signing_keys, monkeypatch):
    private, public = signing_keys
    monkeypatch.setattr("core.evidence_signing.MAX_DOCUMENT_BYTES", 1024)
    path = tmp_path / "signed.json"
    document = {"data": "x" * 1000}
    write_document(str(path), document, private)
    assert path.stat().st_size > 1024
    assert unwrap_document(read_json(str(path)), [public])[0] == document
    with pytest.raises(ValidationError):
        unwrap_document({"data": "x" * 1025})


def test_doctor_wrapper_does_not_reuse_html_output_default():
    command = 'source "$1"; ATILKURT_OUTPUT=report.html; build_application_arguments doctor; printf "%s\\n" "${APPLICATION_ARGUMENTS[@]}"'
    result = subprocess.run(
        ["bash", "-c", command, "test", str(ROOT / "run.sh")], capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0 and result.stdout.strip() == "doctor"

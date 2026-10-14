"""Regression checks for assessment identity, publication and history boundaries."""

import json
import os
from types import SimpleNamespace

import pytest

import AtilKurt
from analysis.assessment_da_paths import identity_source_ids, enumerate_tier0_routes
from core.assessment_history import AssessmentHistory
from core.assessment_identity import match_inventory_principal
from core.directory_redaction import redact_credential_text

DOMAIN = "example.com"
BASE = "DC=example,DC=com"
SID = "S-1-5-21-1-2-3-1100"


def snapshot_data():
    return {
        "domain": DOMAIN,
        "users": [{"sAMAccountName": "alice", "objectSid": SID, "distinguishedName": "CN=Alice," + BASE}],
        "groups": [],
        "computers": [],
        "gpos": [],
        "risks": [],
        "collection_health": {"status": "completed"},
        "assessment_identity": {
            "sam": "alice",
            "sid": SID,
            "dn": "CN=Alice," + BASE,
            "resolved": True,
            "token_groups": {"status": "collected", "sids": ["S-1-5-21-1-2-3-1200"]},
        },
    }


def run_offline(tmp_path, monkeypatch, snapshot, *, extra_args=()):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(snapshot), encoding="utf-8")
    monkeypatch.setattr(AtilKurt, "LDAPConnection", lambda **_: pytest.fail("Offline must not bind"))
    monkeypatch.setattr(
        "sys.argv",
        [
            "atilkurt",
            "-d",
            DOMAIN,
            "--offline-snapshot",
            str(source),
            "--output",
            str(tmp_path / "report.html"),
            "--json-export",
            str(tmp_path / "result.json"),
            *extra_args,
        ],
    )
    code = 0
    try:
        AtilKurt.main()
    except SystemExit as exc:
        code = exc.code
    return code, json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "assignment",
    [
        'password = "first second third"',
        "pass = 'first second third'",
        r'pwd = "first \"second\" third"',
        'password = "first second third',
        "passwd = 'first second third",
        'api_key = "first second third"',
        "Authorization: Bearer first-second-third",
    ],
)
def test_directory_redaction_hides_complete_values(assignment):
    result = redact_credential_text(assignment)
    assert "first" not in result and "second" not in result and "third" not in result
    assert "[REDACTED]" in result


def test_directory_redaction_preserves_noncredential_words():
    text = "bypass=true; password policy managed by IT"
    assert redact_credential_text(text) == text


def test_offline_republication_redacts_legacy_inventory(tmp_path, monkeypatch):
    snapshot = snapshot_data()
    snapshot["users"][0]["description"] = 'password = "test-only first second"'
    code, exported = run_offline(tmp_path, monkeypatch, snapshot, extra_args=['--redact-secrets'])
    assert code == 0
    for path in (tmp_path / "report.html", tmp_path / "result.json"):
        assert "test-only" not in path.read_text(encoding="utf-8")
        assert "first second" not in path.read_text(encoding="utf-8")
    assert "[REDACTED]" in exported["users"][0]["description"]
    assert "test-only" in (tmp_path / "source.json").read_text(encoding="utf-8")


def test_offline_roundtrip_preserves_bind_identity(tmp_path, monkeypatch):
    snapshot = snapshot_data()
    code, exported = run_offline(tmp_path, monkeypatch, snapshot)
    assert code == 0
    assert exported["assessment_identity"] == snapshot["assessment_identity"]
    assert exported["domain_admin_takeover"]["from_assessment_account"]["sam"] == "alice"
    assert exported["scan_context"]["fresh_ldap"] is False


@pytest.mark.parametrize("health", ["partial", "failed", "unknown"])
def test_offline_cli_preserves_incomplete_status(tmp_path, monkeypatch, health):
    snapshot = snapshot_data()
    snapshot["collection_health"]["status"] = health
    code, exported = run_offline(tmp_path, monkeypatch, snapshot)
    assert code == 2
    assert exported["domain_score"] is None
    assert "appears to be in good standing" not in (tmp_path / "report.html").read_text(encoding="utf-8")


def test_offline_cli_preserves_partial_analysis_status(tmp_path, monkeypatch):
    snapshot = snapshot_data()
    snapshot["analysis_execution"] = {"partial_steps": {"dcsync": "ldap_query_failed"}}
    code, exported = run_offline(tmp_path, monkeypatch, snapshot)
    assert code == 2
    assert exported["domain_score"] is None


def test_checkpoint_builder_redacts_unprocessed_inventory():
    data = snapshot_data()
    data["users"][0]["description"] = 'pwd="first second third"'
    checkpoint = AtilKurt.build_checkpoint_payload(SimpleNamespace(domain=DOMAIN), data, {}, {}, {})
    assert "first" not in json.dumps(checkpoint)
    assert "[REDACTED]" in checkpoint["data"]["users"][0]["description"]


@pytest.mark.parametrize("alias", ["same", "hardlink", "symlink"])
def test_outputs_cannot_replace_tls_ca_input(tmp_path, alias):
    ca = tmp_path / "company-ca.pem"
    ca.write_text("test-only CA input", encoding="utf-8")
    output = ca if alias == "same" else tmp_path / "output.pem"
    if alias == "hardlink":
        os.link(ca, output)
    elif alias == "symlink":
        output.symlink_to(ca)
    args = AtilKurt.build_parser().parse_args(
        [
            "-d",
            DOMAIN,
            "-u",
            "alice",
            "--ca-certs-file",
            str(ca),
            "--output",
            str(output),
        ]
    )
    with pytest.raises(SystemExit):
        AtilKurt.validate_output_paths(args)
    assert ca.read_text(encoding="utf-8") == "test-only CA input"


def test_bind_dn_takes_precedence_over_another_accounts_sam():
    decoy = {"sAMAccountName": "alice", "distinguishedName": "CN=Other," + BASE}
    actual = {"sAMAccountName": "alice.admin", "distinguishedName": "CN=Alice," + BASE}
    assert match_inventory_principal([decoy, actual], [], sam="alice", dn=actual["distinguishedName"]) is actual
    assert match_inventory_principal([decoy], [], sam="alice", dn=actual["distinguishedName"]) is None


def test_ambiguous_bind_sam_stays_unresolved():
    records = [{"sAMAccountName": "alice", "distinguishedName": f"CN=Alice,OU={ou}," + BASE} for ou in ("A", "B")]
    assert match_inventory_principal(records, [], sam="alice", dn="") is None


def test_graph_identity_does_not_override_sid_conflict_with_a_name():
    identity = {"sam": "alice", "sid": SID, "dn": "CN=Alice," + BASE}
    graph = {
        "nodes": [
            {"id": "actual", "sid": SID, "label": "alice"},
            {"id": "foreign", "sid": "S-1-5-21-4-5-6-1100", "label": "alice"},
        ]
    }
    assert identity_source_ids(graph, identity) == ["actual"]


def test_fresh_history_kpis_survive_offline_reassessment(tmp_path):
    risk = {"finding_id": "test-id", "type": "dcsync_rights", "severity": "critical"}
    with AssessmentHistory(str(tmp_path / "history.sqlite3")) as history:
        history.record_scan(DOMAIN, [risk], 20, {}, {"fresh_ldap": True}, {})
        before = history.finding_kpi_snapshot(DOMAIN)
        history.record_scan(DOMAIN, [{**risk, "severity": "low"}], 95, {}, {"fresh_ldap": False}, {})
        assert history.finding_kpi_snapshot(DOMAIN) == before


def test_legacy_kpi_history_does_not_invent_counts(tmp_path):
    with AssessmentHistory(str(tmp_path / "history.sqlite3")) as history:
        history.record_scan(DOMAIN, [], 80, {}, {"fresh_ldap": True}, {})
        history.connection.execute("UPDATE runs SET summary=?", (json.dumps({"supported": 0}),))
        snapshot = history.finding_kpi_snapshot(DOMAIN)
        assert snapshot["critical"] is None and snapshot["high"] is None


def test_route_pruning_keeps_all_simple_paths_within_depth():
    graph = {
        "nodes": [{"id": key, "label": key, "privileged": key == "da"} for key in ("a", "b", "c", "da", "dead")],
        "edges": [
            {"source": a, "target": b, "type": "Controls"}
            for a, b in [("a", "b"), ("a", "c"), ("b", "c"), ("c", "b"), ("b", "da"), ("c", "da"), ("a", "dead")]
        ],
    }
    paths = {tuple(route["path"]) for route in enumerate_tier0_routes(graph, ["a"], max_depth=3)}
    assert paths == {("a", "b", "da"), ("a", "c", "da"), ("a", "b", "c", "da"), ("a", "c", "b", "da")}
    assert len(enumerate_tier0_routes(graph, ["a"], max_depth=2)) == 2


@pytest.mark.parametrize("computed, expected", [(0, False), (16, True), ("16", True), ([16], True), (None, None)])
def test_lockout_uses_current_computed_flags(computed, expected):
    from unittest.mock import Mock
    from core.collectors.user_collector import UserCollector
    from analysis.user_risks import UserRiskAnalyzer

    ldap = Mock()
    ldap.search.return_value = [
        {
            "sAMAccountName": "alice",
            "userAccountControl": 512,
            "lockoutTime": 132000000000000000,
            "msDS-User-Account-Control-Computed": computed,
        }
    ]
    users = UserCollector(ldap, show_progress=False).collect()
    assert "msDS-User-Account-Control-Computed" in ldap.search.call_args.kwargs["attributes"]
    assert users[0]["isLocked"] is expected
    findings = UserRiskAnalyzer().analyze(users)
    assert any(risk["type"] == "locked_user_account" for risk in findings) == (expected is True)


@pytest.mark.parametrize("kind", ["user", "computer"])
@pytest.mark.parametrize("value", [116444736000000000, "116444736000000000"])
def test_collector_filetime_is_utc(kind, value):
    from datetime import datetime, timezone
    from core.collectors.user_collector import UserCollector
    from core.collectors.computer_collector import ComputerCollector

    collector = (UserCollector if kind == "user" else ComputerCollector)(None, show_progress=False)
    assert collector._convert_timestamp(value) == datetime(1970, 1, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize("kind", ["user", "computer"])
@pytest.mark.parametrize("value", [0, -1, 9223372036854775807, 10**1000])
def test_collector_filetime_handles_never_and_out_of_range(kind, value):
    from core.collectors.user_collector import UserCollector
    from core.collectors.computer_collector import ComputerCollector

    collector = (UserCollector if kind == "user" else ComputerCollector)(None, show_progress=False)
    assert collector._convert_timestamp(value) is None

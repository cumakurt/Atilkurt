"""Assessment-account Domain Admin routes, leftover catalog, SYSVOL, CISO trends."""

from __future__ import annotations

from unittest.mock import Mock

from analysis.assessment_da_paths import (
    build_assessment_account_view,
    enumerate_tier0_routes,
    identity_source_ids,
)
from analysis.domain_admin_takeover_analyzer import (
    DA_PATH_CATALOG,
    DomainAdminTakeoverAnalyzer,
)
from core.assessment_history import AssessmentHistory
from core.assessment_identity import bind_sam, parse_who_am_i, resolve_assessment_identity
from reporting.ciso_dashboard import CISODashboardGenerator
from reporting.report_sections.domain_admin_section import DomainAdminSectionMixin

DOMAIN = "example.com"
ALICE_SID = "S-1-5-21-1-2-3-1100"
HELPDESK_SID = "S-1-5-21-1-2-3-1200"
DA_SID = "S-1-5-21-1-2-3-512"


def _graph():
    return {
        "nodes": [
            {"id": "user:alice", "label": "alice", "sid": ALICE_SID, "kind": "user", "privileged": False},
            {"id": "group:helpdesk", "label": "Helpdesk", "sid": HELPDESK_SID, "kind": "group", "privileged": False},
            {
                "id": "group:da",
                "label": "Domain Admins",
                "sid": DA_SID,
                "kind": "group",
                "privileged": True,
            },
        ],
        "edges": [
            {"source": "user:alice", "target": "group:helpdesk", "type": "MemberOf"},
            {"source": "group:helpdesk", "target": "group:da", "type": "Controls"},
            {"source": "forest", "target": "group:da", "type": "InboundTrust"},
        ],
    }


def test_bind_sam_and_who_am_i_parsing():
    assert bind_sam(r"CONTOSO\auditor") == "auditor"
    assert bind_sam("auditor@contoso.com") == "auditor"
    assert parse_who_am_i("u:CONTOSO\\alice") == {"sam": "alice", "dn": ""}
    parsed = parse_who_am_i("dn:CN=alice,CN=Users,DC=example,DC=com")
    assert parsed["sam"] == "alice"
    assert parsed["dn"].startswith("CN=alice")


def test_resolve_assessment_identity_matches_inventory_and_reads_token_groups():
    ldap = Mock()
    ldap.username = r"EXAMPLE\alice"
    ldap.connection.extend.standard.who_am_i.return_value = "u:EXAMPLE\\alice"
    ldap.base_search.return_value = [{"objectSid": ALICE_SID, "tokenGroups": [HELPDESK_SID]}]
    users = [{"sAMAccountName": "alice", "objectSid": ALICE_SID, "distinguishedName": "CN=alice,DC=example,DC=com"}]
    identity = resolve_assessment_identity(ldap, users, [], [])
    assert identity["resolved"] is True
    assert identity["sam"] == "alice"
    assert identity["token_groups"]["status"] == "collected"
    assert HELPDESK_SID in identity["token_groups"]["sids"]


def test_tier0_routes_skip_trusts_and_list_every_simple_path():
    routes = enumerate_tier0_routes(_graph(), ["user:alice"])
    assert len(routes) == 1
    assert routes[0]["labels"] == ["alice", "Helpdesk", "Domain Admins"]
    assert routes[0]["hop_count"] == 2
    assert [hop["type"] for hop in routes[0]["hops"]] == ["MemberOf", "Controls"]


def test_already_privileged_bind_is_a_zero_hop_option():
    graph = {
        "nodes": [{"id": "user:da", "label": "da-breakglass", "kind": "user", "privileged": True}],
        "edges": [],
    }
    routes = enumerate_tier0_routes(graph, ["user:da"])
    assert routes[0]["hop_count"] == 0
    assert routes[0]["already_privileged"] is True


def test_identity_source_ids_include_token_group_nodes():
    identity = {"sam": "alice", "sid": ALICE_SID, "token_groups": {"sids": [HELPDESK_SID]}}
    ids = identity_source_ids(_graph(), identity)
    assert "user:alice" in ids
    assert "group:helpdesk" in ids


def test_assessment_view_lists_esc_enroll_and_kerberoast_session_start():
    identity = {"sam": "alice", "sid": ALICE_SID, "resolved": True, "token_groups": {"status": "collected", "sids": []}}
    risks = [
        {
            "type": "certificate_esc1",
            "severity": "critical",
            "affected_object": "UserAuth",
            "evidence": {
                "vulnerability_confirmed": True,
                "enrollment_trustees": [{"sid": "S-1-5-11", "name": "Authenticated Users"}],
                "published_cas": ["corp-CA"],
            },
        },
        {
            "type": "kerberoasting_target",
            "severity": "high",
            "affected_object": "svc-sql",
            "evidence": {"vulnerability_confirmed": True},
        },
    ]
    view = build_assessment_account_view(
        identity, _graph(), risks, open_path_ids=["kerberoasting", "adcs"]
    )
    assert view["reaches_tier0"] is True
    assert view["route_count"] == 1
    assert view["enrollable_templates"][0]["template"] == "UserAuth"
    assert "kerberoasting" in view["session_techniques"]
    assert "adcs" in view["session_techniques"]
    assert "tier0_graph" in view["session_techniques"]


def test_takeover_map_covers_leftover_and_object_options():
    result = DomainAdminTakeoverAnalyzer().analyze(
        [
            {
                "type": "dcsync_rights",
                "severity": "critical",
                "title": "DCSync on helper",
                "affected_object": "helper",
                "trustee": ALICE_SID,
            },
            {
                "type": "dcsync_rights",
                "severity": "critical",
                "title": "DCSync on sync",
                "affected_object": "MSOL_SYNC",
            },
            {
                "type": "ad_dns_broad_zone_acl",
                "severity": "high",
                "title": "WPAD writable",
                "affected_object": "example.com",
            },
            {
                "type": "custom_tier0_backdoor",
                "severity": "critical",
                "title": "Uncatalogued DA option",
                "affected_object": "backdoor",
            },
        ],
        assessment_identity={"sam": "alice", "sid": ALICE_SID, "resolved": True, "token_groups": {"sids": []}},
        attack_graph=_graph(),
    )
    open_ids = [path["id"] for path in result["open_paths"]]
    assert "dcsync" in open_ids
    assert "ad_dns" in open_ids
    assert "other_da" in open_ids
    dcsync = next(path for path in result["open_paths"] if path["id"] == "dcsync")
    assert dcsync["option_count"] == 2
    objects = {item["object"] for item in dcsync["options"]}
    assert objects == {"helper", "MSOL_SYNC"}
    assert len(dcsync["evidence_summaries"]) == 2
    account = result["from_assessment_account"]
    assert account["route_count"] == 1
    assert any(item["object"] == "helper" for item in account["finding_options"])


def test_nonadmin_starters_list_named_footholds_with_reasons_and_evidence():
    bob_sid = "S-1-5-21-1-2-3-1300"
    graph = _graph()
    graph["nodes"].append(
        {"id": "user:bob", "label": "bob", "sid": bob_sid, "kind": "user", "privileged": False}
    )
    graph["nodes"].append(
        {
            "id": "user:da-breakglass",
            "label": "da-breakglass",
            "sid": "S-1-5-21-1-2-3-500",
            "kind": "user",
            "privileged": True,
        }
    )
    result = DomainAdminTakeoverAnalyzer().analyze(
        [
            {
                "type": "acl_generic_all",
                "severity": "critical",
                "title": "GenericAll on Domain Admins",
                "affected_object": "Domain Admins",
                "trustee": bob_sid,
                "trustee_display_name": "bob",
                "permission": "GenericAll",
                "description": "Trustee bob has GenericAll on Domain Admins.",
            },
            {
                "type": "certificate_esc1",
                "severity": "critical",
                "title": "ESC1 template",
                "affected_object": "UserAuth",
                "evidence": {
                    "vulnerability_confirmed": True,
                    "enrollment_trustees": [
                        {"sid": "S-1-5-11", "name": "Authenticated Users"},
                        {"sid": ALICE_SID, "name": "alice"},
                    ],
                },
            },
        ],
        attack_graph=graph,
    )
    starters = result["nonadmin_starters"]
    names = {item["sam"] for item in starters["principals"]}
    assert "alice" in names
    assert "bob" in names
    assert "da-breakglass" not in names
    assert "Authenticated Users" not in names
    assert "Domain Admins" not in names
    alice = next(item for item in starters["principals"] if item["sam"] == "alice")
    bob = next(item for item in starters["principals"] if item["sam"] == "bob")
    assert alice["shortest_hops"] == 2
    assert any(tech["id"] == "tier0_graph" for tech in alice["techniques"])
    graph_tech = next(tech for tech in alice["techniques"] if tech["id"] == "tier0_graph")
    assert "Helpdesk" in graph_tech["reason"]
    assert "Domain Admins" in graph_tech["reason"]
    assert graph_tech["evidence"][0]["detail"]
    assert any(tech["id"] == "adcs" for tech in alice["techniques"])
    acl = next(tech for tech in bob["techniques"] if tech["id"] == "acl_generic_all")
    assert "bob is the evidenced foothold" in acl["reason"]
    assert "GenericAll" in acl["reason"]
    assert acl["evidence"][0]["object"] == "Domain Admins"
    assert acl["evidence"][0]["confirmed"] is True
    assert acl["evidence"][0]["title"] == "GenericAll on Domain Admins"
    html = DomainAdminSectionMixin()._generate_domain_admin_takeover_section(result, domain=DOMAIN)
    assert "Non-admin accounts that can reach Domain Admin" in html
    assert "GenericAll on Domain Admins" in html
    assert "Trustee bob has GenericAll" in html


def test_privileged_hygiene_and_bitlocker_are_named_cards():
    result = DomainAdminTakeoverAnalyzer().analyze(
        [
            {
                "type": "disabled_domain_admin",
                "severity": "high",
                "affected_object": "old-da",
            },
            {
                "type": "bitlocker_recovery_in_ad",
                "severity": "high",
                "affected_object": "DC01",
                "evidence": {"vulnerability_confirmed": True},
            },
        ]
    )
    assert {path["id"] for path in result["open_paths"]} == {"privileged_hygiene", "bitlocker"}
    ids = {spec["id"] for spec in DA_PATH_CATALOG}
    assert {"tier0_graph", "adcs_control", "gmsa_readers", "adminsdholder", "privileged_hygiene", "ad_dns", "bitlocker"} <= ids


def test_html_renders_assessment_account_routes_and_options():
    takeover = DomainAdminTakeoverAnalyzer().analyze(
        [
            {
                "type": "acl_generic_all",
                "severity": "critical",
                "title": "GenericAll on Domain Admins",
                "affected_object": "Domain Admins",
                "trustee": ALICE_SID,
                "trustee_name": "alice",
            }
        ],
        assessment_identity={"sam": "alice", "sid": ALICE_SID, "resolved": True, "token_groups": {"status": "collected", "sids": []}},
        attack_graph=_graph(),
    )
    html = DomainAdminSectionMixin()._generate_domain_admin_takeover_section(takeover, domain=DOMAIN)
    assert "From the account used for this scan" in html
    assert "alice" in html
    assert "Domain Admins" in html
    assert "Object-level options" in html
    assert "Routes from this account" in html


def test_sysvol_flag_targets_the_domain_controller():
    from AtilKurt import build_parser, validate_cli_arguments

    parser = build_parser()
    args = parser.parse_args(["-d", DOMAIN, "-u", "auditor", "--dc-ip", "10.0.0.5", "--sysvol"])
    validate_cli_arguments(parser, args)
    assert args.sysvol_host == ["10.0.0.5"]

    parser = build_parser()
    args = parser.parse_args(["-d", DOMAIN, "-u", "auditor", "--sysvol"])
    validate_cli_arguments(parser, args)
    assert args.sysvol_host == [DOMAIN]


def test_ciso_kpi_trends_use_previous_history_snapshot():
    data = CISODashboardGenerator().generate_dashboard_data(
        [{"type": "dcsync_rights", "severity": "critical"}],
        [{"sAMAccountName": "da", "adminCount": "1", "memberOf": ["CN=Domain Admins,CN=Users,DC=example,DC=com"]}],
        [],
        [],
        40.0,
        {"summary": "test", "top_critical_risks": []},
        previous_kpis={"score": 20, "critical": 5, "high": 0},
    )
    assert data["kpis"]["overall_score"]["trend"] == "improving"
    assert data["kpis"]["critical_risks"]["trend"] == "improving"
    assert data["kpis"]["high_risks"]["trend"] == "stable"
    assert data["kpis"]["privileged_accounts"]["value"] == 1
    assert data["kpis"]["privileged_accounts"]["trend"] == "unknown"
    empty = CISODashboardGenerator().generate_dashboard_data(
        [], [], [], [], 80.0, {"summary": "test", "top_critical_risks": []},
    )
    assert empty["kpis"]["overall_score"]["trend"] == "unknown"


def test_finding_kpi_snapshot_reads_previous_run_before_overwrite(tmp_path):
    coverage = {"summary": {"execution_percent": 100}}
    first = {
        "finding_id": "ak-1",
        "type": "dcsync_rights",
        "severity": "critical",
        "title": "DCSync",
        "affected_object": "helper",
        "object_type": "user",
    }
    with AssessmentHistory(str(tmp_path / "history.db")) as history:
        history.record_scan(DOMAIN, [first], 20, coverage, {"fresh_ldap": True}, {})
        snapshot = history.finding_kpi_snapshot(DOMAIN)
        assert snapshot["critical"] == 1
        assert snapshot["score"] == 20
        history.record_scan(DOMAIN, [], 100, coverage, {"fresh_ldap": True}, {})
        after = history.finding_kpi_snapshot(DOMAIN)
        assert after["critical"] == 0
        assert after["score"] == 100

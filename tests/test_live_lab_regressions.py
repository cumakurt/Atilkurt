"""Live-lab regressions with deterministic, offline directory fixtures."""

import shlex
from unittest.mock import Mock

import pytest

from analysis.adcs_control_plane_analyzer import ADCSControlPlaneAnalyzer
from analysis.assessment_da_paths import build_assessment_account_view
from analysis.attack_graph_v2_analyzer import AttackGraphV2Analyzer
from analysis.remediation_simulator import edge_id, simulate_remediation
from analysis.domain_admin_takeover_analyzer import DomainAdminTakeoverAnalyzer
from analysis.privilege_escalation import PrivilegeEscalationAnalyzer
from analysis.sccm_attack_surface_analyzer import SCCMAttackSurfaceAnalyzer
from analysis.takeover_evidence import evidence_dossier
from core.ad_identity import nested_privileged_groups
from core.ad_security import principal_group_tokens
from core.finding_evidence import requires_validation
from core.optional_directory import optional_subtree
from reporting.report_sections.domain_admin_section import DomainAdminSectionMixin
from tests.test_package_b_attack_surface import FakeLDAP, _sd, _sid

BASE = "DC=example,DC=com"
CONFIG = "CN=Configuration," + BASE
PKI = "CN=Public Key Services,CN=Services," + CONFIG
SID = "S-1-5-21-1-2-3-"


def inventory():
    user = {
        "sAMAccountName": "alice",
        "objectSid": SID + "1100",
        "distinguishedName": "CN=alice," + BASE,
        "memberOf": ["CN=Helpdesk," + BASE],
    }
    groups = [
        {
            "name": "Helpdesk",
            "objectSid": SID + "1101",
            "distinguishedName": "CN=Helpdesk," + BASE,
            "memberOf": ["CN=RenamedAdmins," + BASE],
            "groupType": -2147483646,
        },
        {
            "name": "RenamedAdmins",
            "objectSid": SID + "512",
            "distinguishedName": "CN=RenamedAdmins," + BASE,
            "groupType": -2147483646,
        },
    ]
    return user, groups


def test_optional_container_absence_does_not_query_nonexistent_base():
    ldap = Mock()
    ldap.search.return_value = []
    assert optional_subtree(ldap, BASE, "CN=Absent," + BASE) == []
    assert ldap.search.call_count == 1
    assert ldap.search.call_args.kwargs["search_base"] == BASE


def test_optional_container_errors_propagate():
    ldap = Mock()
    ldap.search.side_effect = RuntimeError("directory unavailable")
    with pytest.raises(RuntimeError, match="unavailable"):
        optional_subtree(ldap, BASE, "CN=Absent," + BASE)


def test_sccm_empty_publication_is_not_a_finding_or_schema_dependency():
    ldap = Mock(base_dn=BASE)
    ldap.search.side_effect = [[{"distinguishedName": "CN=System Management,CN=System," + BASE}], []]
    assert SCCMAttackSurfaceAnalyzer(ldap).analyze() == []
    assert "mSSMSSiteCode" not in ldap.search.call_args.kwargs["attributes"]


def test_pki_descendant_acl_is_not_root_control():
    ldap = FakeLDAP(
        {
            "configurationNamingContext": [{"configurationNamingContext": CONFIG}],
            "CN=Public Key Services": [
                {"cn": "AIA", "distinguishedName": "CN=AIA," + PKI, "nTSecurityDescriptor": _sd(_sid(1, 0))}
            ],
        }
    )
    result = ADCSControlPlaneAnalyzer(ldap).analyze([], [])
    assert not any(risk["evidence"]["target_kind"] == "pki_root" for risk in result["risks"])


def test_observed_pki_acl_remains_a_risk_but_takeover_needs_validation():
    ldap = FakeLDAP(
        {
            "configurationNamingContext": [{"configurationNamingContext": CONFIG}],
            "CN=NTAuthCertificates": [
                {
                    "cn": "NTAuthCertificates",
                    "distinguishedName": "CN=NTAuthCertificates," + PKI,
                    "nTSecurityDescriptor": _sd(_sid(1, 0)),
                }
            ],
        }
    )
    risks = ADCSControlPlaneAnalyzer(ldap).analyze([], [])["risks"]
    assert len(risks) == 1 and not requires_validation(risks[0])
    report = DomainAdminTakeoverAnalyzer().analyze(risks)
    assert not report["open_paths"]
    assert report["pending_paths"][0]["evidence_dossiers"][0]["evidence_state"] == "needs_validation"


def test_renamed_nested_admin_is_current_access_not_takeover():
    user, groups = inventory()
    assert nested_privileged_groups(user, groups) == ["RenamedAdmins"]
    graph = AttackGraphV2Analyzer().analyze([user], groups, [], {})
    assert not graph["risks"]
    alice = next(node for node in graph["graph"]["nodes"] if node["label"] == "alice")
    assert alice["privileged"] and alice["privilege_basis"] == "existing_nested_membership"
    assert PrivilegeEscalationAnalyzer().analyze([user], groups, []) == []


def test_same_cn_in_another_ou_cannot_supply_membership():
    user, groups = inventory()
    user["memberOf"] = ["CN=Helpdesk,OU=Other," + BASE]
    assert nested_privileged_groups(user, groups) == []


def test_distribution_group_cannot_supply_privilege_or_token_sids():
    user, groups = inventory()
    groups[0]["groupType"] = 2
    assert nested_privileged_groups(user, groups) == []
    assert principal_group_tokens([user], groups)[user["objectSid"]] == set()
    graph = AttackGraphV2Analyzer().analyze([user], groups, [], {})["graph"]
    assert not next(node for node in graph["nodes"] if node["label"] == "alice")["privileged"]


@pytest.mark.parametrize("relation", ["primary", "member"])
def test_membership_without_memberof_still_identifies_existing_access(relation):
    user, groups = inventory()
    user["memberOf"] = []
    if relation == "primary":
        user["primaryGroupID"] = 1101
    else:
        groups[0]["member"] = [user["distinguishedName"]]
    graph = AttackGraphV2Analyzer().analyze([user], groups, [], {})["graph"]
    assert next(node for node in graph["nodes"] if node["label"] == "alice")["privileged"]
    assert nested_privileged_groups(user, groups) == ["RenamedAdmins"]


def test_component_sid_alias_connects_a_real_control_path():
    user, groups = inventory()
    user["memberOf"] = []
    components = {
        "gmsa_reader_graph": {
            "nodes": [
                {"id": "reader-alias", "sid": user["objectSid"], "kind": "principal", "label": "untrusted label"},
                {"id": "da-alias", "sid": groups[1]["objectSid"], "kind": "principal", "privileged": False},
            ],
            "edges": [{"source": "reader-alias", "target": "da-alias", "type": "Controls"}],
        }
    }
    result = AttackGraphV2Analyzer().analyze([user], groups, [], components)
    assert result["graph"]["summary"]["open_path_count"] == 1
    assert result["graph"]["shortest_paths"][0]["labels"] == ["alice", "RenamedAdmins"]
    assert any(risk["type"] == "attack_graph_tier0_path" for risk in result["risks"])


def test_session_technique_is_not_tier0_reachability():
    view = build_assessment_account_view({"resolved": True, "sam": "alice"}, {}, open_path_ids=["kerberoasting"])
    assert view["has_assessment_options"]
    assert not view["reaches_tier0"] and not view["takeover_tested"]


def test_mixed_evidence_retains_pending_objects():
    risks = [
        {"type": "dcsync_rights", "affected_object": "observed"},
        {"type": "dcsync_rights", "affected_object": "uncertain", "requires_validation": True},
    ]
    result = DomainAdminTakeoverAnalyzer().analyze(risks)
    assert result["open_paths"][0]["evidence_objects"] == ["observed"]
    assert result["pending_paths"][0]["evidence_objects"] == ["uncertain"]


def test_dcsync_poc_is_root_scoped_and_requires_both_rights():
    dossier = evidence_dossier({"type": "dcsync_rights", "affected_object": "alice"}, domain_dn=BASE, dc_ip="192.0.2.1")
    args = shlex.split(dossier["read_only_poc"])
    assert args[args.index("-b") + 1] == BASE
    assert args[args.index("-s") + 1] == "base"
    assert "-W" in args and "-w" not in args
    assert "1131f6aa" in dossier["expected"] and "1131f6ad" in dossier["expected"]
    assert not dossier["takeover_tested"]


def test_poc_escapes_shell_ldap_and_html_values():
    target = "name')(*)(name=*);$(touch /tmp/forbidden)<script>"
    dossier = evidence_dossier(
        {"type": "asrep_roastable", "affected_object": target}, domain_dn=BASE, dc_ip="192.0.2.1"
    )
    args = shlex.split(dossier["read_only_poc"])
    assert "\\2a" in next(arg for arg in args if arg.startswith("(|"))
    html = DomainAdminSectionMixin()._da_evidence_dossiers({"evidence_dossiers": [dossier]})
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert args[0] == "ldapsearch"


def test_dns_admin_membership_is_sensitive_but_not_a_tier0_route():
    user, groups = inventory()
    groups[1]["name"] = "DnsAdmins"
    groups[1]["objectSid"] = SID + "1102"
    graph = AttackGraphV2Analyzer().analyze([user], groups, [], {})["graph"]
    alice = next(node for node in graph["nodes"] if node["label"] == "alice")
    assert alice["sensitive_access"] and not alice["privileged"]
    view = build_assessment_account_view({"resolved": True, "sam": "alice", "sid": user["objectSid"]}, graph)
    assert view["route_count"] == 0 and not view["reaches_tier0"]
    report = DomainAdminTakeoverAnalyzer().analyze([], attack_graph=graph)
    assert report["existing_access"][0]["tier0"] is False


@pytest.mark.parametrize("target", ["alice'; whoami; '", "$(id)", "alice\nwhoami", "alice --dangerous", "alice\\", "@args"])
def test_legacy_playbook_does_not_embed_command_metacharacters(target):
    from analysis.domain_admin_takeover_playbooks import fill_playbook_fields

    result = fill_playbook_fields({"detail": "{TARGET}", "command": "Get-ADUser {TARGET}"}, target=target)
    assert result["detail"] == target
    assert result["command"] == "Get-ADUser TARGET_REQUIRES_MANUAL_REPLACEMENT"


def test_domain_replication_ace_reaches_the_domain_and_can_be_simulated_closed():
    user, groups = inventory()
    user["memberOf"] = []
    domain_dn = "DC=lab,DC=local"
    result = AttackGraphV2Analyzer().analyze([user], groups, [], {
        "trust_security_v2_graph": {
            "nodes": [{"id": "domain:" + domain_dn.casefold(), "label": domain_dn, "kind": "domain"}],
            "edges": [],
        },
        "comprehensive_acl_risks": [{
            "trustee": user["objectSid"],
            "affected_object": "Domain",
            "object_dn": domain_dn,
            # Secret replication requires both rights on the same domain.
            "permission": permission,
            "type": "acl_" + permission.lower().replace('-', '_'),
        } for permission in ("DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All")],
    })
    graph = result["graph"]
    assert graph["summary"]["open_path_count"] == 1
    assert graph["shortest_paths"][0]["labels"] == ["alice", domain_dn]
    control = next(edge for edge in graph["edges"] if edge["type"] == "Controls")
    simulation = simulate_remediation(graph)
    assert simulation["before"]["exposed_sources"] == 1
    closed = simulate_remediation(graph, [edge_id(control)])
    assert closed["after"]["exposed_sources"] == 0
    assert closed["closed_sources"]


def test_writable_domain_controller_primary_group_is_tier0():
    dc = {"sAMAccountName": "DC01$", "objectSid": SID + "1200", "primaryGroupID": 516}
    groups = [{"name": "Domain Controllers", "objectSid": SID + "516", "groupType": -2147483646}]
    graph = AttackGraphV2Analyzer().analyze([], groups, [dc], {})["graph"]
    assert next(node for node in graph["nodes"] if node["label"] == "DC01$")["privileged"]

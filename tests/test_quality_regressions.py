"""Regression coverage for evidence boundaries and malformed engagement inputs."""

from copy import deepcopy
from datetime import datetime, timezone
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from analysis.effective_gpo_analyzer import analyze_effective_gpo
from analysis.attack_path_planner import plan_attack_paths
from analysis.computer_risks import ComputerRiskAnalyzer
from analysis.focused_verifier import verify_selected_findings
from analysis.remediation_verifier import verify_remediation
from analysis.registry import get_analysis_step_keys
from core.finding_review import FindingReviewManager
from core.exceptions import LDAPSearchError, ValidationError
from core.assessment_scope import AssessmentScope, ScopeLimitError
from core.diagnostics import collection_health
from core.engagement_workflow import prepare_engagement_inputs
from core.graph_import import federate_graphs, import_bloodhound
from core.ldap_connection import LDAPConnection
from core.parallel_ldap import ParallelLDAPExecutor
from core.protocol_checks import verify_protocols
from reporting.client_report import client_document


DOMAIN = "example.com"
BASE = "DC=example,DC=com"
TARGET = "CN=host,OU=Lab," + BASE


@pytest.mark.parametrize("kind,source", [
    ("protocol_smb_signing_required", "protocol_verification"),
    ("protocol_channel_binding_required", "protocol_verification"),
    ("sysvol_gpp_cpassword", "sysvol_read_only"),
])
def test_directory_absence_cannot_close_service_or_shared_file_findings(kind, source):
    risk = {"type": kind, "source": source, "severity": "High", "title": kind,
            "affected_object": "dc.example.com", "requires_validation": False}
    FindingReviewManager().apply([risk], {}, DOMAIN)
    current = {"scan_context": {"fresh_ldap": True, "collected_at": datetime.now(timezone.utc).isoformat()},
               "collection_health": {"status": "completed"}}
    coverage = {"analysis_steps": [{"key": key, "status": "completed"} for key in get_analysis_step_keys()]}
    previous = {"domain": DOMAIN, "risks": [risk]}
    result = verify_remediation(previous, [], current, coverage, DOMAIN)
    assert result["findings"][0]["status"] == "insufficient_evidence"
    assert verify_remediation(previous, [risk], current, coverage, DOMAIN)["findings"][0]["status"] == "still_present"


def gpo_context():
    return {"schema_version": 1, "targets": [{"dn": TARGET, "kind": "computer", "token_complete": True,
            "security_groups": ["S-1-5-11"]}],
            "containers": [{"dn": BASE, "gpOptions": 0, "links": [{"id": "policy", "order": 1}]},
                           {"dn": "OU=Lab," + BASE, "gpOptions": 0, "links": []}],
            "gpos": [{"id": "policy", "flags": 0, "settings": {"protection": True},
                      "security_filter": {"read": ["S-1-5-11"], "apply": ["S-1-5-11"]}}]}


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("field,value", [("flags", 2), ("security_filter", {"read": [], "apply": []})])
def test_conflicting_gpo_metadata_cannot_exclude_or_select_an_arbitrary_setting(reverse, field, value):
    context = gpo_context()
    conflict = {**deepcopy(context["gpos"][0]), field: value}
    context["gpos"].append(conflict)
    if reverse:
        context["gpos"].reverse()
    result = analyze_effective_gpo(context)["targets"][0]
    assert result["policies"][0]["status"] == "conditional"
    assert "Conflicting GPO metadata" in result["policies"][0]["prerequisites"]
    assert result["settings"] == {}


def test_conflicting_container_metadata_is_rejected():
    context = gpo_context()
    context["containers"].append({"dn": BASE.lower(), "gpOptions": 1, "links": []})
    with pytest.raises(ValidationError, match="container"):
        analyze_effective_gpo(context)


@pytest.mark.parametrize('field,value', [('disabled', 'false'), ('enforced', 'false'), ('order', True), ('order', 0)])
def test_gpo_link_fields_cannot_turn_malformed_values_into_access_decisions(field, value):
    context = gpo_context()
    context['containers'][0]['links'][0][field] = value
    with pytest.raises(ValidationError, match='link'):
        analyze_effective_gpo(context)


@pytest.mark.parametrize('field,value', [('settings', []), ('security_filter', {'read': 'S-1-5-11', 'apply': []})])
def test_malformed_gpo_policy_fields_are_rejected(field, value):
    context = gpo_context()
    context['gpos'][0][field] = value
    with pytest.raises(ValidationError):
        analyze_effective_gpo(context)


def test_missing_apply_permission_evidence_does_not_exclude_a_policy():
    context = gpo_context()
    context['gpos'][0]['security_filter'].pop('apply')
    assert analyze_effective_gpo(context)['targets'][0]['policies'][0]['status'] == 'conditional'


@pytest.mark.parametrize("key", ["api_key", "apiKey", "access_token", "Authorization", "connectionString"])
def test_client_reports_redact_secret_fields_without_mutating_evidence(key):
    risk = {"evidence": {key: "test-only-sensitive-value", "token_group_evidence": {"status": "collected"}}}
    document = client_document(DOMAIN, {}, [risk], {})
    assert document["findings"][0]["evidence"][key] == "[REDACTED]"
    assert document["findings"][0]["evidence"]["token_group_evidence"]["status"] == "collected"
    assert risk["evidence"][key] == "test-only-sensitive-value"


@pytest.mark.parametrize("assignment", [
    'password = "first second third"',
    "pwd = 'first second third'",
    'api_key = "first; second third"',
    r'password = "first \"second\" third"',
    'Authorization: Bearer first-second-third',
])
def test_client_reports_redact_complete_quoted_assignments(assignment):
    document = client_document(DOMAIN, {}, [{"description": assignment}], {})
    serialized = json.dumps(document)
    assert "first" not in serialized and "second" not in serialized and "third" not in serialized


def test_client_identity_masking_includes_mapping_keys():
    workspace = {"engagement": {"effective_gpo": {"settings_by_target": {TARGET: {"value": True}}}}}
    document = client_document(DOMAIN, {}, [], workspace, masked=True)
    assert "CN=host" not in json.dumps(document)
    assert TARGET in workspace["engagement"]["effective_gpo"]["settings_by_target"]


@pytest.mark.parametrize("graph", [
    {"nodes": "invalid", "edges": []},
    {"nodes": [None], "edges": []},
    {"nodes": [{"id": "a", "properties": []}], "edges": []},
    {"nodes": [{"id": "a"}], "edges": [None]},
    {"nodes": [{"id": "a"}], "edges": [{"source": "a", "target": "a", "type": "MemberOf", "properties": []}]},
    {"nodes": [{"id": "a"}], "edges": [{"source": "a", "target": "a", "type": "MemberOf", "status": {}}]},
])
def test_malformed_federation_inputs_raise_actionable_validation_errors(graph):
    with pytest.raises(ValidationError):
        federate_graphs([(DOMAIN, graph, {})])


def test_bloodhound_session_entry_requires_an_object_before_network_free_import(tmp_path):
    path = tmp_path / "session.json"
    path.write_text(json.dumps({"meta": {"type": "computers", "version": 6, "count": 1},
                               "data": [{"ObjectIdentifier": "S-1-5-21-1-2-3-1000",
                                         "Properties": {"domain": DOMAIN}, "Sessions": {"Results": [None]}}]}))
    with pytest.raises(ValidationError):
        import_bloodhound([str(path)])


def test_federation_merges_domain_sid_nodes_with_trust_references():
    local = {'nodes': [{'id': 'domain:local', 'kind': 'domain'},
                       {'id': 'domain:other', 'kind': 'trusted_domain', 'label': 'other.example'}],
             'edges': [{'source': 'domain:other', 'target': 'domain:local', 'type': 'InboundTrust'}]}
    other = {'nodes': [{'id': 'domain:sid', 'kind': 'domain', 'sid': 'S-1-5-21-1-2-3', 'label': 'other.example'}], 'edges': []}
    graph = federate_graphs([(DOMAIN, local, {}), ('other.example', other, {})])
    domains = [node for node in graph['nodes'] if node['domain'] == 'other.example']
    assert len(domains) == 1 and domains[0].get('reference_only') is not True
    assert graph['edges'][0]['source'] == domains[0]['id']


@pytest.mark.parametrize("restriction", ["directory", "budget"])
def test_parallel_workers_share_scope_and_report_prevented_reads(monkeypatch, restriction):
    transport = SimpleNamespace(search=Mock(return_value=True), entries=[], result={"result": 0}, unbind=Mock())

    def bind(worker):
        if worker.assessment_scope:
            worker.assessment_scope.consume(DOMAIN, 'ldap')
        worker.connection = transport
        return True

    monkeypatch.setattr(LDAPConnection, 'connect', bind)
    base = LDAPConnection(DOMAIN, 'auditor', 'test-only-password', DOMAIN)
    base.assessment_scope = AssessmentScope(DOMAIN, {"schema_version": 1, "ous": ["OU=Lab," + BASE]},
                                            max_queries=1 if restriction == 'budget' else 10)
    executor = ParallelLDAPExecutor(base, max_workers=1, rate_limit=0)
    query_base = "CN=outside," + BASE if restriction == 'directory' else "OU=Lab," + BASE
    with pytest.raises(LDAPSearchError, match='partial results discarded'):
        executor.execute_parallel([{'id': 'blocked', 'base': query_base}])
    transport.search.assert_not_called()
    transport.unbind.assert_called_once()
    assert base.assessment_scope.requests == 1
    assert collection_health(base)['status'] == 'partial'


def test_exhausted_bind_budget_preserves_scope_limit_error(monkeypatch):
    factory = Mock()
    monkeypatch.setattr('core.ldap_connection.Server', Mock())
    monkeypatch.setattr('core.ldap_connection.Connection', factory)
    ldap = LDAPConnection(DOMAIN, 'auditor', 'test-only-password', DOMAIN)
    ldap.assessment_scope = AssessmentScope(DOMAIN, max_queries=1)
    ldap.assessment_scope.consume(DOMAIN, 'ldap')
    with pytest.raises(ScopeLimitError):
        ldap.connect()
    factory.assert_not_called()


def test_exhausted_search_budget_is_not_retried_as_a_network_fault(monkeypatch):
    sleep = Mock(side_effect=AssertionError('Scope denials must not be retried'))
    monkeypatch.setattr('core.ldap_connection.time.sleep', sleep)
    ldap = LDAPConnection(DOMAIN, 'auditor', 'test-only-password', DOMAIN, enable_paging=False)
    ldap.connection = SimpleNamespace(search=Mock(), entries=[])
    ldap.assessment_scope = AssessmentScope(DOMAIN, max_queries=1)
    ldap.assessment_scope.consume(DOMAIN, 'ldap')
    with pytest.raises(ScopeLimitError):
        ldap.search()
    sleep.assert_not_called()
    ldap.connection.search.assert_not_called()
    assert ldap.assessment_scope.prevented == 1


def test_ldap_does_not_follow_referrals_around_engagement_scope(monkeypatch):
    factory = Mock(return_value=SimpleNamespace(bound=True))
    monkeypatch.setattr('core.ldap_connection.Server', Mock())
    monkeypatch.setattr('core.ldap_connection.Connection', factory)
    LDAPConnection(DOMAIN, 'auditor', 'test-only-password', DOMAIN).connect()
    assert factory.call_args.kwargs['auto_referrals'] is False


def test_excluded_enrollment_endpoint_fails_preflight(tmp_path):
    scope_path = tmp_path / 'scope.json'
    scope_path.write_text(json.dumps({'schema_version': 1, 'hosts': [DOMAIN]}))
    args = SimpleNamespace(domain=DOMAIN, dc_ip=DOMAIN, ssl=False, scope_file=str(scope_path),
                           adcs_endpoint=['https://outside.example/certsrv/'])
    with pytest.raises(ScopeLimitError):
        prepare_engagement_inputs(args)


def test_invalid_protocol_evidence_is_rejected_before_any_probe(monkeypatch):
    factory = Mock()
    monkeypatch.setattr('core.protocol_checks.socket.create_connection', Mock(side_effect=OSError('Synthetic TLS failure')))
    with pytest.raises(ValidationError):
        verify_protocols([DOMAIN], [], AssessmentScope(DOMAIN), smb_factory=factory,
                         local_evidence={'policies': [{'target': DOMAIN, 'check': 'epa_required', 'value': 'false'}]})
    factory.assert_not_called()


def test_enrollment_probe_retains_query_parameters_and_discloses_cleanup_failure(monkeypatch):
    transport = Mock()
    transport.getresponse.return_value = SimpleNamespace(status=200, getheader=lambda *_args: '')
    transport.close.side_effect = OSError('Synthetic cleanup failure')
    monkeypatch.setattr('core.protocol_checks.http.client.HTTPSConnection', Mock(return_value=transport))
    result = verify_protocols([], ['https://ca.example.com/certsrv/?action=info'], AssessmentScope(DOMAIN))
    assert transport.request.call_args.args[1] == '/certsrv/?action=info'
    assert result['checks'][0]['status'] == 'observed'
    assert result['checks'][1]['check'] == 'adcs_cleanup'


@pytest.mark.parametrize('count,expected', [(11, 'still_present'), (10, 'configuration_resolved'),
                                          (1, 'configuration_resolved'), (0, 'configuration_resolved')])
def test_focused_broad_delegation_uses_the_original_threshold(count, expected):
    sid = 'S-1-5-21-1-2-3-1000'
    finding = {'finding_id': 'selected', 'type': 'computer_broad_constrained_delegation', 'affected_object': 'host'}
    previous = {'domain': DOMAIN, 'computers': [{'sAMAccountName': 'host', 'distinguishedName': TARGET, 'objectSid': sid}],
                'risks': [finding]}
    ldap = SimpleNamespace(domain=DOMAIN, base_dn=BASE, base_search=Mock(return_value=[
        {'objectSid': sid, 'userAccountControl': 512, 'msDS-AllowedToDelegateTo': [f'cifs/server{index}' for index in range(count)]}]))
    result = verify_selected_findings(ldap, previous, ['selected'])
    assert result['findings'][0]['status'] == expected


@pytest.mark.parametrize('uac,targets,expected', [
    (0x1000200, [], 'configuration_resolved'),
    (512, ['cifs/server'], 'still_present'),
    (0x1000200, ['cifs/server'], 'still_present'),
])
def test_focused_constrained_delegation_rechecks_allowed_targets(uac, targets, expected):
    sid = 'S-1-5-21-1-2-3-1000'
    previous = {'domain': DOMAIN, 'computers': [{'name': 'host', 'distinguishedName': TARGET, 'objectSid': sid}],
                'risks': [{'finding_id': 'selected', 'type': 'constrained_delegation', 'affected_object': 'host'}]}
    ldap = SimpleNamespace(domain=DOMAIN, base_dn=BASE, base_search=Mock(return_value=[
        {'objectSid': sid, 'userAccountControl': uac, 'msDS-AllowedToDelegateTo': targets}]))
    assert verify_selected_findings(ldap, previous, ['selected'])['findings'][0]['status'] == expected


def test_single_delegation_spn_is_not_counted_by_character_length():
    assert ComputerRiskAnalyzer()._check_constrained_delegation({'msDS-AllowedToDelegateTo': 'cifs/server.example.com'}) == []


def test_attack_planner_discloses_branches_dropped_by_queue_budget():
    graph = {'nodes': [{'id': identifier} for identifier in ('a', 'b', 'c')], 'edges': [
        {'source': 'a', 'target': destination, 'type': 'MemberOf'} for destination in ('b', 'c')]}
    result = plan_attack_paths(graph, 'a', 'c', max_expansions=2)
    assert result['paths'] == []
    assert result['truncated'] is True


@pytest.mark.parametrize('properties,expected', [({'requires_validation': True}, 'conditional'),
    ({'requires_runtime_validation': True}, 'conditional'), ({'status': 'false_positive'}, None)])
def test_attack_planner_honors_explicit_evidence_boundaries(properties, expected):
    graph = {'nodes': [{'id': 'a'}, {'id': 'b'}],
             'edges': [{'source': 'a', 'target': 'b', 'type': 'AdminTo', 'properties': properties}]}
    paths = plan_attack_paths(graph, 'a', 'b')['paths']
    assert (paths[0]['status'] if paths else None) == expected


def test_missing_higher_precedence_gpo_cannot_leave_a_definite_setting_winner():
    context = gpo_context()
    context['containers'][1]['links'] = [{'id': 'unreadable-policy', 'order': 1}]
    result = analyze_effective_gpo(context)['targets'][0]
    assert result['settings']['protection']['status'] == 'conditional'
    assert result['policies'][-1]['status'] == 'conditional'

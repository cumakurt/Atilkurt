"""Reproducible correctness and publication boundaries from the full audit."""

from copy import deepcopy
from types import SimpleNamespace
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json

import pytest

import AtilKurt
from analysis.attack_graph_v2_analyzer import AttackGraphV2Analyzer
from analysis.remediation_simulator import edge_id, simulate_remediation
from core.cache import LDAPQueryCache
from core.directory_redaction import redact_nested_secrets
from core.progress_persistence import ProgressPersistence
from reporting.report_sections.directory_section import DirectorySectionMixin
from analysis.computer_risks import ComputerRiskAnalyzer
from reporting.ciso_dashboard import CISODashboardGenerator

BASE = 'DC=example,DC=com'
SID = 'S-1-5-21-1-2-3-'
REPLICATION = ('DS-Replication-Get-Changes', 'DS-Replication-Get-Changes-All')


def principal(name='alice', rid=1100):
    return {'sAMAccountName': name, 'objectSid': SID + str(rid),
            'distinguishedName': 'CN=' + name + ',' + BASE}


def graph_with_permissions(permissions):
    return AttackGraphV2Analyzer().analyze([principal()], [], [], {
        'trust_security_v2_graph': {'nodes': [{'id': 'domain:' + BASE.casefold(),
                                             'label': BASE, 'kind': 'domain'}]},
        'comprehensive_acl_risks': [
            {'trustee': SID + '1100', 'affected_object': 'Domain', 'object_dn': BASE,
             'permission': permission, 'type': 'acl_' + permission.lower()}
            for permission in permissions
        ],
    })['graph']


@pytest.mark.parametrize('permission', [*REPLICATION, 'DS-Replication-Get-Changes-In-Filtered-Set',
                                       'GenericWrite', 'WriteProperty'])
def test_incomplete_domain_capability_is_not_a_tier0_path(permission):
    graph = graph_with_permissions([permission])
    assert graph['shortest_paths'] == []
    assert simulate_remediation(graph)['before']['exposed_sources'] == 0


def test_replication_pair_is_one_joint_capability_for_remediation():
    graph = graph_with_permissions(REPLICATION)
    assert len(graph['shortest_paths']) == 1
    assert len(graph['edges']) == 1
    assert set(graph['edges'][0]['required_permissions']) == set(REPLICATION)
    closed = simulate_remediation(graph, [edge_id(graph['edges'][0])])
    assert closed['before']['exposed_sources'] == 1
    assert closed['after']['exposed_sources'] == 0


def test_distinct_directory_names_cannot_merge_into_one_graph_identity():
    users = [principal('a+b', 1100), principal('a b', 1101)]
    result = AttackGraphV2Analyzer().analyze(users, [], [], {})['graph']
    assert len(result['nodes']) == 2
    assert {node['sid'] for node in result['nodes']} == {SID + '1100', SID + '1101'}
    reordered = AttackGraphV2Analyzer().analyze(list(reversed(users)), [], [], {})['graph']
    assert reordered == result


def test_explicit_unresolved_dn_cannot_fall_back_to_same_named_privileged_group():
    group = {'name': 'Admins', 'objectSid': SID + '512', 'distinguishedName': 'CN=Admins,' + BASE}
    graph = AttackGraphV2Analyzer().analyze([principal()], [group], [], {
        'comprehensive_acl_risks': [{'trustee': SID + '1100', 'affected_object': 'Admins',
                                    'object_dn': 'CN=Admins,OU=Other,' + BASE, 'permission': 'GenericAll'}],
    })['graph']
    assert not graph['shortest_paths']


def test_ldap_query_cache_preserves_original_evidence_on_both_boundaries():
    cache = LDAPQueryCache()
    rows = [{'memberOf': ['CN=Original,' + BASE], 'description': 'original evidence'}]
    original = deepcopy(rows)
    cache.set_query_result('(objectClass=user)', rows)
    rows[0]['memberOf'].append('CN=Injected,' + BASE)
    first = cache.get_query_result('(objectClass=user)')
    assert first == original
    first[0]['description'] = 'redacted by a consumer'
    assert cache.get_query_result('(objectClass=user)') == original


def test_redaction_covers_multivalued_secret_fields_without_altering_input():
    value = {'password': ['synthetic-one', 'synthetic-two'], 'secret': {'value': 'synthetic-three'}}
    result = redact_nested_secrets(value)
    assert 'synthetic' not in str(result)
    assert value['password'][0] == 'synthetic-one'


def test_checkpoint_redacts_compliance_and_non_description_directory_secrets():
    data = {'users': [{'ms-Mcs-AdmPwd': ['synthetic-secret']}], 'computers': [], 'groups': [], 'gpos': []}
    compliance = {'risk_management_data': {'description': 'password=synthetic-secret'}}
    result = AtilKurt.build_checkpoint_payload(SimpleNamespace(domain='example.com', redact_secrets=True),
                                              data, {}, {}, compliance)
    assert 'synthetic-secret' not in str(result)


def test_report_publication_redacts_compliance_before_rendering(monkeypatch):
    @contextmanager
    def workspace(*args):
        yield {}

    monkeypatch.setattr('core.product_workflow.product_workspace_transaction', workspace)
    monkeypatch.setattr('core.engagement_workflow.refresh_engagement_graph', lambda *args: None)
    captured = {}
    monkeypatch.setattr(AtilKurt, '_write_reports', lambda *args: captured.update(compliance=args[4]))
    compliance = {'risk_management_data': {'description': 'password=synthetic-secret'}}
    AtilKurt.generate_reports(SimpleNamespace(redact_secrets=True), {}, {}, {}, compliance, None)
    assert 'synthetic-secret' not in str(captured)


def test_checkpoint_metadata_uses_timezone_aware_utc(tmp_path):
    persistence = ProgressPersistence(str(tmp_path))
    persistence.save_collection_state('sample', 'users', [], completed=True)
    saved = json.loads((tmp_path / 'sample.json').read_text())
    for stamp in (saved['timestamp'], saved['data']['collections']['users']['timestamp']):
        parsed = datetime.fromisoformat(stamp)
        assert parsed.utcoffset() == timedelta(0)


def test_computer_age_keeps_the_timestamp_offset():
    now = datetime.now(timezone.utc)
    # Same instant represented in two timezones must yield the same day count.
    instant = now - timedelta(days=90, hours=1)
    utc = {'lastLogonTimestamp': instant.isoformat()}
    offset = {'lastLogonTimestamp': instant.astimezone(timezone(timedelta(hours=12))).isoformat()}
    analyzer = ComputerRiskAnalyzer()
    analyzer._enrich_computer_data(utc)
    analyzer._enrich_computer_data(offset)
    assert utc['daysSinceLastLogon'] == offset['daysSinceLastLogon'] == 90


def test_directory_admin_labels_use_identity_not_ou_substrings(monkeypatch):
    captured = {}
    renderer = DirectorySectionMixin()
    monkeypatch.setattr(renderer, '_generate_users_table_rows', lambda rows, *args: captured.update(users=rows) or '')
    monkeypatch.setattr(renderer, '_generate_groups_table_rows', lambda rows, *args: captured.update(groups=rows) or '')
    renamed = {'name': 'RenamedAdmins', 'objectSid': SID + '512',
               'distinguishedName': 'CN=RenamedAdmins,' + BASE}
    fake = {'name': 'Domain Admins Archive', 'objectSid': SID + '1400',
            'distinguishedName': 'CN=Domain Admins Archive,' + BASE}
    users = [{'sAMAccountName': 'ordinary', 'memberOf': ['CN=Readers,OU=Domain Admins,' + BASE]},
             {'sAMAccountName': 'admin', 'memberOf': [renamed['distinguishedName']]}]
    renderer._generate_directory_section(users, [renamed, fake], [], [])
    assert captured['users'][0]['domainAdminGroups'] == []
    assert captured['users'][1]['domainAdminGroups'] == ['RenamedAdmins']
    assert [row['is_privileged'] for row in captured['groups']] == [True, False]


def test_ciso_password_age_is_timezone_invariant():
    instant = datetime.now(timezone.utc) - timedelta(days=91, hours=1)
    generator = CISODashboardGenerator()
    utc = generator._calculate_password_statistics([{'sAMAccountName': 'alice', 'pwdLastSet': instant}])
    offset = generator._calculate_password_statistics([{
        'sAMAccountName': 'alice', 'pwdLastSet': instant.astimezone(timezone(timedelta(hours=12))),
    }])
    assert utc == offset


def test_directory_risk_index_preserves_per_object_counts(monkeypatch):
    renderer = DirectorySectionMixin()
    captured = {}
    monkeypatch.setattr(renderer, '_generate_users_table_rows', lambda rows, *args: captured.update(rows=rows) or '')
    renderer._generate_directory_section([principal('alice'), principal('bob')], [], [], [
        {'affected_object': 'alice', 'severity': 'high'},
        {'affected_object': 'bob', 'severity': 'critical'},
        {'affected_object': 'alice', 'severity': 'critical'},
    ])
    assert [(row['risk_count'], row['critical_risks']) for row in captured['rows']] == [(2, 1), (1, 1)]

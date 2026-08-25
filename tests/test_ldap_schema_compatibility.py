"""Regression tests for RootDSE and optional AD schema compatibility."""

import unittest

from analysis.domain_security_analyzer import DomainSecurityAnalyzer
from analysis.gmsa_analyzer import GMSAAnalyzer
from analysis.laps_analyzer import LAPSAnalyzer
from core.ad_identity import forest_configuration_dn, root_dse_attributes


class _ServerInfo:
    other = {
        'configurationNamingContext': [
            'CN=Configuration,DC=example,DC=com',
        ],
        'defaultNamingContext': ['DC=example,DC=com'],
    }
    naming_contexts = [
        'DC=example,DC=com',
        'CN=Configuration,DC=example,DC=com',
    ]


class _Schema:
    def __init__(self, attributes=(), object_classes=()):
        self.attribute_types = set(attributes)
        self.object_classes = set(object_classes)


class _LDAPStub:
    base_dn = 'DC=example,DC=com'

    def __init__(self, *, attributes=(), object_classes=()):
        schema = _Schema(attributes, object_classes)
        server = type('Server', (), {'info': _ServerInfo(), 'schema': schema})()
        self.connection = type('Connection', (), {'server': server})()
        self.calls = []

    def search(self, **kwargs):
        self.calls.append(kwargs)
        return []


class TestRootDSEMetadata(unittest.TestCase):
    def test_reads_bound_server_info_without_an_ldap_search(self):
        ldap = _LDAPStub()

        root = root_dse_attributes(
            ldap,
            ['configurationNamingContext', 'namingContexts'],
        )

        self.assertEqual(
            forest_configuration_dn(ldap),
            'CN=Configuration,DC=example,DC=com',
        )
        self.assertEqual(root['namingContexts'], _ServerInfo.naming_contexts)
        self.assertEqual(ldap.calls, [])


class TestOptionalSchemaQueries(unittest.TestCase):
    def test_absent_laps_schema_does_not_issue_invalid_searches(self):
        ldap = _LDAPStub()
        computers = [{'name': f'PC{i}'} for i in range(10)]

        risks = LAPSAnalyzer(ldap).analyze_laps(computers, [], [])

        self.assertEqual(ldap.calls, [])
        self.assertTrue(any(risk['type'] == 'laps_not_configured' for risk in risks))

    def test_gmsa_query_uses_real_ldap_attribute_name(self):
        ldap = _LDAPStub(
            object_classes={'msDS-GroupManagedServiceAccount'},
        )

        GMSAAnalyzer(ldap).analyze([])

        requested = {
            str(attribute)
            for call in ldap.calls
            for attribute in call.get('attributes', [])
        }
        self.assertIn('msDS-GroupMSAMembership', requested)
        self.assertNotIn('PrincipalsAllowedToRetrieveManagedPassword', requested)

    def test_domain_policy_checks_do_not_query_nonexistent_ad_attributes(self):
        ldap = _LDAPStub()

        risks = DomainSecurityAnalyzer(ldap).analyze_domain_security(
            gpos=[{'displayName': 'Default Domain Controllers Policy'}],
        )

        self.assertEqual(risks, [])
        self.assertEqual(ldap.calls, [])


if __name__ == '__main__':
    unittest.main()

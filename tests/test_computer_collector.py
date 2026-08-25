"""Regression tests for schema-tolerant computer collection."""

import unittest

from core.collectors.computer_collector import ComputerCollector
from core.exceptions import LDAPSearchError


class SearchStub:
    """LDAP stub whose schema does not include legacy Microsoft LAPS."""

    connection = None

    def __init__(self):
        self.calls = []

    def search(self, *, search_filter, attributes, progress_callback):
        self.calls.append(list(attributes))
        if 'ms-Mcs-AdmPwdExpirationTime' in attributes:
            raise LDAPSearchError(
                'LDAP paged search error: invalid attribute type '
                'ms-Mcs-AdmPwdExpirationTime'
            )
        return [{
            'dn': 'CN=PC1,CN=Computers,DC=example,DC=com',
            'name': 'PC1',
            'userAccountControl': 0,
            'msLAPS-PasswordExpirationTime': '133700000000000000',
        }]


class SchemaStub:
    """Minimal ldap3-compatible schema container."""

    class AttributeTypes:
        def __contains__(self, attribute):
            return attribute != 'ms-Mcs-AdmPwdExpirationTime'

    attribute_types = AttributeTypes()


class SchemaAwareSearchStub(SearchStub):
    def __init__(self):
        super().__init__()
        server = type('ServerStub', (), {'schema': SchemaStub()})()
        self.connection = type('ConnectionStub', (), {'server': server})()


class TestComputerCollectorSchemaCompatibility(unittest.TestCase):
    def test_retries_without_named_unsupported_optional_attribute(self):
        ldap = SearchStub()

        computers = ComputerCollector(ldap, show_progress=False).collect()

        self.assertEqual(len(ldap.calls), 2)
        self.assertIn('ms-Mcs-AdmPwdExpirationTime', ldap.calls[0])
        self.assertNotIn('ms-Mcs-AdmPwdExpirationTime', ldap.calls[1])
        self.assertEqual(computers[0]['name'], 'PC1')
        self.assertEqual(
            computers[0]['msLAPS-PasswordExpirationTime'],
            '133700000000000000',
        )

    def test_uses_loaded_schema_to_avoid_the_failed_search(self):
        ldap = SchemaAwareSearchStub()

        computers = ComputerCollector(ldap, show_progress=False).collect()

        self.assertEqual(len(ldap.calls), 1)
        self.assertNotIn('ms-Mcs-AdmPwdExpirationTime', ldap.calls[0])
        self.assertEqual(computers[0]['name'], 'PC1')


if __name__ == '__main__':
    unittest.main()

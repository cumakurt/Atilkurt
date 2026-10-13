"""Regression tests for LDAP transport and search failure handling."""

import unittest
from unittest.mock import Mock, patch

from ldap3 import NTLM
from ldap3.core.exceptions import LDAPException

from core.exceptions import LDAPConnectionError, LDAPSearchError
from core.ldap_connection import LDAPConnection


class FakeAttribute:
    """Minimal ldap3 attribute stub."""

    def __init__(self, value):
        self.values = [value]


class FakeEntry:
    """Minimal ldap3 entry stub."""

    def __init__(self, distinguished_name, name):
        self.entry_dn = distinguished_name
        self.entry_attributes = ["name"]
        self._attributes = {"name": FakeAttribute(name)}

    def __getitem__(self, key):
        return self._attributes[key]


class FakeSearchConnection:
    """Configurable ldap3 search connection stub."""

    def __init__(self, *, succeeded=True, result=None, entries=None):
        self.succeeded = succeeded
        self.result = result if result is not None else {"result": 0, "description": "success"}
        self.entries = entries or []
        self.bound = True
        self.last_kwargs = None

    def search(self, **kwargs):
        self.last_kwargs = kwargs
        return self.succeeded


def build_connection(**kwargs):
    """Build a validated LDAP wrapper without making a network connection."""
    options = {
        "domain": "example.com",
        "username": "tester",
        "password": "ValidPass123!",
        "dc_ip": "10.0.0.1",
        "max_retries": 1,
        "enable_cache": False,
    }
    options.update(kwargs)
    return LDAPConnection(**options)


class TestLDAPTransportSecurity(unittest.TestCase):
    def test_disconnect_clears_bind_password(self):
        connection = build_connection()
        client = Mock()
        client.password = "ValidPass123!"
        connection.connection = client
        connection.disconnect()
        self.assertEqual(connection.password, "")
        self.assertIsNone(client.password)
        client.unbind.assert_called_once()
        self.assertIsNone(connection.connection)


    """TLS requests and plaintext authentication must fail closed."""

    @patch("core.ldap_connection.Connection")
    @patch("core.ldap_connection.Server")
    def test_explicit_tls_never_falls_back_to_plaintext(self, server_mock, connection_mock):
        """A failed LDAPS connection must not retry on port 389."""
        server_mock.return_value = Mock()
        connection_mock.side_effect = LDAPException("TLS unavailable")
        ldap = build_connection(use_ssl=True)

        with self.assertRaises(LDAPConnectionError):
            ldap.connect()

        self.assertTrue(server_mock.call_args.kwargs["use_ssl"])
        self.assertEqual(server_mock.call_args.kwargs["port"], 636)
        self.assertTrue(all(call.kwargs["use_ssl"] for call in server_mock.call_args_list))

    @patch("core.ldap_connection.Connection")
    @patch("core.ldap_connection.Server")
    def test_plaintext_transport_does_not_attempt_simple_bind(self, server_mock, connection_mock):
        """LDAP on port 389 may use NTLM but must never send a SIMPLE password bind."""
        server_mock.return_value = Mock()
        connection_mock.side_effect = LDAPException("authentication failed")
        ldap = build_connection(use_ssl=False)

        with self.assertRaises(LDAPConnectionError):
            ldap.connect()

        self.assertEqual(connection_mock.call_count, 1)
        self.assertEqual(connection_mock.call_args.kwargs["authentication"], NTLM)

    @patch("core.ldap_connection.Connection")
    @patch("core.ldap_connection.Server")
    def test_bound_connection_rejects_directory_writes(self, server_mock, connection_mock):
        """A bound client cannot add, change, delete or rename a directory object."""
        server_mock.return_value = Mock()
        client = Mock()
        client.bound = True
        client.read_only = False
        attempted = []
        for name in ("add", "delete", "modify", "modify_dn"):
            getattr(client, name).side_effect = lambda *args, name=name, **kwargs: attempted.append(name)
        connection_mock.return_value = client
        ldap = build_connection(use_ssl=True)

        self.assertTrue(ldap.connect())

        self.assertTrue(connection_mock.call_args.kwargs["read_only"])
        self.assertTrue(client.read_only)
        for name in ("add", "delete", "modify", "modify_dn"):
            with self.assertRaisesRegex(LDAPConnectionError, "read-only"):
                getattr(ldap.connection, name)("CN=unchanged,DC=example,DC=com")
        self.assertEqual(attempted, [])


class TestLDAPSearchCorrectness(unittest.TestCase):
    """LDAP result codes and partial paging must not become successful data."""

    def test_unsuccessful_search_result_raises(self):
        """ldap3 can return False without raising; the wrapper must surface it."""
        ldap = build_connection()
        ldap.connection = FakeSearchConnection(
            succeeded=False,
            result={
                "result": 50,
                "description": "insufficientAccessRights",
                "message": "access denied",
            },
        )

        with self.assertRaisesRegex(LDAPSearchError, "insufficientAccessRights"):
            ldap.search(search_filter="(objectClass=user)")

    def test_false_return_with_success_result_is_an_empty_success(self):
        """The LDAP result code remains authoritative for an empty response."""
        ldap = build_connection()
        ldap.connection = FakeSearchConnection(
            succeeded=False,
            result={"result": 0, "description": "success"},
        )

        self.assertEqual(ldap.search(search_filter="(objectClass=user)"), [])

    def test_security_descriptor_attribute_sends_sd_flags_control(self):
        ldap = build_connection(enable_paging=False)
        ldap.connection = FakeSearchConnection()
        ldap.search(search_filter="(objectClass=pKICertificateTemplate)", attributes=["nTSecurityDescriptor"])
        self.assertIn("controls", ldap.connection.last_kwargs)
        ldap.search(search_filter="(objectClass=user)", attributes=["sAMAccountName"])
        self.assertNotIn("controls", ldap.connection.last_kwargs)

    def test_paged_size_limit_does_not_duplicate_final_page(self):
        """Stopping at a caller size limit must append each entry exactly once."""
        ldap = build_connection(page_size=2)
        ldap.connection = FakeSearchConnection(
            entries=[
                FakeEntry("CN=One,DC=example,DC=com", "One"),
                FakeEntry("CN=Two,DC=example,DC=com", "Two"),
                FakeEntry("CN=Three,DC=example,DC=com", "Three"),
            ]
        )

        results = ldap._paged_search(
            search_base=ldap.base_dn,
            search_filter="(objectClass=computer)",
            attributes=["name"],
            size_limit=2,
            timeout=30,
        )

        self.assertEqual([result["name"] for result in results], ["One", "Two"])

    def test_paged_timeout_keeps_partial_results_on_the_error(self):
        """A timed-out page raises, and the pages already read stay on the error."""
        ldap = build_connection()
        ldap.connection = FakeSearchConnection(
            entries=[FakeEntry("CN=One,DC=example,DC=com", "One")]
        )
        ticks = iter((0, 0, 5))

        with patch("core.ldap_connection.time.monotonic", side_effect=lambda: next(ticks)):
            with self.assertRaisesRegex(LDAPSearchError, "partial entries retained") as raised:
                ldap._paged_search(
                    search_base=ldap.base_dn,
                    search_filter="(objectClass=computer)",
                    attributes=["name"],
                    size_limit=0,
                    timeout=1,
                )
        self.assertEqual(raised.exception.partial_results[0]["name"], "One")


if __name__ == "__main__":
    unittest.main()

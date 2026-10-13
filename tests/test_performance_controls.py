"""
Tests for performance-oriented scan controls.
"""

import unittest

from analysis.acl_security_analyzer import ACLSecurityAnalyzer
from core.ldap_connection import LDAPConnection
import analysis.registry as registry


class FakeLDAPConnection:
    """LDAP stub that fails on unexpected network calls."""

    def search(self, *args, **kwargs):
        raise AssertionError("Unexpected LDAP search")


class FakeConnection:
    """Minimal ldap3 connection stub."""

    def __init__(self):
        self.entries = []
        self.search_count = 0

    def search(self, *args, **kwargs):
        self.search_count += 1
        self.entries = []
        return True


class TestLDAPRateLimitHook(unittest.TestCase):
    """Ensure rate limiting is applied only to network searches."""

    def test_pre_search_hook_skips_cache_hits(self):
        ldap = LDAPConnection(
            domain="example.com",
            username="tester",
            password="ValidPass123!",
            dc_ip="10.0.0.1",
            enable_cache=True,
        )
        fake_connection = FakeConnection()
        ldap.connection = fake_connection

        hook_calls = []
        ldap.pre_search_hook = lambda: hook_calls.append("called")

        first = ldap.search(search_filter="(objectClass=user)", attributes=["cn"])
        second = ldap.search(search_filter="(objectClass=user)", attributes=["cn"])

        self.assertEqual(first, [])
        self.assertEqual(second, [])
        self.assertEqual(fake_connection.search_count, 1)
        self.assertEqual(len(hook_calls), 1)


class TestAnalysisProfiles(unittest.TestCase):
    """Test analysis profile and skip selection behavior."""

    def setUp(self):
        self.original_registry = registry.ANALYSIS_STEP_REGISTRY
        self.original_steps = registry.ANALYSIS_STEPS
        self.original_defaults = registry.ANALYSIS_STEP_DEFAULTS
        self.original_fast_excluded = registry.FAST_PROFILE_EXCLUDED

    def tearDown(self):
        registry.ANALYSIS_STEP_REGISTRY = self.original_registry
        registry.ANALYSIS_STEPS = self.original_steps
        registry.ANALYSIS_STEP_DEFAULTS = self.original_defaults
        registry.FAST_PROFILE_EXCLUDED = self.original_fast_excluded

    def test_fast_profile_uses_defaults_for_excluded_steps(self):
        registry.ANALYSIS_STEP_REGISTRY = [
            ("cheap", "Cheap analysis", lambda ldap, data: {"cheap_risks": [1]}),
            ("expensive", "Expensive analysis", lambda ldap, data: {"expensive_risks": [2]}),
        ]
        registry.ANALYSIS_STEP_DEFAULTS = {
            "cheap": {"cheap_risks": []},
            "expensive": {"expensive_risks": []},
        }
        registry.FAST_PROFILE_EXCLUDED = {"expensive"}

        result = registry.run_all_analyses(None, {}, profile="fast")

        self.assertEqual(result["cheap_risks"], [1])
        self.assertEqual(result["expensive_risks"], [])

    def test_skip_analysis_uses_default_result(self):
        registry.ANALYSIS_STEP_REGISTRY = [
            ("cheap", "Cheap analysis", lambda ldap, data: {"cheap_risks": [1]}),
        ]
        registry.ANALYSIS_STEP_DEFAULTS = {
            "cheap": {"cheap_risks": []},
        }

        result = registry.run_all_analyses(None, {}, skip_keys=["cheap"])

        self.assertEqual(result["cheap_risks"], [])

    def test_unexpected_step_failure_is_analysis_error(self):
        from core.exceptions import AnalysisError

        def broken_runner(ldap, data):
            raise TypeError("synthetic analyzer bug")

        registry.ANALYSIS_STEP_REGISTRY = [
            ("broken", "Broken analysis", broken_runner),
        ]
        registry.ANALYSIS_STEP_DEFAULTS = {"broken": {"broken_risks": []}}

        with self.assertRaises(AnalysisError) as caught:
            registry.run_all_analyses(None, {}, profile="full")
        self.assertIn("broken", str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, TypeError)


class TestACLShadowAdminPerformance(unittest.TestCase):
    """Shadow Admin detection should not perform per-user LDAP lookups."""

    def test_shadow_admin_detection_uses_collected_sid_data(self):
        analyzer = ACLSecurityAnalyzer(FakeLDAPConnection())
        users = [
            {
                "sAMAccountName": "alice",
                "distinguishedName": "CN=Alice,DC=example,DC=com",
                "objectSid": "S-1-5-21-1000",
                "memberOf": [],
            }
        ]
        groups = []
        acl_findings = [
            {
                "trustee": "S-1-5-21-1000",
                "permission": "GenericAll",
                "affected_object": "Domain",
                "object_type": "domain",
                "object_dn": "DC=example,DC=com",
                "is_inherited": False,
            }
        ]

        result = analyzer._detect_shadow_admins(
            users,
            groups,
            "DC=example,DC=com",
            privileged_users=[],
            privileged_groups=[],
            acl_findings=acl_findings,
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["user"], "alice")
        self.assertEqual(result[0]["principal_type"], "user")


class TestAclLegacySkipAndPaging(unittest.TestCase):
    def test_full_profile_skips_acl_legacy_when_acl_security_runs(self):
        keys = [key for key, _, _ in registry._selected_analysis_steps("full", [])]
        self.assertIn("acl_security", keys)
        self.assertNotIn("acl_legacy", keys)

    def test_fast_profile_excludes_acl_legacy(self):
        keys = [key for key, _, _ in registry._selected_analysis_steps("fast", [])]
        self.assertNotIn("acl_legacy", keys)
        self.assertNotIn("acl_security", keys)

    def test_paged_search_converts_only_new_accumulated_entries(self):
        from tests.test_ldap_connection import FakeEntry, build_connection

        class AccumulatingConnection:
            def __init__(self):
                self.entries = []
                self.result = {"result": 0, "description": "success"}
                self.bound = True
                self.calls = 0

            def search(self, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    self.entries = [FakeEntry("CN=One,DC=example,DC=com", "One")]
                    self.result = {"result": 0, "controls": {
                        "1.2.840.113556.1.4.319": {"value": {"cookie": b"next"}}
                    }}
                else:
                    self.entries = [
                        FakeEntry("CN=One,DC=example,DC=com", "One"),
                        FakeEntry("CN=Two,DC=example,DC=com", "Two"),
                    ]
                    self.result = {"result": 0, "controls": {
                        "1.2.840.113556.1.4.319": {"value": {"cookie": b""}}
                    }}
                return True

        ldap = build_connection(page_size=1, enable_cache=False)
        ldap.connection = AccumulatingConnection()
        converted = []
        original = ldap._entry_to_dict

        def counted(entry):
            converted.append(getattr(entry, "entry_dn", None))
            return original(entry)

        ldap._entry_to_dict = counted
        results = ldap._paged_search(
            search_base=ldap.base_dn,
            search_filter="(objectClass=computer)",
            attributes=["name"],
            size_limit=0,
            timeout=30,
        )
        self.assertEqual([row["name"] for row in results], ["One", "Two"])
        self.assertEqual(converted, ["CN=One,DC=example,DC=com", "CN=Two,DC=example,DC=com"])


if __name__ == "__main__":
    unittest.main()

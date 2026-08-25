"""Unit tests for modern AD/LDAP attack-surface analyzers."""

import unittest

from analysis.delegated_msa_analyzer import DelegatedMSAAnalyzer
from analysis.hidden_privilege_analyzer import HiddenPrivilegeAnalyzer
from analysis.hybrid_identity_analyzer import HybridIdentityAnalyzer
from analysis.ldap_directory_exposure_analyzer import LDAPDirectoryExposureAnalyzer
from analysis.rodc_attack_surface_analyzer import RODCAttackSurfaceAnalyzer
from analysis.sccm_attack_surface_analyzer import SCCMAttackSurfaceAnalyzer
from analysis.registry import CONSOLIDATION_RISK_KEYS, get_analysis_step_keys


class FakeLDAP:
    """Minimal LDAP stub that returns canned search results by filter substring."""

    def __init__(self, responses=None, base_dn="DC=contoso,DC=com"):
        self.base_dn = base_dn
        self.responses = responses or {}

    def search(self, search_base=None, search_filter="(objectClass=*)", attributes=None, size_limit=0, **kwargs):
        attrs = attributes or []
        if isinstance(attrs, str):
            attrs = [attrs]
        blob = f"{search_base or ''}|{search_filter or ''}|{' '.join(str(a) for a in attrs)}".lower()
        matches = [(key, rows) for key, rows in self.responses.items() if key.lower() in blob]
        if not matches:
            return []
        key, rows = max(matches, key=lambda item: len(item[0]))
        return list(rows)


class TestRegistryWiring(unittest.TestCase):
    def test_new_steps_registered(self):
        keys = get_analysis_step_keys()
        for key in (
            "ldap_directory_exposure",
            "hidden_privilege",
            "hybrid_identity",
            "rodc_attack_surface",
            "delegated_msa",
            "sccm_attack_surface",
        ):
            self.assertIn(key, keys)

    def test_new_risk_keys_consolidated(self):
        for key in (
            "ldap_directory_exposure_risks",
            "hidden_privilege_risks",
            "hybrid_identity_risks",
            "rodc_attack_surface_risks",
            "delegated_msa_risks",
            "sccm_attack_surface_risks",
        ):
            self.assertIn(key, CONSOLIDATION_RISK_KEYS)


class TestLDAPDirectoryExposureAnalyzer(unittest.TestCase):
    def test_anonymous_ldap_and_prewin2k(self):
        ldap = FakeLDAP({
            "objectClass=*": [{
                "configurationNamingContext": "CN=Configuration,DC=contoso,DC=com",
                "domainFunctionality": "3",
                "forestFunctionality": "3",
            }],
            "Directory Service": [{"dSHeuristics": "0000002"}],
            "Pre-Windows 2000": [{"cn": "Pre-Windows 2000 Compatible Access", "member": ["CN=Everyone,CN=WellKnown"]}],
            "Guest": [{"sAMAccountName": "Guest", "userAccountControl": 512}],
        })
        risks = LDAPDirectoryExposureAnalyzer(ldap).analyze()
        types = {risk["type"] for risk in risks}
        self.assertIn("ldap_anonymous_enabled", types)
        self.assertIn("ldap_prewin2k_broad_membership", types)
        self.assertIn("ldap_guest_enabled", types)
        self.assertIn("ldap_legacy_functional_level", types)

    def test_child_domain_does_not_invent_configuration_dn(self):
        class RecordingLDAP(FakeLDAP):
            def __init__(self):
                super().__init__(
                    {"objectClass=*": [{"domainFunctionality": "7", "forestFunctionality": "7"}]},
                    base_dn="DC=child,DC=contoso,DC=com",
                )
                self.bases = []

            def search(self, search_base=None, search_filter="(objectClass=*)", attributes=None, size_limit=0, **kwargs):
                self.bases.append(search_base)
                return super().search(search_base, search_filter, attributes, size_limit, **kwargs)

        ldap = RecordingLDAP()
        LDAPDirectoryExposureAnalyzer(ldap).analyze()
        self.assertFalse(
            any(
                base and "CN=Configuration,DC=child,DC=contoso,DC=com" in str(base)
                for base in ldap.bases
            )
        )

    def test_secure_defaults_produce_no_findings(self):
        ldap = FakeLDAP({
            "objectClass=*": [{"domainFunctionality": "7", "forestFunctionality": "7"}],
            "Guest": [{"sAMAccountName": "Guest", "userAccountControl": 514}],
        })
        self.assertEqual(LDAPDirectoryExposureAnalyzer(ldap).analyze(), [])


class TestHiddenPrivilegeAnalyzer(unittest.TestCase):
    def test_primary_group_and_computer_in_da(self):
        users = [{
            "sAMAccountName": "shadow",
            "userAccountControl": 512,
            "primaryGroupID": 512,
            "objectSid": "S-1-5-21-1-2-3-1106",
        }, {
            "sAMAccountName": "BreakGlass",
            "userAccountControl": 512,
            "primaryGroupID": 513,
            "objectSid": "S-1-5-21-1-2-3-500",
        }]
        computers = [{
            "name": "JUMP01",
            "sAMAccountName": "JUMP01$",
            "distinguishedName": "CN=JUMP01,CN=Computers,DC=contoso,DC=com",
            "userAccountControl": 4096,
            "primaryGroupID": 515,
        }]
        groups = [{
            "name": "Domain Admins",
            "member": ["CN=JUMP01,CN=Computers,DC=contoso,DC=com"],
        }]
        risks = HiddenPrivilegeAnalyzer().analyze(users, computers, groups)
        types = {risk["type"] for risk in risks}
        self.assertIn("hidden_primary_group_privilege", types)
        self.assertIn("privileged_computer_account", types)
        self.assertIn("builtin_admin_renamed", types)

    def test_hyperv_administrators_computer_member_is_not_privileged_group(self):
        computers = [{
            "name": "HV01",
            "sAMAccountName": "HV01$",
            "distinguishedName": "CN=HV01,CN=Computers,DC=contoso,DC=com",
            "userAccountControl": 4096,
            "primaryGroupID": 515,
        }]
        groups = [{
            "name": "Hyper-V Administrators",
            "member": ["CN=HV01,CN=Computers,DC=contoso,DC=com"],
        }]
        risks = HiddenPrivilegeAnalyzer().analyze([], computers, groups)
        types = {risk["type"] for risk in risks}
        self.assertNotIn("privileged_computer_account", types)


class TestHybridIdentityAnalyzer(unittest.TestCase):
    def test_connect_and_sso_accounts(self):
        users = [{
            "sAMAccountName": "MSOL_abc123",
            "userAccountControl": 512,
            "adminCount": "1",
            "memberOf": ["CN=Domain Admins,CN=Users,DC=contoso,DC=com"],
        }]
        computers = [{
            "sAMAccountName": "AZUREADSSOACC$",
            "name": "AZUREADSSOACC",
            "userAccountControl": 4096,
        }]
        risks = HybridIdentityAnalyzer(FakeLDAP()).analyze(users, computers)
        types = {risk["type"] for risk in risks}
        self.assertIn("hybrid_azure_sso_account", types)
        self.assertIn("hybrid_entra_connect_account", types)


class TestRODCAttackSurfaceAnalyzer(unittest.TestCase):
    def test_privileged_reveal(self):
        computers = [{
            "name": "RODC01",
            "sAMAccountName": "RODC01$",
            "userAccountControl": 0x4000000,
            "distinguishedName": "CN=RODC01,OU=Domain Controllers,DC=contoso,DC=com",
            "msDS-RevealOnDemandGroup": ["CN=Domain Admins,CN=Users,DC=contoso,DC=com"],
            "msDS-NeverRevealGroup": [],
            "msDS-RevealedUsers": [f"user{i}" for i in range(30)],
        }]
        groups = [{
            "name": "Allowed RODC Password Replication Group",
            "member": ["CN=Domain Admins,CN=Users,DC=contoso,DC=com"],
        }]
        risks = RODCAttackSurfaceAnalyzer(FakeLDAP()).analyze(computers, groups)
        types = {risk["type"] for risk in risks}
        self.assertIn("rodc_missing_never_reveal", types)
        self.assertIn("rodc_privileged_reveal", types)
        self.assertIn("rodc_allowed_group_privileged", types)


class TestDelegatedMSAAnalyzer(unittest.TestCase):
    def test_predecessor_link(self):
        ldap = FakeLDAP({
            "msDS-DelegatedManagedServiceAccount": [{
                "sAMAccountName": "evil$",
                "msDS-ManagedAccountPrecededByLink": "CN=Administrator,CN=Users,DC=contoso,DC=com",
                "msDS-DelegatedMSAState": "2",
            }]
        })
        risks = DelegatedMSAAnalyzer(ldap).analyze()
        self.assertTrue(any(r["type"] == "dmsa_predecessor_link" for r in risks))

    def test_schema_present_without_objects(self):
        ldap = FakeLDAP({
            "schemaNamingContext": [{
                "schemaNamingContext": "CN=Schema,CN=Configuration,DC=contoso,DC=com",
            }],
            "msDS-DelegatedManagedServiceAccount": [],
            "lDAPDisplayName=msDS-DelegatedManagedServiceAccount": [{
                "lDAPDisplayName": "msDS-DelegatedManagedServiceAccount",
                "cn": "ms-DS-Delegated-Managed-Service-Account",
            }],
        })
        risks = DelegatedMSAAnalyzer(ldap).analyze()
        self.assertTrue(any(r["type"] == "dmsa_schema_enabled" for r in risks))


class TestSCCMAttackSurfaceAnalyzer(unittest.TestCase):
    def test_management_container(self):
        ldap = FakeLDAP({
            "System Management": [
                {"cn": "SMS-MP-SITE-MP01", "dNSHostName": "mp01.contoso.com", "objectClass": ["mSSMSManagementPoint"]},
                {"cn": "SMS-SITE-P01"},
            ]
        })
        risks = SCCMAttackSurfaceAnalyzer(ldap).analyze()
        types = {risk["type"] for risk in risks}
        self.assertIn("sccm_system_management_present", types)
        self.assertIn("sccm_management_point", types)

    def test_absent_container(self):
        ldap = FakeLDAP()
        def boom(**kwargs):
            raise Exception("no such object")
        ldap.search = boom
        self.assertEqual(SCCMAttackSurfaceAnalyzer(ldap).analyze(), [])


class TestGuestRID501(unittest.TestCase):
    def test_renamed_enabled_guest_is_detected_from_sid(self):
        users = [{
            "sAMAccountName": "HelpdeskGuest",
            "userAccountControl": 512,
            "objectSid": "S-1-5-21-1-2-3-501",
        }]
        risks = LDAPDirectoryExposureAnalyzer(FakeLDAP()).analyze(users)
        self.assertTrue(any(risk["type"] == "ldap_guest_enabled" for risk in risks))

    def test_disabled_renamed_guest_is_ignored(self):
        users = [{
            "sAMAccountName": "HelpdeskGuest",
            "userAccountControl": 514,
            "objectSid": "S-1-5-21-1-2-3-501",
        }]
        risks = LDAPDirectoryExposureAnalyzer(FakeLDAP()).analyze(users)
        self.assertFalse(any(risk["type"] == "ldap_guest_enabled" for risk in risks))


class TestHybridIdentityFalsePositives(unittest.TestCase):
    def test_on_prem_estate_does_not_report_missing_hybrid_join(self):
        computers = [{"sAMAccountName": "PC01$", "name": "PC01", "userAccountControl": 4096}]
        risks = HybridIdentityAnalyzer(FakeLDAP()).analyze([], computers)
        self.assertFalse(any(risk["type"] == "hybrid_join_not_observed" for risk in risks))

    def test_account_named_adfs_without_spn_is_not_flagged(self):
        users = [{"sAMAccountName": "ADFSHelpdesk", "userAccountControl": 512, "servicePrincipalName": []}]
        risks = HybridIdentityAnalyzer(FakeLDAP()).analyze(users, [])
        self.assertFalse(any(risk["type"] == "hybrid_adfs_service" for risk in risks))

    def test_adfs_spn_is_flagged(self):
        computers = [{
            "sAMAccountName": "STS$",
            "name": "STS",
            "userAccountControl": 4096,
            "servicePrincipalName": ["http/adfs.contoso.com"],
        }]
        risks = HybridIdentityAnalyzer(FakeLDAP()).analyze([], computers)
        self.assertTrue(any(risk["type"] == "hybrid_adfs_service" for risk in risks))

    def test_connect_account_without_hybrid_join_adds_coverage_finding(self):
        users = [{
            "sAMAccountName": "MSOL_abc123",
            "userAccountControl": 512,
            "adminCount": "1",
            "memberOf": ["CN=Domain Admins,CN=Users,DC=contoso,DC=com"],
        }]
        computers = [{"sAMAccountName": "PC01$", "name": "PC01", "userAccountControl": 4096}]
        types = {risk["type"] for risk in HybridIdentityAnalyzer(FakeLDAP()).analyze(users, computers)}
        self.assertIn("hybrid_entra_connect_account", types)
        self.assertIn("hybrid_join_not_observed", types)


class TestDelegatedMSASchemaContext(unittest.TestCase):
    def test_child_domain_uses_rootdse_schema_naming_context(self):
        ldap = FakeLDAP(
            {
                "schemaNamingContext": [{
                    "schemaNamingContext": "CN=Schema,CN=Configuration,DC=contoso,DC=com",
                }],
                "lDAPDisplayName=msDS-DelegatedManagedServiceAccount": [{
                    "lDAPDisplayName": "msDS-DelegatedManagedServiceAccount",
                }],
            },
            base_dn="DC=child,DC=contoso,DC=com",
        )
        risks = DelegatedMSAAnalyzer(ldap).analyze()
        self.assertTrue(any(risk["type"] == "dmsa_schema_enabled" for risk in risks))


class TestLAPSAnalyzerHardening(unittest.TestCase):
    def test_does_not_query_each_computer_or_request_password_attributes(self):
        from analysis.laps_analyzer import LAPSAnalyzer

        class RecordingLDAP(FakeLDAP):
            def __init__(self):
                super().__init__()
                self.calls = []

            def search(self, search_base=None, search_filter="(objectClass=*)", attributes=None, size_limit=0, **kwargs):
                self.calls.append({
                    "search_base": search_base,
                    "search_filter": search_filter,
                    "attributes": list(attributes or []),
                })
                return super().search(search_base, search_filter, attributes, size_limit, **kwargs)

        ldap = RecordingLDAP()
        computers = [
            {
                "name": f"PC{i:03d}",
                "sAMAccountName": f"PC{i:03d}$",
                "distinguishedName": f"CN=PC{i:03d},CN=Computers,DC=contoso,DC=com",
            }
            for i in range(80)
        ]
        LAPSAnalyzer(ldap).analyze_laps(computers, [], [])
        self.assertLess(len(ldap.calls), 10)
        for call in ldap.calls:
            for attr in call["attributes"]:
                self.assertNotEqual(str(attr).lower(), "mslaps-password")
                self.assertNotEqual(str(attr).lower(), "ms-mcs-admpwd")

    def test_collected_expiry_attributes_avoid_coverage_search(self):
        from analysis.laps_analyzer import LAPSAnalyzer

        class RecordingLDAP(FakeLDAP):
            def __init__(self):
                super().__init__()
                self.calls = []

            def search(self, search_base=None, search_filter="(objectClass=*)", attributes=None, size_limit=0, **kwargs):
                self.calls.append(search_filter)
                return super().search(search_base, search_filter, attributes, size_limit, **kwargs)

        ldap = RecordingLDAP()
        computers = [{
            "name": f"PC{i}",
            "ms-Mcs-AdmPwdExpirationTime": "1",
            "msLAPS-PasswordExpirationTime": "1",
        } for i in range(8)]
        risks = LAPSAnalyzer(ldap).analyze_laps(computers, [], [])
        self.assertFalse(any("AdmPwdExpirationTime" in str(call) for call in ldap.calls))
        types = {risk["type"] for risk in risks}
        self.assertNotIn("windows_laps_not_deployed", types)


class TestRiskTabCategorization(unittest.TestCase):
    def test_ldap_signing_is_not_directory_exposure(self):
        from reporting.report_sections.risk_tab_builder import (
            ADCS_EXTENDED_TYPES,
            LDAP_DIRECTORY_EXPOSURE_TYPES,
            PASSWORD_POLICY_TYPES,
        )
        self.assertNotIn("ldap_signing_disabled", LDAP_DIRECTORY_EXPOSURE_TYPES)
        self.assertIn("ldap_anonymous_enabled", LDAP_DIRECTORY_EXPOSURE_TYPES)
        self.assertIn("certificate_esc15", ADCS_EXTENDED_TYPES)
        self.assertNotIn("weak_fine_grained_password_policy", PASSWORD_POLICY_TYPES)


class TestRODCFilterEscaping(unittest.TestCase):
    def test_distinguished_name_with_parentheses_is_escaped(self):
        class RecordingLDAP(FakeLDAP):
            def __init__(self):
                super().__init__()
                self.filters = []

            def search(self, search_base=None, search_filter="(objectClass=*)", attributes=None, size_limit=0, **kwargs):
                self.filters.append(search_filter)
                return []

        ldap = RecordingLDAP()
        computers = [{
            "name": "RODC01",
            "sAMAccountName": "RODC01$",
            "userAccountControl": 0x4000000,
            "distinguishedName": "CN=RODC01 (Site A),OU=Domain Controllers,DC=contoso,DC=com",
        }]
        RODCAttackSurfaceAnalyzer(ldap).analyze(computers, [])
        self.assertTrue(any("\\28" in item or "\\29" in item for item in ldap.filters))


if __name__ == "__main__":
    unittest.main()

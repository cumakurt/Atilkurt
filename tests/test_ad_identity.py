"""Tests for well-known AD identity matching."""

import unittest

from core.ad_identity import (
    DOMAIN_ADMINS_RID,
    first_ldap_rdn,
    group_is_role,
    is_privileged_group_name,
    is_privileged_group_record,
    is_privileged_principal_reference,
    membership_names,
    sid_rid,
)
from analysis.privileged_account_status import privileged_admin_roles


class TestSidRid(unittest.TestCase):
    def test_sddl_and_binary(self):
        self.assertEqual(sid_rid("S-1-5-21-1-2-3-512"), 512)
        self.assertEqual(sid_rid(b"\x01\x05" + b"\x00" * 6 + b"\x00" * 16 + (512).to_bytes(4, "little")), 512)
        self.assertIsNone(sid_rid(None))
        self.assertIsNone(sid_rid("CN=Domain Admins,CN=Users,DC=example,DC=com"))


class TestFirstLdapRdn(unittest.TestCase):
    def test_dn_and_bare_name(self):
        self.assertEqual(
            first_ldap_rdn("CN=Domain Admins,CN=Users,DC=example,DC=com"),
            "Domain Admins",
        )
        self.assertEqual(first_ldap_rdn("Hyper-V Administrators"), "Hyper-V Administrators")
        self.assertEqual(first_ldap_rdn("S-1-5-21-1-2-3-512"), "")


class TestGroupIsRole(unittest.TestCase):
    def test_exact_name_matches_domain_admins(self):
        group = {
            "name": "Domain Admins",
            "sAMAccountName": "Domain Admins",
            "distinguishedName": "CN=Domain Admins,CN=Users,DC=example,DC=com",
        }
        self.assertTrue(group_is_role(group, "Domain Admins"))

    def test_ou_named_domain_admins_does_not_match(self):
        group = {
            "name": "Helpdesk",
            "sAMAccountName": "Helpdesk",
            "distinguishedName": "CN=Helpdesk,OU=Domain Admins,DC=example,DC=com",
        }
        self.assertFalse(group_is_role(group, "Domain Admins"))

    def test_localized_name_matches_via_rid(self):
        group = {
            "name": "Domänen-Admins",
            "sAMAccountName": "Domänen-Admins",
            "objectSid": "S-1-5-21-1-2-3-512",
            "distinguishedName": "CN=Domänen-Admins,CN=Users,DC=example,DC=com",
        }
        self.assertTrue(group_is_role(group, "Domain Admins"))
        self.assertEqual(sid_rid(group["objectSid"]), DOMAIN_ADMINS_RID)

    def test_hyperv_administrators_is_not_builtin_administrators(self):
        self.assertFalse(is_privileged_group_name("Hyper-V Administrators"))
        self.assertFalse(
            is_privileged_group_record({
                "name": "Hyper-V Administrators",
                "sAMAccountName": "Hyper-V Administrators",
                "distinguishedName": "CN=Hyper-V Administrators,CN=Builtin,DC=example,DC=com",
            })
        )


class TestPrivilegedPrincipalReference(unittest.TestCase):
    def test_domain_admins_dn_is_privileged(self):
        self.assertTrue(
            is_privileged_principal_reference("CN=Domain Admins,CN=Users,DC=example,DC=com")
        )

    def test_hyperv_administrators_dn_is_not_privileged(self):
        self.assertFalse(
            is_privileged_principal_reference(
                "CN=Hyper-V Administrators,CN=Builtin,DC=example,DC=com"
            )
        )

    def test_administrator_and_krbtgt_are_privileged(self):
        self.assertTrue(is_privileged_principal_reference("CN=krbtgt,CN=Users,DC=example,DC=com"))
        self.assertTrue(
            is_privileged_principal_reference("CN=Administrator,CN=Users,DC=example,DC=com")
        )

    def test_admin_count_is_privileged_evidence(self):
        from core.ad_identity import account_has_privileged_evidence
        self.assertTrue(account_has_privileged_evidence({"adminCount": "1", "memberOf": []}))
        self.assertFalse(
            account_has_privileged_evidence({
                "adminCount": "0",
                "memberOf": ["CN=Hyper-V Administrators,CN=Builtin,DC=example,DC=com"],
            })
        )
        self.assertTrue(
            account_has_privileged_evidence({
                "adminCount": "0",
                "memberOf": ["CN=Domain Admins,CN=Users,DC=example,DC=com"],
            })
        )


class TestMembershipAndAdminRoles(unittest.TestCase):
    def test_membership_uses_first_rdn_only(self):
        names = membership_names([
            "CN=Helpdesk,OU=Domain Admins,DC=example,DC=com",
            "CN=Domain Admins,CN=Users,DC=example,DC=com",
        ])
        self.assertEqual(names, {"helpdesk", "domain admins"})

    def test_user_in_ou_named_domain_admins_is_not_a_domain_admin(self):
        roles = privileged_admin_roles({
            "sAMAccountName": "helpdesk",
            "memberOf": ["CN=Helpdesk,OU=Domain Admins,DC=example,DC=com"],
            "primaryGroupID": 513,
        })
        self.assertEqual(roles, [])

    def test_user_with_domain_admins_member_of(self):
        roles = privileged_admin_roles({
            "sAMAccountName": "da",
            "memberOf": ["CN=Domain Admins,CN=Users,DC=example,DC=com"],
            "primaryGroupID": 513,
        })
        self.assertEqual(roles, ["Domain Admins"])


class TestDomainControllerDetection(unittest.TestCase):
    def test_server_trust_account_is_dc(self):
        from core.ad_identity import computer_is_domain_controller
        self.assertTrue(computer_is_domain_controller({
            "name": "DC01",
            "userAccountControl": 0x2000,
            "distinguishedName": "CN=DC01,OU=Domain Controllers,DC=example,DC=com",
        }))

    def test_hostname_containing_dc_is_not_enough(self):
        from core.ad_identity import computer_is_domain_controller
        self.assertFalse(computer_is_domain_controller({
            "name": "ADCS01",
            "userAccountControl": 4096,
            "primaryGroupID": 515,
            "distinguishedName": "CN=ADCS01,CN=Computers,DC=example,DC=com",
        }))

    def test_ou_domain_controllers_is_enough(self):
        from core.ad_identity import computer_is_domain_controller
        self.assertTrue(computer_is_domain_controller({
            "name": "RODC01",
            "userAccountControl": 0x4000000,
            "distinguishedName": "CN=RODC01,OU=Domain Controllers,DC=example,DC=com",
        }))

    def test_spaced_domain_controllers_ou_still_matches(self):
        from core.ad_identity import computer_is_domain_controller
        self.assertTrue(computer_is_domain_controller({
            "name": "DC02",
            "userAccountControl": 4096,
            "distinguishedName": "CN=DC02,OU=Domain Controllers,DC=example,DC=com",
        }))


class TestForestConfigurationDn(unittest.TestCase):
    def test_uses_rootdse_not_child_domain_dn(self):
        from core.ad_identity import forest_configuration_dn

        class FakeLDAP:
            base_dn = "DC=child,DC=example,DC=com"

            def search(self, **kwargs):
                if kwargs.get("search_base") == "":
                    return [{"configurationNamingContext": "CN=Configuration,DC=example,DC=com"}]
                return []

        self.assertEqual(
            forest_configuration_dn(FakeLDAP()),
            "CN=Configuration,DC=example,DC=com",
        )

    def test_does_not_invent_config_dn_from_child_domain(self):
        from core.ad_identity import forest_configuration_dn

        class FakeLDAP:
            base_dn = "DC=child,DC=example,DC=com"

            def search(self, **kwargs):
                return []

        self.assertIsNone(forest_configuration_dn(FakeLDAP()))


if __name__ == "__main__":
    unittest.main()

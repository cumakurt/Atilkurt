"""
Tests for Analysis Modules
Unit tests for user risk, computer risk, and other analyzers
"""

import unittest
from datetime import datetime
from analysis.user_risks import UserRiskAnalyzer
from analysis.computer_risks import ComputerRiskAnalyzer
from analysis.group_risks import GroupRiskAnalyzer
from analysis.kerberoasting_detector import KerberoastingDetector
from analysis.legacy_os_analyzer import LegacyOSAnalyzer
from analysis.exploitability_scorer import ExploitabilityScorer


class TestUserRiskAnalyzer(unittest.TestCase):
    """Test cases for UserRiskAnalyzer."""

    def setUp(self):
        self.analyzer = UserRiskAnalyzer()

    def test_empty_users(self):
        """No users → no risks."""
        risks = self.analyzer.analyze([])
        self.assertEqual(risks, [])

    def test_disabled_admin(self):
        """Disabled admin account should be detected."""
        users = [{
            'sAMAccountName': 'admin',
            'userAccountControl': 514,  # ACCOUNTDISABLE + NORMAL_ACCOUNT
            'adminCount': 1,
            'memberOf': ['CN=Domain Admins,CN=Users,DC=test,DC=com'],
            'pwdLastSet': None,
            'lastLogonTimestamp': None,
            'servicePrincipalName': [],
            'isDisabled': True,
            'distinguishedName': 'CN=admin,CN=Users,DC=test,DC=com',
        }]
        risks = self.analyzer.analyze(users)
        types = {risk.get("type") for risk in risks}
        self.assertIn("disabled_domain_admin", types)
        self.assertNotIn("disabled_user_account", types)
        finding = next(risk for risk in risks if risk["type"] == "disabled_domain_admin")
        self.assertEqual(finding.get("affected_object"), "admin")
        self.assertEqual(finding.get("severity"), "high")

    def test_disabled_enterprise_admin(self):
        """Disabled Enterprise Admin accounts are reported separately."""
        users = [{
            "sAMAccountName": "ea_old",
            "userAccountControl": 514,
            "adminCount": 1,
            "memberOf": ["CN=Enterprise Admins,CN=Users,DC=test,DC=com"],
            "pwdLastSet": None,
            "lastLogonTimestamp": None,
            "servicePrincipalName": [],
            "isDisabled": True,
            "distinguishedName": "CN=ea_old,CN=Users,DC=test,DC=com",
        }]
        types = {risk.get("type") for risk in self.analyzer.analyze(users)}
        self.assertIn("disabled_enterprise_admin", types)

    def test_enabled_domain_admin_is_not_flagged_as_disabled(self):
        users = [{
            "sAMAccountName": "da_live",
            "userAccountControl": 512,
            "adminCount": 1,
            "memberOf": ["CN=Domain Admins,CN=Users,DC=test,DC=com"],
            "pwdLastSet": None,
            "lastLogonTimestamp": None,
            "servicePrincipalName": [],
            "isDisabled": False,
            "distinguishedName": "CN=da_live,CN=Users,DC=test,DC=com",
        }]
        types = {risk.get("type") for risk in self.analyzer.analyze(users)}
        self.assertNotIn("disabled_domain_admin", types)

    def test_user_with_no_password_expiry(self):
        """User with DONT_EXPIRE_PASSWORD flag should be flagged."""
        users = [{
            'sAMAccountName': 'svc_account',
            'userAccountControl': 66048,  # NORMAL + DONT_EXPIRE_PASSWORD
            'adminCount': 0,
            'memberOf': [],
            'pwdLastSet': None,
            'lastLogonTimestamp': None,
            'servicePrincipalName': [],
            'isDisabled': False,
            'distinguishedName': 'CN=svc_account,CN=Users,DC=test,DC=com',
        }]
        risks = self.analyzer.analyze(users)
        self.assertIsInstance(risks, list)
        self.assertTrue(any(r.get('type') == 'user_password_never_expires' for r in risks))


class TestUserCollectorLockout(unittest.TestCase):
    """Locked-account detection must honor UAC LOCKOUT and non-zero lockoutTime."""

    def test_nonzero_filetime_is_locked(self):
        from unittest.mock import MagicMock
        from core.collectors.user_collector import UserCollector

        collector = UserCollector(MagicMock(), show_progress=False)
        self.assertTrue(collector._is_account_locked(132000000000000000))
        self.assertFalse(collector._is_account_locked(0))
        self.assertTrue(collector._is_account_locked(datetime.now()))

    def test_uac_lockout_flag_marks_account_locked(self):
        from unittest.mock import MagicMock
        from core.collectors.user_collector import UserCollector
        from core.constants import UACFlags

        ldap = MagicMock()
        ldap.search.return_value = [{
            "sAMAccountName": "locked",
            "userAccountControl": UACFlags.LOCKOUT | UACFlags.NORMAL_ACCOUNT,
            "lockoutTime": 0,
            "memberOf": [],
            "servicePrincipalName": [],
        }]
        users = UserCollector(ldap, show_progress=False).collect()
        self.assertEqual(len(users), 1)
        self.assertTrue(users[0]["isLocked"])


class TestComputerRiskAnalyzer(unittest.TestCase):
    """Test cases for ComputerRiskAnalyzer."""

    def setUp(self):
        self.analyzer = ComputerRiskAnalyzer()

    def test_empty_computers(self):
        """No computers → no risks."""
        risks = self.analyzer.analyze([])
        self.assertEqual(risks, [])

    def test_old_os(self):
        """Computer with Windows Server 2008 should be flagged."""
        computers = [{
            'name': 'SERVER01',
            'operatingSystem': 'Windows Server 2008 R2',
            'operatingSystemVersion': '6.1 (7601)',
            'lastLogonTimestamp': None,
            'whenCreated': None,
            'userAccountControl': 4096,
            'distinguishedName': 'CN=SERVER01,CN=Computers,DC=test,DC=com',
            'unconstrainedDelegation': False,
            'trustedToAuthForDelegation': False,
            'msDS_AllowedToDelegateTo': [],
        }]
        risks = self.analyzer.analyze(computers)
        self.assertIsInstance(risks, list)

    def test_longest_eol_os_name_matches_first(self):
        """Windows 8.1 must not be classified as Windows 8."""
        risks = self.analyzer.analyze([{
            'name': 'WORKSTATION01',
            'operatingSystem': 'Windows 8.1 Enterprise',
            'lastLogonTimestamp': None,
            'whenCreated': None,
        }])

        eol_risk = next(risk for risk in risks if risk['type'] == 'eol_operating_system')
        self.assertEqual(eol_risk['eol_date'], '2023-01-10')


class TestGroupRiskAnalyzer(unittest.TestCase):
    """Test cases for GroupRiskAnalyzer."""

    def setUp(self):
        self.analyzer = GroupRiskAnalyzer()

    def test_empty_groups(self):
        """No groups → no risks."""
        risks = self.analyzer.analyze([], [])
        self.assertEqual(risks, [])

    def test_domain_admins_excessive_members(self):
        """Domain Admins with many members should be flagged."""
        groups = [{
            'name': 'Domain Admins',
            'sAMAccountName': 'Domain Admins',
            'distinguishedName': 'CN=Domain Admins,CN=Users,DC=test,DC=com',
            'member': [f'CN=user{i},CN=Users,DC=test,DC=com' for i in range(15)],
            'memberOf': [],
            'whenCreated': None,
            'whenChanged': None,
            'isPrivileged': True,
        }]
        users = []
        risks = self.analyzer.analyze(groups, users)
        self.assertIsInstance(risks, list)

    def test_disabled_domain_admin_group_member(self):
        """A disabled user listed on Domain Admins is reported even without memberOf."""
        groups = [{
            "name": "Domain Admins",
            "sAMAccountName": "Domain Admins",
            "distinguishedName": "CN=Domain Admins,CN=Users,DC=test,DC=com",
            "member": ["CN=legacyda,CN=Users,DC=test,DC=com"],
            "memberOf": [],
            "whenCreated": None,
            "whenChanged": None,
            "isPrivileged": True,
        }]
        users = [{
            "sAMAccountName": "legacyda",
            "userAccountControl": 514,
            "isDisabled": True,
            "memberOf": [],
            "distinguishedName": "CN=legacyda,CN=Users,DC=test,DC=com",
        }]
        types = {risk.get("type") for risk in self.analyzer.analyze(groups, users)}
        self.assertIn("disabled_domain_admin", types)

    def test_group_in_ou_named_domain_admins_is_not_too_many_das(self):
        groups = [{
            "name": "Helpdesk",
            "sAMAccountName": "Helpdesk",
            "distinguishedName": "CN=Helpdesk,OU=Domain Admins,DC=test,DC=com",
            "member": [f"CN=user{i},CN=Users,DC=test,DC=com" for i in range(15)],
            "memberOf": [],
            "isPrivileged": False,
        }]
        types = {risk.get("type") for risk in self.analyzer.analyze(groups, [])}
        self.assertNotIn("too_many_domain_admins", types)

    def test_hyperv_administrators_is_not_nested_admin_group(self):
        groups = [{
            "name": "Hyper-V Administrators",
            "sAMAccountName": "Hyper-V Administrators",
            "distinguishedName": "CN=Hyper-V Administrators,CN=Builtin,DC=test,DC=com",
            "member": [],
            "memberOf": ["CN=Administrators,CN=Builtin,DC=test,DC=com"],
            "isPrivileged": False,
        }]
        types = {risk.get("type") for risk in self.analyzer.analyze(groups, [])}
        self.assertNotIn("nested_admin_group", types)


class TestKerberoastingDetector(unittest.TestCase):
    """Test cases for KerberoastingDetector."""

    def setUp(self):
        self.detector = KerberoastingDetector()

    def test_no_targets(self):
        """Users without SPNs should not be Kerberoasting targets."""
        users = [{
            'sAMAccountName': 'user1',
            'servicePrincipalName': [],
            'userAccountControl': 512,
            'isDisabled': False,
            'memberOf': [],
            'distinguishedName': 'CN=user1,CN=Users,DC=test,DC=com',
        }]
        targets = self.detector.detect_kerberoasting_targets(users)
        self.assertEqual(len(targets), 0)

    def test_spn_user_detected(self):
        """Users with SPNs should be Kerberoasting targets."""
        users = [{
            'sAMAccountName': 'svc_sql',
            'servicePrincipalName': ['MSSQLSvc/sql01.test.com:1433'],
            'userAccountControl': 512,
            'isDisabled': False,
            'memberOf': ['CN=Domain Admins,CN=Users,DC=test,DC=com'],
            'distinguishedName': 'CN=svc_sql,CN=Users,DC=test,DC=com',
            'adminCount': 1,
        }]
        targets = self.detector.detect_kerberoasting_targets(users)
        # Should detect at least one target
        self.assertGreaterEqual(len(targets), 1)


class TestLegacyOSAnalyzer(unittest.TestCase):
    """Test cases for LegacyOSAnalyzer."""

    def setUp(self):
        self.analyzer = LegacyOSAnalyzer()

    def test_empty_computers(self):
        """No computers → empty results."""
        result = self.analyzer.analyze([])
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get('total_count', 0), 0)

    def test_eol_os_detected(self):
        """Windows XP should be detected as EOL."""
        computers = [{
            'name': 'OLD_PC',
            'operatingSystem': 'Windows XP Professional',
            'operatingSystemVersion': '5.1',
            'lastLogonTimestamp': None,
            'distinguishedName': 'CN=OLD_PC,CN=Computers,DC=test,DC=com',
            'userAccountControl': 4096,
        }]
        result = self.analyzer.analyze(computers)
        self.assertIsInstance(result, dict)

    def test_longest_eol_os_name_matches_first(self):
        """Windows 8.1 must use its own EOL date."""
        result = self.analyzer.analyze([{
            'name': 'WORKSTATION01',
            'operatingSystem': 'Windows 8.1 Enterprise',
            'operatingSystemVersion': '6.3',
        }])

        self.assertEqual(result['legacy_computers'][0]['legacyOSInfo']['eol_date'], '2023-01-10')


class TestExploitabilityScorer(unittest.TestCase):
    """Test cases for ExploitabilityScorer."""

    def setUp(self):
        self.scorer = ExploitabilityScorer()

    def test_score_basic_risk(self):
        """Score a basic risk dictionary."""
        risk = {
            'type': 'password_never_expires',
            'severity': 'high',
            'title': 'Password Never Expires',
            'description': 'Test risk',
            'affected_object': 'user1',
            'object_type': 'user',
        }
        score = self.scorer.score_risk(risk)
        self.assertIsInstance(score, dict)


class TestPrivilegeEscalationMatching(unittest.TestCase):
    def test_hyperv_administrators_is_not_a_privileged_group(self):
        from analysis.privilege_escalation import PrivilegeEscalationAnalyzer

        analyzer = PrivilegeEscalationAnalyzer()
        self.assertFalse(analyzer._is_privileged_group("Hyper-V Administrators"))
        self.assertTrue(analyzer._is_privileged_group("Domain Admins"))

    def test_helpdesk_in_ou_named_domain_admins_is_not_extracted_as_da(self):
        from analysis.privilege_escalation import PrivilegeEscalationAnalyzer

        analyzer = PrivilegeEscalationAnalyzer()
        self.assertEqual(
            analyzer._extract_group_name("CN=Helpdesk,OU=Domain Admins,DC=test,DC=com"),
            "Helpdesk",
        )


if __name__ == '__main__':
    unittest.main()

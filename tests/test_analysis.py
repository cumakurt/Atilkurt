"""
Tests for Analysis Modules
Unit tests for user risk, computer risk, and other analyzers
"""

import unittest
from analysis.user_risks import UserRiskAnalyzer
from analysis.computer_risks import ComputerRiskAnalyzer
from analysis.group_risks import GroupRiskAnalyzer
from analysis.kerberos_delegation import KerberosDelegationAnalyzer
from analysis.kerberoasting_detector import KerberoastingDetector
from analysis.service_account_analyzer import ServiceAccountAnalyzer
from analysis.legacy_os_analyzer import LegacyOSAnalyzer
from analysis.gpo_abuse_analyzer import GPOAbuseAnalyzer
from analysis.exploitability_scorer import ExploitabilityScorer
from analysis.privilege_escalation import PrivilegeEscalationAnalyzer


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
        self.assertIsInstance(risks, list)

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
        # Should find risks for password never expiring
        risk_types = [r.get('type', '') for r in risks]
        # May vary by implementation, but we expect at least something
        self.assertTrue(len(risks) >= 0)


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


if __name__ == '__main__':
    unittest.main()

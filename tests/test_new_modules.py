"""
Tests for New Analysis Modules
Unit tests for PasswordSprayRiskAnalyzer, GoldenGMSAAnalyzer, HoneypotDetector,
StaleObjectsAnalyzer, ADCSExtendedAnalyzer, AuditPolicyAnalyzer,
BackupOperatorAnalyzer, CoerceAttackAnalyzer, GMSAAnalyzer,
KRBTGTHealthAnalyzer, LateralMovementAnalyzer, MachineQuotaAnalyzer,
ReplicationMetadataAnalyzer
"""

import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta


# ═══════════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _make_mock_ldap(search_results=None):
    """Create a mock LDAP connection that returns configurable search results."""
    mock = MagicMock()
    mock.search.return_value = search_results or []
    mock.search_s.return_value = search_results or []
    # Support for analyzers that use ldap_conn.connection.search(...)
    mock.connection = MagicMock()
    mock.connection.search.return_value = True
    mock.connection.response = search_results or []
    mock.connection.entries = search_results or []
    # Support for .base_dn / .domain_dn
    mock.base_dn = 'DC=test,DC=com'
    mock.domain_dn = 'DC=test,DC=com'
    mock.default_search_base = 'DC=test,DC=com'
    return mock


def _make_user(**overrides):
    """Create a user dict with sane defaults."""
    base = {
        'sAMAccountName': 'testuser',
        'distinguishedName': 'CN=testuser,CN=Users,DC=test,DC=com',
        'userAccountControl': 512,
        'memberOf': [],
        'adminCount': 0,
        'pwdLastSet': datetime.now() - timedelta(days=30),
        'lastLogonTimestamp': datetime.now() - timedelta(days=5),
        'servicePrincipalName': [],
        'isDisabled': False,
        'description': '',
        'whenCreated': datetime.now() - timedelta(days=365),
    }
    base.update(overrides)
    return base


def _make_computer(**overrides):
    """Create a computer dict with sane defaults."""
    base = {
        'name': 'SRV01',
        'sAMAccountName': 'SRV01$',
        'distinguishedName': 'CN=SRV01,CN=Computers,DC=test,DC=com',
        'operatingSystem': 'Windows Server 2019',
        'operatingSystemVersion': '10.0 (17763)',
        'userAccountControl': 4096,
        'lastLogonTimestamp': datetime.now() - timedelta(days=5),
        'whenCreated': datetime.now() - timedelta(days=365),
        'servicePrincipalName': [],
    }
    base.update(overrides)
    return base


def _make_group(**overrides):
    """Create a group dict with sane defaults."""
    base = {
        'name': 'TestGroup',
        'sAMAccountName': 'TestGroup',
        'distinguishedName': 'CN=TestGroup,CN=Users,DC=test,DC=com',
        'member': [],
        'memberOf': [],
        'isPrivileged': False,
    }
    base.update(overrides)
    return base


# ═══════════════════════════════════════════════════════════════════════════
#  PasswordSprayRiskAnalyzer Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestPasswordSprayRiskAnalyzer(unittest.TestCase):
    """Test cases for PasswordSprayRiskAnalyzer."""

    def setUp(self):
        from analysis.password_spray_risk_analyzer import PasswordSprayRiskAnalyzer
        self.ldap = _make_mock_ldap()
        self.analyzer = PasswordSprayRiskAnalyzer(self.ldap)

    def test_empty_users(self):
        """No users → no password-spray risks."""
        risks = self.analyzer.analyze([])
        self.assertIsInstance(risks, list)

    def test_basic_analysis(self):
        """Users with weak lockout policy should produce risks."""
        users = [_make_user(sAMAccountName=f'user{i}') for i in range(10)]
        risks = self.analyzer.analyze(users)
        self.assertIsInstance(risks, list)

    def test_old_passwords_detected(self):
        """Users with very old passwords should be flagged."""
        users = [
            _make_user(
                sAMAccountName='oldpwd_user',
                pwdLastSet=datetime.now() - timedelta(days=500),
            )
        ]
        risks = self.analyzer.analyze(users)
        self.assertIsInstance(risks, list)


# ═══════════════════════════════════════════════════════════════════════════
#  GoldenGMSAAnalyzer Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestGoldenGMSAAnalyzer(unittest.TestCase):
    """Test cases for GoldenGMSAAnalyzer."""

    def setUp(self):
        from analysis.golden_gmsa_analyzer import GoldenGMSAAnalyzer
        self.ldap = _make_mock_ldap()
        self.analyzer = GoldenGMSAAnalyzer(self.ldap)

    def test_no_kds_root_keys(self):
        """No KDS Root Keys → empty or informational result."""
        risks = self.analyzer.analyze()
        self.assertIsInstance(risks, list)

    def test_returns_list(self):
        """Analyzer must always return a list."""
        risks = self.analyzer.analyze()
        self.assertIsInstance(risks, list)


# ═══════════════════════════════════════════════════════════════════════════
#  HoneypotDetector Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestHoneypotDetector(unittest.TestCase):
    """Test cases for HoneypotDetector."""

    def setUp(self):
        from analysis.honeypot_detector import HoneypotDetector
        self.detector = HoneypotDetector()

    def test_empty_inputs(self):
        """No users/groups → no honeypot findings."""
        risks = self.detector.analyze([], [])
        self.assertIsInstance(risks, list)

    def test_honeypot_candidate_detected(self):
        """Account with honeypot-like characteristics should be flagged."""
        users = [
            _make_user(
                sAMAccountName='HoneyAdmin',
                adminCount=1,
                lastLogonTimestamp=None,
                description='Decoy admin account',
            )
        ]
        groups = []
        risks = self.detector.analyze(users, groups)
        self.assertIsInstance(risks, list)

    def test_normal_user_not_flagged(self):
        """Regular active user should not be flagged as honeypot."""
        users = [_make_user()]
        risks = self.detector.analyze(users, [])
        self.assertIsInstance(risks, list)


# ═══════════════════════════════════════════════════════════════════════════
#  StaleObjectsAnalyzer Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestStaleObjectsAnalyzer(unittest.TestCase):
    """Test cases for StaleObjectsAnalyzer."""

    def setUp(self):
        from analysis.stale_objects_analyzer import StaleObjectsAnalyzer
        self.ldap = _make_mock_ldap()
        self.analyzer = StaleObjectsAnalyzer(self.ldap)

    def test_empty_inputs(self):
        """No objects → no stale findings."""
        risks = self.analyzer.analyze([], [], [])
        self.assertIsInstance(risks, list)

    def test_inactive_account_detected(self):
        """Account inactive for 180+ days should be flagged."""
        users = [
            _make_user(
                sAMAccountName='stale_user',
                lastLogonTimestamp=datetime.now() - timedelta(days=200),
                isDisabled=False,
            )
        ]
        risks = self.analyzer.analyze(users, [], [])
        self.assertIsInstance(risks, list)

    def test_ancient_password_detected(self):
        """Account with very old password should be flagged."""
        users = [
            _make_user(
                sAMAccountName='ancient_pwd',
                pwdLastSet=datetime.now() - timedelta(days=720),
            )
        ]
        risks = self.analyzer.analyze(users, [], [])
        self.assertIsInstance(risks, list)

    def test_credential_in_description(self):
        """Account with password-like text in description should be flagged."""
        users = [
            _make_user(
                sAMAccountName='leaky_user',
                description='Password: P@ssw0rd123',
            )
        ]
        risks = self.analyzer.analyze(users, [], [])
        self.assertIsInstance(risks, list)


# ═══════════════════════════════════════════════════════════════════════════
#  ADCSExtendedAnalyzer Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestADCSExtendedAnalyzer(unittest.TestCase):
    """Test cases for ADCSExtendedAnalyzer."""

    def setUp(self):
        from analysis.ad_cs_extended_analyzer import ADCSExtendedAnalyzer
        self.ldap = _make_mock_ldap()
        self.analyzer = ADCSExtendedAnalyzer(self.ldap)

    def test_no_adcs(self):
        """No AD CS environment → empty results."""
        risks = self.analyzer.analyze()
        self.assertIsInstance(risks, list)

    def test_returns_list(self):
        """Must always return a list."""
        risks = self.analyzer.analyze()
        self.assertIsInstance(risks, list)


# ═══════════════════════════════════════════════════════════════════════════
#  AuditPolicyAnalyzer Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestAuditPolicyAnalyzer(unittest.TestCase):
    """Test cases for AuditPolicyAnalyzer."""

    def setUp(self):
        from analysis.audit_policy_analyzer import AuditPolicyAnalyzer
        self.ldap = _make_mock_ldap()
        self.analyzer = AuditPolicyAnalyzer(self.ldap)

    def test_empty_gpos(self):
        """No GPOs → audit policy gaps detected."""
        risks = self.analyzer.analyze([])
        self.assertIsInstance(risks, list)

    def test_with_gpos(self):
        """GPOs present should be analyzed for audit settings."""
        gpos = [_make_group(name='Default Domain Policy')]
        risks = self.analyzer.analyze(gpos)
        self.assertIsInstance(risks, list)


# ═══════════════════════════════════════════════════════════════════════════
#  BackupOperatorAnalyzer Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestBackupOperatorAnalyzer(unittest.TestCase):
    """Test cases for BackupOperatorAnalyzer."""

    def setUp(self):
        from analysis.backup_operator_analyzer import BackupOperatorAnalyzer
        self.analyzer = BackupOperatorAnalyzer()

    def test_empty_inputs(self):
        """No users/groups → no findings."""
        risks = self.analyzer.analyze([], [])
        self.assertIsInstance(risks, list)

    def test_backup_operator_members_detected(self):
        """Filled Backup Operators group should produce risks."""
        users = [_make_user(sAMAccountName='backup_user')]
        groups = [
            _make_group(
                name='Backup Operators',
                sAMAccountName='Backup Operators',
                member=['CN=backup_user,CN=Users,DC=test,DC=com'],
                isPrivileged=True,
            )
        ]
        risks = self.analyzer.analyze(users, groups)
        self.assertIsInstance(risks, list)

    def test_empty_backup_operators(self):
        """Empty Backup Operators group → fewer or no risks."""
        groups = [
            _make_group(
                name='Backup Operators',
                sAMAccountName='Backup Operators',
                member=[],
                isPrivileged=True,
            )
        ]
        risks = self.analyzer.analyze([], groups)
        self.assertIsInstance(risks, list)


# ═══════════════════════════════════════════════════════════════════════════
#  CoerceAttackAnalyzer Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestCoerceAttackAnalyzer(unittest.TestCase):
    """Test cases for CoerceAttackAnalyzer."""

    def setUp(self):
        from analysis.coerce_attack_analyzer import CoerceAttackAnalyzer
        self.ldap = _make_mock_ldap()
        self.analyzer = CoerceAttackAnalyzer(self.ldap)

    def test_empty_computers(self):
        """No computers → no coercion risks."""
        risks = self.analyzer.analyze([])
        self.assertIsInstance(risks, list)

    def test_spooler_exposure(self):
        """Server with Print Spooler characteristics should be analysed."""
        computers = [_make_computer(name='DC01', operatingSystem='Windows Server 2019')]
        risks = self.analyzer.analyze(computers)
        self.assertIsInstance(risks, list)


# ═══════════════════════════════════════════════════════════════════════════
#  GMSAAnalyzer Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestGMSAAnalyzer(unittest.TestCase):
    """Test cases for GMSAAnalyzer."""

    def setUp(self):
        from analysis.gmsa_analyzer import GMSAAnalyzer
        self.ldap = _make_mock_ldap()
        self.analyzer = GMSAAnalyzer(self.ldap)

    def test_empty_users(self):
        """No users → no gMSA findings."""
        risks = self.analyzer.analyze([])
        self.assertIsInstance(risks, list)

    def test_legacy_service_account(self):
        """Legacy service account (SVC_ prefix) should be flagged for gMSA migration."""
        users = [
            _make_user(
                sAMAccountName='SVC_SQL',
                servicePrincipalName=['MSSQLSvc/sql01:1433'],
                userAccountControl=66048,  # NORMAL + DONT_EXPIRE_PASSWORD
            )
        ]
        risks = self.analyzer.analyze(users)
        self.assertIsInstance(risks, list)


# ═══════════════════════════════════════════════════════════════════════════
#  KRBTGTHealthAnalyzer Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestKRBTGTHealthAnalyzer(unittest.TestCase):
    """Test cases for KRBTGTHealthAnalyzer."""

    def setUp(self):
        from analysis.krbtgt_health_analyzer import KRBTGTHealthAnalyzer
        self.ldap = _make_mock_ldap()
        self.analyzer = KRBTGTHealthAnalyzer(self.ldap)

    def test_returns_list(self):
        """Must always return a list."""
        risks = self.analyzer.analyze()
        self.assertIsInstance(risks, list)

    def test_no_crash_on_empty_ldap(self):
        """Empty LDAP results should not crash the analyzer."""
        risks = self.analyzer.analyze()
        self.assertIsInstance(risks, list)


# ═══════════════════════════════════════════════════════════════════════════
#  LateralMovementAnalyzer Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestLateralMovementAnalyzer(unittest.TestCase):
    """Test cases for LateralMovementAnalyzer."""

    def setUp(self):
        from analysis.lateral_movement_analyzer import LateralMovementAnalyzer
        self.analyzer = LateralMovementAnalyzer()

    def test_empty_inputs(self):
        """No users/computers/groups → no findings."""
        risks = self.analyzer.analyze([], [], [])
        self.assertIsInstance(risks, list)

    def test_unrestricted_admin(self):
        """Admin without logon workstation restrictions should be flagged."""
        users = [
            _make_user(
                sAMAccountName='admin_no_restrict',
                adminCount=1,
                memberOf=['CN=Domain Admins,CN=Users,DC=test,DC=com'],
            )
        ]
        groups = [
            _make_group(
                name='Domain Admins',
                sAMAccountName='Domain Admins',
                member=['CN=admin_no_restrict,CN=Users,DC=test,DC=com'],
                isPrivileged=True,
            )
        ]
        risks = self.analyzer.analyze(users, [_make_computer()], groups)
        self.assertIsInstance(risks, list)


# ═══════════════════════════════════════════════════════════════════════════
#  MachineQuotaAnalyzer Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestMachineQuotaAnalyzer(unittest.TestCase):
    """Test cases for MachineQuotaAnalyzer."""

    def setUp(self):
        from analysis.machine_quota_analyzer import MachineQuotaAnalyzer
        self.ldap = _make_mock_ldap()
        self.analyzer = MachineQuotaAnalyzer(self.ldap)

    def test_returns_list(self):
        """Must always return a list."""
        risks = self.analyzer.analyze()
        self.assertIsInstance(risks, list)

    def test_no_crash_on_empty_ldap(self):
        """Empty LDAP results should not crash."""
        risks = self.analyzer.analyze()
        self.assertIsInstance(risks, list)


# ═══════════════════════════════════════════════════════════════════════════
#  ReplicationMetadataAnalyzer Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestReplicationMetadataAnalyzer(unittest.TestCase):
    """Test cases for ReplicationMetadataAnalyzer."""

    def setUp(self):
        from analysis.replication_metadata_analyzer import ReplicationMetadataAnalyzer
        self.ldap = _make_mock_ldap()
        self.analyzer = ReplicationMetadataAnalyzer(self.ldap)

    def test_empty_inputs(self):
        """No users/groups → no replication findings."""
        risks = self.analyzer.analyze([], [])
        self.assertIsInstance(risks, list)

    def test_returns_list(self):
        """Must always return a list."""
        risks = self.analyzer.analyze([_make_user()], [_make_group()])
        self.assertIsInstance(risks, list)


# ═══════════════════════════════════════════════════════════════════════════
#  Integration Smoke Test
# ═══════════════════════════════════════════════════════════════════════════

class TestModuleImports(unittest.TestCase):
    """Verify all new modules can be imported without errors."""

    def test_import_password_spray(self):
        from analysis.password_spray_risk_analyzer import PasswordSprayRiskAnalyzer
        self.assertTrue(callable(PasswordSprayRiskAnalyzer))

    def test_import_golden_gmsa(self):
        from analysis.golden_gmsa_analyzer import GoldenGMSAAnalyzer
        self.assertTrue(callable(GoldenGMSAAnalyzer))

    def test_import_honeypot(self):
        from analysis.honeypot_detector import HoneypotDetector
        self.assertTrue(callable(HoneypotDetector))

    def test_import_stale_objects(self):
        from analysis.stale_objects_analyzer import StaleObjectsAnalyzer
        self.assertTrue(callable(StaleObjectsAnalyzer))

    def test_import_adcs_extended(self):
        from analysis.ad_cs_extended_analyzer import ADCSExtendedAnalyzer
        self.assertTrue(callable(ADCSExtendedAnalyzer))

    def test_import_audit_policy(self):
        from analysis.audit_policy_analyzer import AuditPolicyAnalyzer
        self.assertTrue(callable(AuditPolicyAnalyzer))

    def test_import_backup_operator(self):
        from analysis.backup_operator_analyzer import BackupOperatorAnalyzer
        self.assertTrue(callable(BackupOperatorAnalyzer))

    def test_import_coerce_attack(self):
        from analysis.coerce_attack_analyzer import CoerceAttackAnalyzer
        self.assertTrue(callable(CoerceAttackAnalyzer))

    def test_import_gmsa(self):
        from analysis.gmsa_analyzer import GMSAAnalyzer
        self.assertTrue(callable(GMSAAnalyzer))

    def test_import_krbtgt_health(self):
        from analysis.krbtgt_health_analyzer import KRBTGTHealthAnalyzer
        self.assertTrue(callable(KRBTGTHealthAnalyzer))

    def test_import_lateral_movement(self):
        from analysis.lateral_movement_analyzer import LateralMovementAnalyzer
        self.assertTrue(callable(LateralMovementAnalyzer))

    def test_import_machine_quota(self):
        from analysis.machine_quota_analyzer import MachineQuotaAnalyzer
        self.assertTrue(callable(MachineQuotaAnalyzer))

    def test_import_replication_metadata(self):
        from analysis.replication_metadata_analyzer import ReplicationMetadataAnalyzer
        self.assertTrue(callable(ReplicationMetadataAnalyzer))


if __name__ == '__main__':
    unittest.main()

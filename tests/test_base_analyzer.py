"""
Tests for Base Analyzer
"""

import unittest
from core.base_analyzer import BaseAnalyzer
from core.constants import RiskTypes, Severity, MITRETechniques


class TestBaseAnalyzer(BaseAnalyzer):
    """Test analyzer implementation."""
    
    def analyze(self, data):
        """Test analyze method."""
        return []


class TestBaseAnalyzerClass(unittest.TestCase):
    """Test cases for BaseAnalyzer."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = TestBaseAnalyzer()
    
    def test_create_risk(self):
        """Test risk creation."""
        risk = self.analyzer._create_risk(
            risk_type=RiskTypes.PASSWORD_NOT_REQUIRED,
            title='Test Risk',
            description='Test description',
            affected_object='test_user',
            object_type='user',
            severity=Severity.CRITICAL,
            impact='Test impact',
            attack_scenario='Test scenario',
            mitigation='Test mitigation',
            cis_reference='CIS Test',
            mitre_attack=MITRETechniques.VALID_ACCOUNTS
        )
        
        self.assertEqual(risk['type'], RiskTypes.PASSWORD_NOT_REQUIRED)
        self.assertEqual(risk['severity'], Severity.CRITICAL)
        self.assertEqual(risk['title'], 'Test Risk')
        self.assertEqual(risk['affected_object'], 'test_user')
        self.assertEqual(risk['object_type'], 'user')
        self.assertIn('impact', risk)
        self.assertIn('attack_scenario', risk)
        self.assertIn('mitigation', risk)
    
    def test_check_uac_flag(self):
        """Test UAC flag checking."""
        uac = 0x400000  # DONT_REQUIRE_PREAUTH
        
        from core.constants import UACFlags
        result = self.analyzer._check_uac_flag(uac, UACFlags.DONT_REQUIRE_PREAUTH)
        self.assertTrue(result)
        
        result = self.analyzer._check_uac_flag(uac, UACFlags.DONT_EXPIRE_PASSWORD)
        self.assertFalse(result)
    
    def test_check_uac_flag_string(self):
        """Test UAC flag checking with string input."""
        uac = "4194304"  # DONT_REQUIRE_PREAUTH as string
        
        from core.constants import UACFlags
        result = self.analyzer._check_uac_flag(uac, UACFlags.DONT_REQUIRE_PREAUTH)
        self.assertTrue(result)
    
    def test_check_uac_flag_invalid(self):
        """Test UAC flag checking with invalid input."""
        uac = "invalid"
        
        from core.constants import UACFlags
        result = self.analyzer._check_uac_flag(uac, UACFlags.DONT_REQUIRE_PREAUTH)
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()

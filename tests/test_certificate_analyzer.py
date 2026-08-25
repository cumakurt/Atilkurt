"""Tests for ESC1/ESC2 attribute interpretation and forest config lookup."""

import unittest

from analysis.certificate_analyzer import CertificateAnalyzer


class FakeLDAP:
    def __init__(self, config_dn="CN=Configuration,DC=example,DC=com", templates=None):
        self.base_dn = "DC=child,DC=example,DC=com"
        self.config_dn = config_dn
        self.templates = templates or []
        self.searches = []

    def search(self, search_base="", search_filter="", attributes=None, size_limit=0):
        self.searches.append(search_base)
        if search_base == "":
            return [{"configurationNamingContext": self.config_dn}]
        return list(self.templates)


class TestCertificateAnalyzer(unittest.TestCase):
    def test_searches_forest_configuration_not_child_domain_dn(self):
        ldap = FakeLDAP()
        CertificateAnalyzer(ldap).analyze_certificate_services()
        self.assertTrue(
            any(
                base.startswith("CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com")
                for base in ldap.searches
            )
        )
        self.assertFalse(
            any("DC=child,DC=example,DC=com" in base and "Certificate Templates" in base for base in ldap.searches)
        )

    def test_missing_eku_attribute_is_not_esc2(self):
        analyzer = CertificateAnalyzer(FakeLDAP())
        risks = analyzer._analyze_template_vulnerabilities(
            {"name": "User", "msPKI-Certificate-Name-Flag": 0, "msPKI-Enrollment-Flag": 0},
            "User",
        )
        types = {risk["type"] for risk in risks}
        self.assertNotIn("certificate_esc2", types)

    def test_esc1_uses_name_flag_not_enrollment_flag(self):
        analyzer = CertificateAnalyzer(FakeLDAP())
        risks = analyzer._analyze_template_vulnerabilities(
            {
                "name": "ESC1",
                "msPKI-Certificate-Name-Flag": 0x1,
                "msPKI-Enrollment-Flag": 0,
                "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
            },
            "ESC1",
        )
        types = {risk["type"] for risk in risks}
        self.assertIn("certificate_esc1", types)

    def test_any_purpose_eku_is_esc2(self):
        analyzer = CertificateAnalyzer(FakeLDAP())
        risks = analyzer._analyze_template_vulnerabilities(
            {
                "name": "AnyPurpose",
                "msPKI-Certificate-Name-Flag": 0,
                "msPKI-Enrollment-Flag": 0,
                "pKIExtendedKeyUsage": ["2.5.29.37.0"],
            },
            "AnyPurpose",
        )
        types = {risk["type"] for risk in risks}
        self.assertIn("certificate_esc2", types)


if __name__ == "__main__":
    unittest.main()

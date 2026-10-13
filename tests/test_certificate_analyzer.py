"""Tests for ESC1/ESC2 attribute interpretation, enrollment ACLs, and forest config lookup."""

import struct
import unittest
from uuid import UUID

from analysis.certificate_analyzer import CertificateAnalyzer
from analysis.domain_admin_takeover_analyzer import DomainAdminTakeoverAnalyzer
from core.finding_evidence import requires_validation
from core.security_descriptor_parser import parse_security_descriptor
from scoring.risk_scorer import RiskScorer

ENROLL_GUID = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
AUTH_USERS = "S-1-5-11"
DOMAIN_ADMINS = "S-1-5-21-1-2-3-512"
HELPDESK = "S-1-5-21-1-2-3-1100"


def ace(mask, sid=AUTH_USERS, guid=None):
    parts = [int(part) for part in sid.split("-")[1:]]
    binary_sid = bytes([parts[0], len(parts) - 2]) + parts[1].to_bytes(6, "big")
    binary_sid += b"".join(part.to_bytes(4, "little") for part in parts[2:])
    kind = 5 if guid else 0
    payload = struct.pack("<I", mask)
    if guid:
        payload += struct.pack("<I", 1) + UUID(guid).bytes_le
    payload += binary_sid
    return struct.pack("<BBH", kind, 0, len(payload) + 4) + payload


def descriptor(*entries):
    body = b"".join(entries)
    acl = struct.pack("<BBHHH", 4, 0, 8 + len(body), len(entries), 0) + body
    return struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20) + acl


def esc1_template(**extra):
    template = {
        "name": "ESC1",
        "cn": "ESC1",
        "msPKI-Certificate-Name-Flag": 0x1,
        "msPKI-Enrollment-Flag": 0,
        "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
    }
    template.update(extra)
    return template


class FakeLDAP:
    def __init__(self, config_dn="CN=Configuration,DC=example,DC=com", templates=None, cas=None):
        self.base_dn = "DC=child,DC=example,DC=com"
        self.config_dn = config_dn
        self.templates = templates or []
        self.cas = cas if cas is not None else []
        self.searches = []

    def search(self, search_base="", search_filter="", attributes=None, size_limit=0):
        self.searches.append(search_base)
        if search_base == "":
            return [{"configurationNamingContext": self.config_dn}]
        if "Enrollment Services" in (search_base or ""):
            return list(self.cas)
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
        self.assertTrue(
            any(
                "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com" in base
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
        self.assertTrue(requires_validation(risks[0]))

    def test_esc1_is_reported_when_enrollment_flag_was_not_collected(self):
        analyzer = CertificateAnalyzer(FakeLDAP())
        risks = analyzer._analyze_template_vulnerabilities(
            {
                "name": "ESC1",
                "msPKI-Certificate-Name-Flag": 0x1,
                "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
            },
            "ESC1",
        )
        self.assertEqual([risk["type"] for risk in risks], ["certificate_esc1"])
        self.assertIn("msPKI-Enrollment-Flag", risks[0]["evidence"]["missing_prerequisites"])
        self.assertFalse(risks[0]["evidence"]["enrollment_flag_observed"])

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

    def test_enrollment_guid_is_certificate_enrollment(self):
        parsed = parse_security_descriptor(descriptor(ace(0x100, guid=ENROLL_GUID)))
        self.assertIn("Certificate-Enrollment", parsed["dacl"][0]["permissions"])

    def test_authenticated_users_enroll_on_published_esc1_is_confirmed(self):
        template = esc1_template(nTSecurityDescriptor=descriptor(ace(0x100, guid=ENROLL_GUID)))
        ca = {
            "cn": "CORP-CA",
            "certificateTemplates": ["ESC1"],
            "nTSecurityDescriptor": descriptor(ace(0x100, guid=ENROLL_GUID)),
        }
        risks = CertificateAnalyzer(FakeLDAP(templates=[template], cas=[ca])).analyze_certificate_services()
        esc1 = next(risk for risk in risks if risk["type"] == "certificate_esc1")
        self.assertTrue(esc1["evidence"]["vulnerability_confirmed"])
        self.assertFalse(requires_validation(esc1))
        self.assertEqual(esc1["evidence"]["published_cas"], ["CORP-CA"])
        self.assertEqual(esc1["evidence"]["enrollment_trustees"][0]["name"], "Authenticated Users")
        scored = RiskScorer().score_risks([esc1])
        self.assertGreater(scored[0]["final_score"], 0)
        takeover = DomainAdminTakeoverAnalyzer().analyze(risks)
        self.assertIn("adcs", [path["id"] for path in takeover["open_paths"]])
        self.assertEqual(takeover["pending_paths"], [])

    def test_esc1_without_enrollment_flag_is_not_confirmed(self):
        template = esc1_template(nTSecurityDescriptor=descriptor(ace(0x100, guid=ENROLL_GUID)))
        del template["msPKI-Enrollment-Flag"]
        ca = {
            "cn": "CORP-CA",
            "certificateTemplates": ["ESC1"],
            "nTSecurityDescriptor": descriptor(ace(0x100, guid=ENROLL_GUID)),
        }
        risks = CertificateAnalyzer(FakeLDAP(templates=[template], cas=[ca])).analyze_certificate_services()
        esc1 = next(risk for risk in risks if risk["type"] == "certificate_esc1")
        self.assertFalse(esc1["evidence"].get("vulnerability_confirmed"))
        self.assertTrue(requires_validation(esc1))
        self.assertIn("msPKI-Enrollment-Flag", esc1["evidence"]["missing_prerequisites"])

    def test_domain_admins_only_enroll_is_not_reported(self):
        template = esc1_template(nTSecurityDescriptor=descriptor(ace(0x100, sid=DOMAIN_ADMINS, guid=ENROLL_GUID)))
        ca = {
            "cn": "CORP-CA",
            "certificateTemplates": ["ESC1"],
            "nTSecurityDescriptor": descriptor(ace(0x100, guid=ENROLL_GUID)),
        }
        risks = CertificateAnalyzer(FakeLDAP(templates=[template], cas=[ca])).analyze_certificate_services()
        self.assertFalse(any(risk["type"] == "certificate_esc1" for risk in risks))

    def test_unpublished_esc1_template_is_not_reported(self):
        template = esc1_template(nTSecurityDescriptor=descriptor(ace(0x100, guid=ENROLL_GUID)))
        ca = {"cn": "CORP-CA", "certificateTemplates": ["User"]}
        risks = CertificateAnalyzer(FakeLDAP(templates=[template], cas=[ca])).analyze_certificate_services()
        self.assertEqual(risks, [])

    def test_esc1_without_template_acl_stays_pending(self):
        template = esc1_template()
        ca = {"cn": "CORP-CA", "certificateTemplates": ["ESC1"]}
        risks = CertificateAnalyzer(FakeLDAP(templates=[template], cas=[ca])).analyze_certificate_services()
        esc1 = next(risk for risk in risks if risk["type"] == "certificate_esc1")
        self.assertTrue(requires_validation(esc1))
        self.assertIn("template enrollment ACL", esc1["evidence"]["missing_prerequisites"])
        takeover = DomainAdminTakeoverAnalyzer().analyze(risks)
        self.assertEqual(takeover["open_paths"], [])
        self.assertEqual([path["id"] for path in takeover["pending_paths"]], ["adcs"])

    def test_helpdesk_enroll_on_published_esc1_is_confirmed(self):
        template = esc1_template(nTSecurityDescriptor=descriptor(ace(0x100, sid=HELPDESK, guid=ENROLL_GUID)))
        ca = {
            "cn": "CORP-CA",
            "certificateTemplates": ["ESC1"],
            "nTSecurityDescriptor": descriptor(ace(0x100, guid=ENROLL_GUID)),
        }
        groups = [{"sAMAccountName": "Helpdesk", "objectSid": HELPDESK}]
        risks = CertificateAnalyzer(
            FakeLDAP(templates=[template], cas=[ca]), groups=groups
        ).analyze_certificate_services()
        esc1 = next(risk for risk in risks if risk["type"] == "certificate_esc1")
        self.assertFalse(requires_validation(esc1))
        self.assertEqual(esc1["evidence"]["enrollment_trustees"][0]["name"], "Helpdesk")

    def test_ca_with_only_domain_admin_enroll_is_not_reported(self):
        template = esc1_template(nTSecurityDescriptor=descriptor(ace(0x100, guid=ENROLL_GUID)))
        ca = {
            "cn": "CORP-CA",
            "certificateTemplates": ["ESC1"],
            "nTSecurityDescriptor": descriptor(ace(0x100, sid=DOMAIN_ADMINS, guid=ENROLL_GUID)),
        }
        risks = CertificateAnalyzer(FakeLDAP(templates=[template], cas=[ca])).analyze_certificate_services()
        self.assertFalse(any(risk["type"] == "certificate_esc1" for risk in risks))


if __name__ == "__main__":
    unittest.main()

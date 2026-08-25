"""Tests for Package A modern identity-protection analyzers."""

from __future__ import annotations

import struct
from uuid import UUID

from analysis.adminsdholder_analyzer import AdminSDHolderAnalyzer
from analysis.authentication_policy_analyzer import AuthenticationPolicyAnalyzer
from analysis.certificate_mapping_analyzer import CertificateMappingAnalyzer
from analysis.kerberos_rc4_analyzer import KerberosRC4ReadinessAnalyzer
from analysis.key_credential_analyzer import KeyCredentialAnalyzer, KeyCredentialParser
from analysis.laps_v2_analyzer import WindowsLAPSV2Analyzer
from analysis.registry import CONSOLIDATION_RISK_KEYS, get_analysis_step_keys
from reporting.localization import localize_finding_list


class FakeLDAP:
    def __init__(self, responses=None, base_dn="DC=contoso,DC=com"):
        self.responses = responses or {}
        self.base_dn = base_dn

    def search(self, search_base=None, search_filter="(objectClass=*)", attributes=None, **kwargs):
        attrs = attributes or []
        if isinstance(attrs, str):
            attrs = [attrs]
        blob = f"{search_base or ''}|{search_filter}|{' '.join(attrs)}".casefold()
        matches = [(key, rows) for key, rows in self.responses.items() if key.casefold() in blob]
        if not matches:
            return []
        return list(max(matches, key=lambda pair: len(pair[0]))[1])


def _key_entry(identifier: int, value: bytes) -> bytes:
    return len(value).to_bytes(2, "little") + bytes([identifier]) + value


def _key_credential_blob(device_id: UUID) -> str:
    blob = (0x200).to_bytes(4, "little")
    blob += _key_entry(0x01, b"k" * 32)
    blob += _key_entry(0x03, b"public-key-material")
    blob += _key_entry(0x04, b"\x01")
    blob += _key_entry(0x05, b"\x00")
    blob += _key_entry(0x06, device_id.bytes_le)
    return f"B:{len(blob) * 2}:{blob.hex()}:CN=owner,DC=contoso,DC=com"


def _sid_bytes(authority: int, *subauthorities: int) -> bytes:
    return bytes([1, len(subauthorities)]) + authority.to_bytes(6, "big") + b"".join(
        part.to_bytes(4, "little") for part in subauthorities
    )


def _security_descriptor(sid: bytes, mask: int, *, protected: bool) -> bytes:
    ace = bytes([0, 0]) + struct.pack("<H", 8 + len(sid)) + struct.pack("<I", mask) + sid
    acl = bytes([2, 0]) + struct.pack("<H", 8 + len(ace)) + struct.pack("<H", 1) + b"\x00\x00" + ace
    control = 0x8004 | (0x1000 if protected else 0)
    return bytes([1, 0]) + struct.pack("<H", control) + struct.pack("<IIII", 0, 0, 0, 20) + acl


def test_package_a_registry_wiring():
    for key in (
        "authentication_policy", "key_credential_forensics", "windows_laps_v2",
        "certificate_mapping", "kerberos_rc4_readiness", "adminsdholder_drift",
    ):
        assert key in get_analysis_step_keys()
    for key in (
        "authentication_policy_risks", "key_credential_forensic_risks",
        "windows_laps_v2_risks", "certificate_mapping_risks",
        "kerberos_rc4_readiness_risks", "adminsdholder_drift_risks",
    ):
        assert key in CONSOLIDATION_RISK_KEYS


def test_authentication_policy_detects_audit_and_unprotected_privileged_account():
    policy_dn = "CN=Tier0 Policy,CN=AuthN Policy Configuration,CN=Services,CN=Configuration,DC=contoso,DC=com"
    ldap = FakeLDAP({
        "configurationNamingContext": [{"configurationNamingContext": "CN=Configuration,DC=contoso,DC=com"}],
        "objectClass=msDS-AuthNPolicySilo": [{
            "cn": "Tier0 Silo",
            "distinguishedName": "CN=Tier0 Silo,CN=AuthN Policy Configuration,CN=Services,CN=Configuration,DC=contoso,DC=com",
            "msDS-AuthNPolicySiloEnforced": "FALSE",
            "msDS-UserAuthNPolicy": policy_dn,
        }],
        "objectClass=msDS-AuthNPolicy)|": [{
            "cn": "Tier0 Policy",
            "distinguishedName": policy_dn,
            "msDS-AuthNPolicyEnforced": "FALSE",
            "msDS-UserTGTLifetime": "28800",
        }],
        "adminCount=1": [{"sAMAccountName": "DA1", "adminCount": "1", "memberOf": ["CN=Domain Admins,CN=Users,DC=contoso,DC=com"]}],
    })
    types = {risk["type"] for risk in AuthenticationPolicyAnalyzer(ldap).analyze([])}
    assert "auth_policy_audit_only" in types
    assert "auth_policy_excessive_tgt_lifetime" in types
    assert "auth_policy_privileged_unprotected" in types


def test_key_credential_parser_and_duplicate_device_detection():
    device_id = UUID("12345678-1234-5678-9abc-def012345678")
    value = _key_credential_blob(device_id)
    parsed = KeyCredentialParser.parse(value)
    assert parsed.valid is True
    assert parsed.device_id == str(device_id)
    ldap = FakeLDAP({
        "msDS-KeyCredentialLink=*": [
            {"sAMAccountName": "DA1", "adminCount": "1", "msDS-KeyCredentialLink": [value]},
            {"sAMAccountName": "PC1$", "msDS-KeyCredentialLink": [value]},
        ]
    })
    types = {risk["type"] for risk in KeyCredentialAnalyzer(ldap).analyze()}
    assert "key_credential_privileged" in types
    assert "key_credential_duplicate_device" in types


def test_windows_laps_v2_detects_encryption_history_and_dsrm_gaps():
    dc_dn = "CN=DC1,OU=Domain Controllers,DC=contoso,DC=com"
    pc_dn = "CN=PC1,CN=Computers,DC=contoso,DC=com"
    ldap = FakeLDAP({
        "msLAPS-PasswordExpirationTime": [
            {"distinguishedName": dc_dn}, {"distinguishedName": pc_dn},
        ],
        "msLAPS-EncryptedPassword=*)": [{"distinguishedName": pc_dn}],
        "msLAPS-EncryptedPasswordHistory=*)": [],
        "msLAPS-EncryptedDSRMPassword=*)": [],
        "nTSecurityDescriptor": [],
    })
    computers = [{
        "name": "DC1", "distinguishedName": dc_dn,
        "userAccountControl": 0x2000, "primaryGroupID": 516,
    }]
    types = {risk["type"] for risk in WindowsLAPSV2Analyzer(ldap).analyze(computers)}
    assert "windows_laps_encryption_gap" in types
    assert "windows_laps_history_disabled" in types
    assert "windows_laps_dsrm_not_backed_up" in types


def test_certificate_mapping_detects_weak_mapping_and_missing_sid_extension():
    ldap = FakeLDAP({
        "configurationNamingContext": [{"configurationNamingContext": "CN=Configuration,DC=contoso,DC=com"}],
        "altSecurityIdentities=*": [{
            "sAMAccountName": "DA1", "adminCount": "1",
            "altSecurityIdentities": ["X509:<I>CN=CA<S>CN=DA1"],
        }],
        "pKICertificateTemplate": [{
            "cn": "UserAuth", "msPKI-Enrollment-Flag": str(0x00080000),
            "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
        }],
    })
    risks = CertificateMappingAnalyzer(ldap).analyze()
    types = {risk["type"] for risk in risks}
    assert "certificate_weak_explicit_mapping" in types
    assert "certificate_sid_extension_disabled" in types
    assert next(r for r in risks if r["type"] == "certificate_weak_explicit_mapping")["severity"] == "critical"


def test_kerberos_rc4_readiness_distinguishes_aes_accounts():
    users = [
        {"sAMAccountName": "svc_rc4", "servicePrincipalName": ["HTTP/app"], "msDS-SupportedEncryptionTypes": 4},
        {"sAMAccountName": "svc_aes", "servicePrincipalName": ["HTTP/aes"], "msDS-SupportedEncryptionTypes": 24},
        {"sAMAccountName": "svc_unknown", "servicePrincipalName": ["HTTP/old"], "msDS-SupportedEncryptionTypes": None},
    ]
    types = [risk["type"] for risk in KerberosRC4ReadinessAnalyzer(FakeLDAP()).analyze(users, [])]
    assert types.count("kerberos_rc4_only") == 1
    assert "kerberos_aes_readiness_unknown" in types


def test_adminsdholder_detects_broad_ace_and_unprotected_orphan():
    everyone = _sid_bytes(1, 0)
    admin_sd = _security_descriptor(everyone, 0x40000000, protected=True)
    object_sd = _security_descriptor(everyone, 0x40000000, protected=False)
    ldap = FakeLDAP({
        "CN=AdminSDHolder": [{"distinguishedName": "CN=AdminSDHolder,CN=System,DC=contoso,DC=com", "nTSecurityDescriptor": admin_sd}],
        "adminCount=1": [{
            "sAMAccountName": "FormerAdmin", "distinguishedName": "CN=FormerAdmin,CN=Users,DC=contoso,DC=com",
            "adminCount": "1", "nTSecurityDescriptor": object_sd,
        }],
    })
    types = {risk["type"] for risk in AdminSDHolderAnalyzer(ldap).analyze([], [])}
    assert "adminsdholder_dangerous_ace" in types
    assert "adminsdholder_orphaned_admincount" in types
    assert "adminsdholder_inheritance_enabled" in types


def test_package_a_findings_are_localized_without_changing_identifiers():
    finding = {
        "type": "certificate_weak_explicit_mapping",
        "severity": "high",
        "title": "Weak explicit certificate mapping",
        "description": "English technical narrative",
        "affected_object": "DA1",
        "object_type": "user",
    }
    localized = localize_finding_list([finding], "tr")[0]
    assert localized["type"] == finding["type"]
    assert localized["affected_object"] == "DA1"
    assert localized["title"] == "Zayıf Açık Sertifika Eşlemesi"
    assert localized["description"] != finding["description"]

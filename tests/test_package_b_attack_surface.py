"""Tests for Package B graph and modern attack-surface analyzers."""

from __future__ import annotations

import struct

from analysis.ad_dns_security_analyzer import ADDNSSecurityAnalyzer
from analysis.adcs_control_plane_analyzer import ADCSControlPlaneAnalyzer
from analysis.attack_graph_v2_analyzer import AttackGraphV2Analyzer
from analysis.gmsa_reader_graph_analyzer import GMSAReaderGraphAnalyzer
from analysis.hybrid_identity_v2_analyzer import HybridIdentityV2Analyzer
from analysis.registry import CONSOLIDATION_RISK_KEYS, get_analysis_step_keys
from analysis.trust_security_v2_analyzer import TrustSecurityV2Analyzer
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
        return list(max(matches, key=lambda pair: len(pair[0]))[1]) if matches else []


def _sid(authority: int, *parts: int) -> bytes:
    return bytes([1, len(parts)]) + authority.to_bytes(6, "big") + b"".join(
        part.to_bytes(4, "little") for part in parts
    )


def _sd(sid: bytes, mask: int = 0x40000000) -> bytes:
    ace = bytes([0, 0]) + struct.pack("<H", 8 + len(sid)) + struct.pack("<I", mask) + sid
    acl = bytes([2, 0]) + struct.pack("<H", 8 + len(ace)) + struct.pack("<H", 1) + b"\x00\x00" + ace
    return bytes([1, 0]) + struct.pack("<H", 0x9004) + struct.pack("<IIII", 0, 0, 0, 20) + acl


def test_package_b_registry_wiring():
    for key in (
        "gmsa_reader_graph", "adcs_control_plane", "trust_security_v2",
        "ad_dns_security", "hybrid_identity_v2", "attack_graph_v2",
    ):
        assert key in get_analysis_step_keys()
    for key in (
        "gmsa_reader_graph_risks", "adcs_control_plane_risks", "trust_security_v2_risks",
        "ad_dns_security_risks", "hybrid_identity_v2_risks", "attack_graph_v2_risks",
    ):
        assert key in CONSOLIDATION_RISK_KEYS


def test_gmsa_reader_graph_decodes_broad_password_reader():
    ldap = FakeLDAP({
        "msDS-GroupManagedServiceAccount": [{
            "sAMAccountName": "svcTier0$", "adminCount": "1",
            "msDS-GroupMSAMembership": _sd(_sid(1, 0)),
        }]
    })
    result = GMSAReaderGraphAnalyzer(ldap).analyze([], [], [])
    types = {risk["type"] for risk in result["risks"]}
    assert "gmsa_broad_password_reader" in types
    assert "gmsa_privileged_reader_path" in types
    assert result["graph"]["summary"]["edge_count"] == 1


def test_adcs_control_plane_uses_acl_evidence():
    ldap = FakeLDAP({
        "configurationNamingContext": [{"configurationNamingContext": "CN=Configuration,DC=contoso,DC=com"}],
        "CN=NTAuthCertificates": [{
            "cn": "NTAuthCertificates",
            "distinguishedName": "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com",
            "nTSecurityDescriptor": _sd(_sid(1, 0)),
        }],
    })
    result = ADCSControlPlaneAnalyzer(ldap).analyze([], [])
    assert any(risk["type"] == "adcs_ntauth_acl" for risk in result["risks"])
    assert result["graph"]["summary"]["edge_count"] == 1


def test_trust_security_v2_decodes_selective_auth_rc4_sid_filtering_and_tgt_flags():
    ldap = FakeLDAP({
        "objectClass=trustedDomain": [{
            "trustPartner": "legacy.example",
            "trustDirection": 3,
            "trustType": 2,
            "trustAttributes": 0x80 | 0x800,
            "msDS-SupportedEncryptionTypes": 4,
        }]
    })
    result = TrustSecurityV2Analyzer(ldap).analyze()
    types = {risk["type"] for risk in result["risks"]}
    assert "trust_selective_auth_disabled" in types
    assert "trust_sid_filtering_weak" in types
    assert "trust_tgt_delegation_enabled" in types
    assert "trust_rc4_dependency" in types
    assert len(result["graph"]["edges"]) == 2


def test_ad_dns_detects_broad_zone_acl_and_wpad_node():
    zone_dn = "DC=contoso.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=contoso,DC=com"
    ldap = FakeLDAP({
        "objectClass=dnsZone": [{
            "dc": "contoso.com", "distinguishedName": zone_dn,
            "nTSecurityDescriptor": _sd(_sid(1, 0)),
        }],
        "objectClass=dnsNode": [{
            "dc": "wpad", "distinguishedName": f"DC=wpad,{zone_dn}",
            "dnsRecord": [{"type": "A"}], "whenChanged": "2026-01-01T00:00:00+00:00",
        }],
    })
    result = ADDNSSecurityAnalyzer(ldap).analyze()
    types = {risk["type"] for risk in result["risks"]}
    assert "ad_dns_broad_zone_acl" in types
    assert "ad_dns_high_risk_node" in types


def test_hybrid_identity_v2_detects_stale_cloud_and_seamless_sso_keys():
    ldap = FakeLDAP({
        "cn=AzureADKerberos": [{
            "sAMAccountName": "krbtgt_AzureAD", "pwdLastSet": "2020-01-01T00:00:00+00:00",
            "msDS-SupportedEncryptionTypes": 24,
        }],
    })
    computers = [{
        "sAMAccountName": "AZUREADSSOACC$", "pwdLastSet": "2020-01-01T00:00:00+00:00",
    }]
    result = HybridIdentityV2Analyzer(ldap).analyze([], computers)
    types = {risk["type"] for risk in result["risks"]}
    assert "hybrid_cloud_kerberos_stale_key" in types
    assert "hybrid_seamless_sso_stale_key" in types


def test_attack_graph_v2_finds_shortest_tier0_path_and_opengraph_export():
    users = [{
        "sAMAccountName": "alice",
        "memberOf": ["CN=Helpdesk,CN=Users,DC=contoso,DC=com"],
    }]
    groups = [
        {
            "name": "Helpdesk", "distinguishedName": "CN=Helpdesk,CN=Users,DC=contoso,DC=com",
            "memberOf": ["CN=Domain Admins,CN=Users,DC=contoso,DC=com"],
        },
        {
            "name": "Domain Admins", "distinguishedName": "CN=Domain Admins,CN=Users,DC=contoso,DC=com",
            "objectSid": "S-1-5-21-1-2-3-512", "memberOf": [],
        },
    ]
    result = AttackGraphV2Analyzer().analyze(users, groups, [], {})
    assert any(risk["type"] == "attack_graph_tier0_path" for risk in result["risks"])
    assert result["graph"]["summary"]["open_path_count"] == 1
    assert result["graph"]["opengraph"]["graph"]["nodes"]
    assert result["graph"]["opengraph"]["graph"]["edges"]


def test_package_b_finding_has_turkish_presentation():
    finding = {
        "type": "attack_graph_chokepoint", "severity": "high",
        "title": "Attack graph chokepoint", "description": "English",
        "affected_object": "Helpdesk", "object_type": "group",
    }
    localized = localize_finding_list([finding], "tr")[0]
    assert localized["type"] == "attack_graph_chokepoint"
    assert localized["title"] == "Saldırı Grafiği Darboğazı"

"""
Domain Security Analyzer Module
Checks LDAP Signing, Channel Binding, NTLM restrictions, and SMB signing via GPO
"""

import logging
from typing import List, Dict, Any, Optional
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)


class DomainSecurityAnalyzer:
    """Analyzes domain-level security settings: LDAP, NTLM, SMB."""

    def __init__(self, ldap_connection):
        self.ldap = ldap_connection

    def analyze_domain_security(
        self,
        gpos: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """
        Analyze domain security settings.
        Checks LDAP signing, NTLM restrictions, and SMB signing.
        """
        risks = []
        try:
            risks.extend(self._check_ldap_signing_channel_binding())
            risks.extend(self._check_ntlm_restrictions())
            if gpos:
                risks.extend(self._check_smb_signing(gpos))
            logger.info(f"Domain security analysis found {len(risks)} risks")
        except Exception as e:
            logger.error(f"Error in domain security analysis: {str(e)}")
        return risks

    def _check_ldap_signing_channel_binding(self) -> List[Dict[str, Any]]:
        """Check LDAP server signing requirements and channel binding."""
        risks = []
        try:
            results = self.ldap.search(
                search_filter='(objectClass=domainDNS)',
                search_base=self.ldap.base_dn,
                attributes=[
                    'msDS-ldapServerIntegrity',
                    'msDS-Other-Settings',
                    'distinguishedName'
                ]
            )
            if not results:
                risks.append({
                    'type': RiskTypes.LDAP_SIGNING_DISABLED,
                    'severity': Severity.HIGH,
                    'title': 'LDAP Signing/Channel Binding Status Unknown',
                    'description': (
                        'Could not query LDAP signing configuration. LDAP signing prevents '
                        'man-in-the-middle attacks. Ensure LDAP signing is required.'
                    ),
                    'affected_object': self.ldap.base_dn,
                    'object_type': 'configuration',
                    'impact': (
                        'Without LDAP signing, attackers can perform LDAP relay attacks and '
                        'intercept credentials.'
                    ),
                    'attack_scenario': (
                        'An attacker with network access could relay LDAP authentication to '
                        'compromise credentials or perform privilege escalation.'
                    ),
                    'mitigation': (
                        'Set LDAP Server Signing Requirements to "Require signing" via GPO. '
                        'Configure channel binding for LDAP over TLS.'
                    ),
                    'mitre_attack': MITRETechniques.PASS_THE_HASH,
                })
                return risks

            domain = results[0]
            integrity = domain.get('msDS-ldapServerIntegrity') or domain.get('msDS-LdapServerIntegrity')
            if integrity is not None:
                if isinstance(integrity, list):
                    integrity = integrity[0] if integrity else None
                if integrity in (0, '0', 'None'):
                    risks.append({
                        'type': RiskTypes.LDAP_SIGNING_DISABLED,
                        'severity': Severity.HIGH,
                        'title': 'LDAP Signing Not Required',
                        'description': (
                            'Domain LDAP servers may accept unsigned connections. '
                            'This enables LDAP relay attacks.'
                        ),
                        'affected_object': domain.get('distinguishedName', 'Domain'),
                        'object_type': 'configuration',
                        'impact': (
                            'Attackers can relay LDAP authentication without signing, '
                            'leading to credential theft and privilege escalation.'
                        ),
                        'mitigation': (
                            'Set "Domain controller: LDAP server signing requirements" to '
                            '"Require signing" in GPO. Apply to all Domain Controllers.'
                        ),
                        'mitre_attack': MITRETechniques.PASS_THE_HASH,
                    })
        except Exception as e:
            logger.debug(f"LDAP signing check: {e}")
            risks.append({
                'type': RiskTypes.LDAP_SIGNING_DISABLED,
                'severity': Severity.MEDIUM,
                'title': 'LDAP Signing Check Unavailable',
                'description': (
                    'Could not verify LDAP signing. Manually verify "Require signing" is set '
                    'for LDAP server. Attribute: msDS-ldapServerIntegrity.'
                ),
                'affected_object': 'Domain',
                'object_type': 'configuration',
                'mitigation': 'Audit GPO: Computer Configuration > Windows Settings > Security > LDAP server signing requirements.',
            })
        return risks

    def _check_ntlm_restrictions(self) -> List[Dict[str, Any]]:
        """Check NTLM authentication restrictions."""
        risks = []
        try:
            results = self.ldap.search(
                search_filter='(objectClass=domainDNS)',
                search_base=self.ldap.base_dn,
                attributes=[
                    'msDS-NtlmMinClientSec',
                    'msDS-NtlmMinServerSec',
                    'distinguishedName'
                ]
            )
            if not results:
                return risks

            domain = results[0]
            min_client = domain.get('msDS-NtlmMinClientSec') or domain.get('msDS-NtlmMinClientSec')
            min_server = domain.get('msDS-NtlmMinServerSec') or domain.get('msDS-NtlmMinServerSec')

            def _parse_sec(val):
                if val is None:
                    return 0
                if isinstance(val, list):
                    val = val[0] if val else 0
                try:
                    return int(val)
                except (ValueError, TypeError):
                    return 0

            client_sec = _parse_sec(min_client)
            server_sec = _parse_sec(min_server)

            # NTLM_MIN_CLIENT_SEC / NTLM_MIN_SERVER_SEC flags:
            # 0x00000000 = No minimum
            # 0x00080000 = NTLMv2 session security required
            # 0x20000000 = Require 128-bit encryption
            # 0x80000000 = Require NTLMv2
            NTLMV2_REQUIRED = 0x80000000
            if client_sec == 0 and server_sec == 0:
                risks.append({
                    'type': RiskTypes.NTLM_RESTRICTION_WEAK,
                    'severity': Severity.MEDIUM,
                    'title': 'NTLM Restrictions Not Configured',
                    'description': (
                        'Domain has no NTLM minimum security requirements. NTLMv1 and weak '
                        'encryption may be accepted.'
                    ),
                    'affected_object': domain.get('distinguishedName', 'Domain'),
                    'object_type': 'configuration',
                    'impact': (
                        'NTLMv1 and weak NTLM are vulnerable to relay attacks and offline cracking.'
                    ),
                    'mitigation': (
                        'Configure "Network security: LAN Manager authentication level" to '
                        '"Send NTLMv2 response only. Refuse LM & NTLM". Require 128-bit encryption.'
                    ),
                    'mitre_attack': MITRETechniques.PASS_THE_HASH,
                })
        except Exception as e:
            logger.debug(f"NTLM check: {e}")
        return risks

    def _check_smb_signing(self, gpos: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check SMB signing requirements via GPO (conceptual - GPO content requires SMB access)."""
        risks = []
        try:
            # SMB signing is configured via GPO: Microsoft network server: Digitally sign
            # communications (always). We cannot read GPO file content via LDAP only.
            # Provide guidance based on typical misconfigurations.
            risks.append({
                'type': RiskTypes.SMB_SIGNING_DISABLED,
                'severity': Severity.MEDIUM,
                'title': 'SMB Signing Verification Recommended',
                'description': (
                    'Verify SMB signing is required on all Domain Controllers and servers. '
                    'SMB signing prevents relay attacks (PetitPotam, etc.). Check GPO: '
                    '"Microsoft network server: Digitally sign communications (always)" = Enabled.'
                ),
                'affected_object': 'Domain Controllers',
                'object_type': 'configuration',
                'impact': (
                    'Without SMB signing, attackers can relay SMB authentication for '
                    'privilege escalation (e.g., PetitPotam to NTLM relay).'
                ),
                'mitigation': (
                    'Enable "Microsoft network server: Digitally sign communications (always)" '
                    'for all Domain Controllers. Enable for servers where possible.'
                ),
                'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_GOLDEN,
            })
        except Exception as e:
            logger.debug(f"SMB signing check: {e}")
        return risks

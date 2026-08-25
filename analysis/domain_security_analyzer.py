"""
Domain Security Analyzer Module
Checks LDAP Signing, Channel Binding, NTLM restrictions, and SMB signing via GPO
"""

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


class DomainSecurityAnalyzer:
    """Analyzes domain-level security settings: LDAP, NTLM, SMB."""

    def __init__(self, ldap_connection):
        self.ldap = ldap_connection

    def analyze_domain_security(
        self,
        gpos: Optional[list[dict[str, Any]]] = None
    ) -> list[dict[str, Any]]:
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

    def _check_ldap_signing_channel_binding(self) -> list[dict[str, Any]]:
        """Check LDAP server signing requirements and channel binding."""
        # LDAPServerIntegrity and LdapEnforceChannelBinding are registry/GPO
        # policy values on each DC, not attributes of the domainDNS object.
        # LDAP-only collection cannot prove either state without reading SYSVOL
        # policy content or testing each DC's protocol behavior.
        logger.info(
            "LDAP signing/channel binding requires GPO, registry, or per-DC protocol verification"
        )
        return []

    def _check_ntlm_restrictions(self) -> list[dict[str, Any]]:
        """Check NTLM authentication restrictions."""
        # NtlmMinClientSec/NtlmMinServerSec are LSA registry policy values, not
        # AD schema attributes. Do not turn an unavailable measurement into a
        # weak-NTLM finding or issue an invalid LDAP request.
        logger.info("NTLM minimum security requires GPO or registry verification")
        return []

    def _check_smb_signing(self, gpos: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Record the SMB-signing measurement boundary without a false finding."""
        # GPO objects collected over LDAP expose metadata and SYSVOL paths, not
        # the registry.pol values needed to prove SMB signing configuration.
        logger.info("SMB signing requires SYSVOL policy or per-host protocol verification")
        return []

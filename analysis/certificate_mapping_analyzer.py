"""Strong certificate-binding and explicit certificate-mapping assessment."""

from __future__ import annotations

import logging
import re
from typing import Any

from core.ad_identity import account_has_privileged_evidence, forest_configuration_dn
from core.ad_security import as_int, as_list, as_text
from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)


class CertificateMappingAnalyzer:
    """Classify explicit mappings and SID security-extension template posture."""

    NO_SECURITY_EXTENSION = 0x00080000
    AUTHENTICATION_EKUS = frozenset({
        "1.3.6.1.5.5.7.3.2",       # Client Authentication
        "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
        "1.3.6.1.5.2.3.4",         # PKINIT Client Authentication
        "2.5.29.37.0",              # Any Purpose
    })

    def __init__(self, ldap_connection: Any):
        self.ldap = ldap_connection

    def analyze(self) -> list[dict[str, Any]]:
        risks = self._analyze_explicit_mappings()
        risks.extend(self._analyze_template_sid_extension())
        return risks

    def _analyze_explicit_mappings(self) -> list[dict[str, Any]]:
        try:
            rows = self.ldap.search(
                search_base=self.ldap.base_dn,
                search_filter="(altSecurityIdentities=*)",
                attributes=["sAMAccountName", "distinguishedName", "adminCount", "memberOf", "altSecurityIdentities"],
            ) or []
        except Exception as exc:
            logger.debug("Explicit certificate mapping search failed: %s", exc)
            return []

        risks: list[dict[str, Any]] = []
        for row in rows:
            name = as_text(row.get("sAMAccountName") or row.get("distinguishedName")) or "unknown account"
            privileged = account_has_privileged_evidence(row)
            weak_types = [
                mapping_type for value in as_list(row.get("altSecurityIdentities"))
                if (mapping_type := self.classify_mapping(value)).startswith("weak:")
            ]
            if not weak_types:
                continue
            risks.append({
                "type": RiskTypes.CERTIFICATE_WEAK_EXPLICIT_MAPPING,
                "severity": Severity.CRITICAL if privileged else Severity.HIGH,
                "title": f'Weak explicit certificate mapping on "{name}"',
                "description": (
                    "The account uses username-, email-, or subject-based certificate mappings that Microsoft "
                    "classifies as weak because their identifiers can be reused."
                ),
                "affected_object": name,
                "object_type": "user",
                "impact": "A certificate that satisfies a reusable weak mapping can authenticate as the mapped account.",
                "attack_scenario": "An attacker obtains a certificate with matching subject or email data and authenticates as the victim.",
                "mitigation": "Replace weak mappings with issuer/serial, SKI, SHA1 public-key, or SID-extension based strong mappings.",
                "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
                "evidence": {"weak_mapping_types": sorted(set(weak_types)), "privileged": privileged},
            })
        return risks

    def _analyze_template_sid_extension(self) -> list[dict[str, Any]]:
        config_dn = forest_configuration_dn(self.ldap)
        if not config_dn:
            return []
        base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}"
        try:
            rows = self.ldap.search(
                search_base=base,
                search_filter="(objectClass=pKICertificateTemplate)",
                attributes=[
                    "cn", "displayName", "msPKI-Enrollment-Flag",
                    "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy",
                ],
            ) or []
        except Exception as exc:
            logger.debug("Certificate SID-extension template search failed: %s", exc)
            return []

        risks: list[dict[str, Any]] = []
        for template in rows:
            flags = as_int(template.get("msPKI-Enrollment-Flag")) or 0
            eku_values = {
                str(value).strip() for attribute in (
                    "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy",
                ) for value in as_list(template.get(attribute))
            }
            if not flags & self.NO_SECURITY_EXTENSION or not eku_values.intersection(self.AUTHENTICATION_EKUS):
                continue
            name = as_text(template.get("displayName") or template.get("cn")) or "certificate template"
            risks.append({
                "type": RiskTypes.CERTIFICATE_SID_EXTENSION_DISABLED,
                "severity": Severity.HIGH,
                "title": f'Authentication template "{name}" suppresses the SID security extension',
                "description": (
                    "The CT_FLAG_NO_SECURITY_EXTENSION enrollment flag is set on an authentication-capable "
                    "template, so issued certificates omit the szOID_NTDS_CA_SECURITY_EXT SID binding."
                ),
                "affected_object": name,
                "object_type": "configuration",
                "impact": "Certificates without the SID extension require another strong mapping or can create authentication failures and weaker binding paths.",
                "attack_scenario": "A misissued certificate is mapped through a weaker identity field instead of a unique account SID.",
                "mitigation": "Clear CT_FLAG_NO_SECURITY_EXTENSION unless a documented strong explicit mapping is required and monitored.",
                "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
                "evidence": {"enrollment_flags": flags, "authentication_ekus": sorted(eku_values.intersection(self.AUTHENTICATION_EKUS))},
            })
        return risks

    @staticmethod
    def classify_mapping(value: Any) -> str:
        """Return the KB5014754 mapping strength and mapping family."""
        text = str(value or "").strip().upper()
        if not text.startswith("X509:"):
            return "unknown"
        if "<SHA1-PUKEY>" in text:
            return "strong:sha1_public_key"
        if "<SKI>" in text:
            return "strong:ski"
        if "<SR>" in text and "<I>" in text:
            return "strong:issuer_serial"
        if "<RFC822>" in text:
            return "weak:rfc822"
        if "<S>" in text and "<I>" in text:
            return "weak:issuer_subject"
        if re.search(r"X509:\s*<S>", text):
            return "weak:subject_only"
        return "unknown"

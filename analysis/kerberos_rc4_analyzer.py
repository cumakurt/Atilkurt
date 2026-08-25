"""Kerberos AES readiness and explicit RC4 dependency assessment."""

from __future__ import annotations

import logging
from typing import Any

from core.ad_identity import account_has_privileged_evidence
from core.ad_security import as_int, as_list, as_text
from core.constants import MITRETechniques, RiskTypes, Severity, UACFlags

logger = logging.getLogger(__name__)


class KerberosRC4ReadinessAnalyzer:
    """Find static directory evidence of workloads that are not AES-ready."""

    DES_MASK = 0x03
    RC4_MASK = 0x04
    AES_MASK = 0x18

    def __init__(self, ldap_connection: Any):
        self.ldap = ldap_connection

    def analyze(
        self,
        users: list[dict[str, Any]],
        computers: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        risks: list[dict[str, Any]] = []
        unknown_service_accounts: list[str] = []

        for object_type, objects in (("user", users), ("computer", computers)):
            for account in objects:
                uac = as_int(account.get("userAccountControl")) or 0
                if uac & UACFlags.ACCOUNTDISABLE:
                    continue
                spns = as_list(account.get("servicePrincipalName"))
                privileged = account_has_privileged_evidence(account)
                name = as_text(
                    account.get("sAMAccountName") or account.get("name")
                    or account.get("distinguishedName")
                ) or "unknown account"
                encryption = as_int(account.get("msDS-SupportedEncryptionTypes"))
                relevant = bool(spns) or privileged or name.casefold().rstrip("$") == "krbtgt"
                if not relevant:
                    continue
                if encryption is None:
                    if spns and object_type == "user":
                        unknown_service_accounts.append(name)
                    continue
                if encryption & self.AES_MASK:
                    continue
                if encryption & (self.RC4_MASK | self.DES_MASK) or encryption == 0:
                    risks.append({
                        "type": RiskTypes.KERBEROS_RC4_ONLY,
                        "severity": Severity.CRITICAL if privileged else Severity.HIGH,
                        "title": f'Kerberos account "{name}" is not AES-ready',
                        "description": (
                            f"msDS-SupportedEncryptionTypes={encryption:#x} contains no AES128/AES256 support "
                            "for an enabled service or high-value account."
                        ),
                        "affected_object": name,
                        "object_type": object_type,
                        "impact": "RC4/DES dependencies increase Kerberoasting exposure and can fail after modern KDC hardening.",
                        "attack_scenario": "An attacker requests a weaker service ticket and performs offline password cracking.",
                        "mitigation": "Reset legacy account keys where required, enable AES128/AES256, test dependencies, and monitor events 4768/4769 before disabling RC4.",
                        "mitre_attack": MITRETechniques.STEAL_FORGE_KERBEROS_KERBEROASTING,
                        "evidence": {
                            "supported_encryption_types": encryption,
                            "has_rc4": bool(encryption & self.RC4_MASK),
                            "has_des": bool(encryption & self.DES_MASK),
                            "has_aes": False,
                            "privileged": privileged,
                            "spn_count": len(spns),
                        },
                    })

        risks.extend(self._analyze_trusts())
        if unknown_service_accounts:
            risks.append({
                "type": RiskTypes.KERBEROS_AES_READINESS_UNKNOWN,
                "severity": Severity.MEDIUM,
                "title": f"AES readiness is unverified for {len(unknown_service_accounts)} service accounts",
                "description": (
                    "SPN-bearing user accounts have no explicit msDS-SupportedEncryptionTypes value. "
                    "Directory data alone cannot prove the processed KDC encryption choice."
                ),
                "affected_object": self._sample(unknown_service_accounts),
                "object_type": "user",
                "impact": "Hidden RC4 dependencies can preserve Kerberoasting exposure or cause outages when RC4 is disabled.",
                "attack_scenario": "A legacy service silently continues receiving RC4 tickets until KDC defaults are hardened.",
                "mitigation": "Correlate KDC events 4768/4769, reset old service-account passwords to generate AES keys, and stage AES enforcement.",
                "mitre_attack": MITRETechniques.STEAL_FORGE_KERBEROS_KERBEROASTING,
                "evidence": {"account_count": len(unknown_service_accounts), "requires_runtime_validation": True},
            })
        return risks

    def _analyze_trusts(self) -> list[dict[str, Any]]:
        try:
            rows = self.ldap.search(
                search_base=self.ldap.base_dn,
                search_filter="(objectClass=trustedDomain)",
                attributes=["cn", "flatName", "trustPartner", "msDS-SupportedEncryptionTypes"],
            ) or []
        except Exception as exc:
            logger.debug("Kerberos trust encryption search failed: %s", exc)
            return []
        risks: list[dict[str, Any]] = []
        for trust in rows:
            encryption = as_int(trust.get("msDS-SupportedEncryptionTypes"))
            if encryption is None or encryption & self.AES_MASK:
                continue
            name = as_text(trust.get("trustPartner") or trust.get("flatName") or trust.get("cn")) or "trusted domain"
            risks.append({
                "type": RiskTypes.KERBEROS_RC4_ONLY,
                "severity": Severity.HIGH,
                "title": f'Trust "{name}" is not configured for AES',
                "description": f"The trustedDomain object advertises encryption types {encryption:#x} without AES128/AES256.",
                "affected_object": name,
                "object_type": "trust",
                "impact": "Cross-domain Kerberos authentication can depend on RC4 and fail during enforcement.",
                "attack_scenario": "A weaker inter-domain trust key becomes a credential-cracking or ticket-forging target.",
                "mitigation": "Enable AES on both sides of the trust, rotate trust secrets, and validate cross-domain workloads.",
                "mitre_attack": MITRETechniques.STEAL_FORGE_KERBEROS_GOLDEN,
                "evidence": {"supported_encryption_types": encryption, "has_aes": False},
            })
        return risks

    @staticmethod
    def _sample(values: list[str]) -> str:
        unique = sorted(set(values), key=str.casefold)
        return ", ".join(unique[:15]) + (f" ... (+{len(unique) - 15} more)" if len(unique) > 15 else "")

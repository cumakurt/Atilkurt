"""Assess account-level Kerberos encryption and delegation protections."""

import logging
from typing import Any, Optional

from core.constants import MITRETechniques, RiskTypes, Severity, UACFlags

logger = logging.getLogger(__name__)

ENC_DES_CBC_CRC = 0x01
ENC_DES_CBC_MD5 = 0x02
ENC_RC4_HMAC = 0x04
ENC_AES128 = 0x08
ENC_AES256 = 0x10

PRIVILEGED_GROUP_NAMES = {
    "ADMINISTRATORS",
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "SCHEMA ADMINS",
}


class KerberosAccountSecurityAnalyzer:
    """Detect explicit legacy encryption and delegatable privileged users."""

    def analyze(
        self,
        users: list[dict[str, Any]],
        computers: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Return account-level Kerberos security findings."""
        risks: list[dict[str, Any]] = []

        for user in users or []:
            if self._is_enabled(user) and self._account_name(user, "user").lower() != "krbtgt":
                encryption_risk = self._assess_encryption(user, "user")
                if encryption_risk:
                    risks.append(encryption_risk)

                delegation_risk = self._assess_privileged_delegation(user)
                if delegation_risk:
                    risks.append(delegation_risk)

        for computer in computers or []:
            if self._is_enabled(computer):
                encryption_risk = self._assess_encryption(computer, "computer")
                if encryption_risk:
                    risks.append(encryption_risk)

        logger.info("Found %d account-level Kerberos security risks", len(risks))
        return risks

    def _assess_encryption(
        self,
        account: dict[str, Any],
        object_type: str,
    ) -> Optional[dict[str, Any]]:
        """Return a finding when an account explicitly enables legacy encryption."""
        account_name = self._account_name(account, object_type)
        uac = self._as_int(account.get("userAccountControl")) or 0
        encryption_types = self._as_int(account.get("msDS-SupportedEncryptionTypes"))
        issues: list[str] = []

        des_only = bool(uac & UACFlags.USE_DES_KEY_ONLY)
        if des_only:
            issues.append("The USE_DES_KEY_ONLY account-control flag forces DES Kerberos keys.")

        # A missing or zero value is governed by domain/KDC defaults. It is not
        # sufficient evidence that the account is RC4-only.
        if encryption_types:
            has_des = bool(encryption_types & (ENC_DES_CBC_CRC | ENC_DES_CBC_MD5))
            has_rc4 = bool(encryption_types & ENC_RC4_HMAC)
            has_aes = bool(encryption_types & (ENC_AES128 | ENC_AES256))

            if has_des and not des_only:
                issues.append("The account explicitly advertises deprecated DES encryption support.")
            if has_rc4 and not has_aes:
                issues.append("The account explicitly supports RC4 but does not advertise AES support.")

        if not issues:
            return None

        severity = Severity.CRITICAL if des_only else Severity.HIGH
        return {
            "type": RiskTypes.KERBEROS_LEGACY_ENCRYPTION,
            "severity": severity,
            "title": f"Legacy Kerberos encryption configured on {account_name}",
            "description": " ".join(issues),
            "affected_object": account_name,
            "object_type": object_type,
            "impact": (
                "DES and RC4 provide materially weaker protection than AES and increase exposure "
                "to offline ticket or key cracking when the account participates in Kerberos authentication."
            ),
            "mitigation": (
                "Inventory clients and services that use this account, enable AES-compatible Kerberos settings, "
                "rotate the account password under change control so AES keys are generated, monitor for remaining "
                "RC4 use, and then remove DES and RC4 support."
            ),
            "mitre_attack": MITRETechniques.STEAL_FORGE_KERBEROS_KERBEROASTING,
            "encryption_types": encryption_types,
            "use_des_key_only": des_only,
            "encryption_issues": issues,
        }

    def _assess_privileged_delegation(
        self,
        user: dict[str, Any],
    ) -> Optional[dict[str, Any]]:
        """Return a finding for a privileged user that can be delegated."""
        privilege_evidence = self._privilege_evidence(user)
        if not privilege_evidence:
            return None

        uac = self._as_int(user.get("userAccountControl")) or 0
        if uac & UACFlags.NOT_DELEGATED:
            return None

        account_name = self._account_name(user, "user")
        return {
            "type": RiskTypes.PRIVILEGED_ACCOUNT_DELEGATABLE,
            "severity": Severity.HIGH,
            "title": f"Privileged account can be delegated: {account_name}",
            "description": (
                "The account is privileged or protected but does not have the NOT_DELEGATED "
                '("Account is sensitive and cannot be delegated") flag.'
            ),
            "affected_object": account_name,
            "object_type": "user",
            "is_privileged": True,
            "privilege_evidence": privilege_evidence,
            "impact": (
                "A service or host trusted for delegation may obtain and reuse this privileged user's "
                "Kerberos credentials, increasing credential-theft and lateral-movement impact."
            ),
            "mitigation": (
                'Enable "Account is sensitive and cannot be delegated" for interactive privileged accounts. '
                "Validate service dependencies first; use dedicated, least-privileged service identities when "
                "delegation is operationally required."
            ),
            "mitre_attack": MITRETechniques.PASS_THE_TICKET,
        }

    @staticmethod
    def _as_int(value: Any) -> Optional[int]:
        """Convert common LDAP scalar representations to an integer."""
        if isinstance(value, (list, tuple)):
            if len(value) != 1:
                return None
            value = value[0]
        if value in (None, ""):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _is_enabled(cls, account: dict[str, Any]) -> bool:
        """Return whether an account is enabled according to UAC."""
        uac = cls._as_int(account.get("userAccountControl")) or 0
        return not bool(uac & UACFlags.ACCOUNTDISABLE)

    @staticmethod
    def _account_name(account: dict[str, Any], object_type: str) -> str:
        """Return a stable report label for a directory account."""
        if object_type == "computer":
            return str(account.get("name") or account.get("sAMAccountName") or "Unknown computer")
        return str(account.get("sAMAccountName") or account.get("name") or "Unknown user")

    @staticmethod
    def _privilege_evidence(user: dict[str, Any]) -> list[str]:
        """Return evidence that the user is privileged or protected."""
        evidence: list[str] = []
        if str(user.get("adminCount", "")) == "1":
            evidence.append("adminCount=1")

        member_of = user.get("memberOf") or []
        if not isinstance(member_of, (list, tuple)):
            member_of = [member_of]
        for group_dn in member_of:
            first_rdn = str(group_dn).split(",", 1)[0]
            group_name = first_rdn.split("=", 1)[-1].strip().upper()
            if group_name in PRIVILEGED_GROUP_NAMES:
                evidence.append(f"Member of {group_name.title()}")

        return evidence

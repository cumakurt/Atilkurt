"""Assess identity-protection controls visible in collected AD user records."""

import logging
from typing import Any, Optional

from core.constants import MITRETechniques, RiskTypes, Severity, UACFlags

logger = logging.getLogger(__name__)


class IdentityProtectionAnalyzer:
    """Detect high-value account protections that are absent or weakened."""

    PRIVILEGED_GROUPS = {
        "ADMINISTRATORS", "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
        "ACCOUNT OPERATORS", "SERVER OPERATORS", "BACKUP OPERATORS", "PRINT OPERATORS",
    }

    def analyze(self, users: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return identity-protection findings for enabled privileged users."""
        risks: list[dict[str, Any]] = []
        for user in users or []:
            if not self._is_enabled(user) or not self._is_privileged(user):
                continue

            account_name = str(user.get("sAMAccountName") or user.get("name") or "Unknown user")
            uac = self._as_int(user.get("userAccountControl")) or 0
            member_of = user.get("memberOf")
            group_names = self._group_names(member_of)

            if uac & UACFlags.ENCRYPTED_TEXT_PWD_ALLOWED:
                risks.append(self._risk(
                    RiskTypes.REVERSIBLE_ENCRYPTION_ENABLED,
                    Severity.CRITICAL,
                    f"Reversible password encryption enabled: {account_name}",
                    "The ENCRYPTED_TEXT_PWD_ALLOWED flag permits reversible password storage for a privileged account.",
                    account_name,
                    "Clear the setting, rotate the password, and verify that no service dependency requires reversible storage.",
                ))

            # Missing LDAP attributes must not become false-positive absence findings.
            if isinstance(member_of, (list, tuple, str)) and "PROTECTED USERS" not in group_names:
                risks.append(self._risk(
                    RiskTypes.PRIVILEGED_USER_OUTSIDE_PROTECTED_USERS,
                    Severity.HIGH,
                    f"Privileged account is outside Protected Users: {account_name}",
                    "The enabled privileged account is not a member of Protected Users, which provides additional Kerberos and credential-delegation protections.",
                    account_name,
                    "Review compatibility and add the account to Protected Users where appropriate; use dedicated service identities for incompatible workloads.",
                ))

            if not (uac & UACFlags.SMARTCARD_REQUIRED):
                risks.append(self._risk(
                    RiskTypes.PRIVILEGED_USER_WITHOUT_SMARTCARD,
                    Severity.MEDIUM,
                    f"Privileged account does not require smart card: {account_name}",
                    "The privileged account does not have SMARTCARD_REQUIRED set, increasing password-only credential-theft impact.",
                    account_name,
                    "Require phishing-resistant or smart-card authentication after validating application and emergency-access dependencies.",
                ))

        logger.info("Found %d identity-protection risks", len(risks))
        return risks

    @classmethod
    def _is_privileged(cls, user: dict[str, Any]) -> bool:
        """Return whether a user has direct privileged-account evidence."""
        if str(user.get("adminCount", "")) == "1":
            return True
        member_of = user.get("memberOf") or []
        if not isinstance(member_of, (list, tuple)):
            member_of = [member_of]
        return any(name in cls.PRIVILEGED_GROUPS for name in cls._group_names(member_of))

    @staticmethod
    def _is_enabled(user: dict[str, Any]) -> bool:
        """Return whether the account is enabled according to userAccountControl."""
        try:
            return not bool(int(user.get("userAccountControl", 0) or 0) & UACFlags.ACCOUNTDISABLE)
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _as_int(value: Any) -> Optional[int]:
        """Convert a scalar or one-element LDAP value to an integer."""
        if isinstance(value, (list, tuple)):
            if len(value) != 1:
                return None
            value = value[0]
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _group_names(member_of: Any) -> set[str]:
        """Normalize group DNs and names to uppercase first-RDN names."""
        if not isinstance(member_of, (list, tuple)):
            member_of = [member_of] if member_of else []
        names: set[str] = set()
        for value in member_of:
            first_rdn = str(value).split(",", 1)[0]
            names.add(first_rdn.split("=", 1)[-1].strip().upper())
        return names

    @staticmethod
    def _risk(
        risk_type: str,
        severity: str,
        title: str,
        description: str,
        account_name: str,
        mitigation: str,
    ) -> dict[str, Any]:
        """Build a consistent identity-protection risk record."""
        return {
            "type": risk_type, "severity": severity, "title": title,
            "description": description, "affected_object": account_name,
            "object_type": "user", "mitigation": mitigation,
            "mitre_attack": MITRETechniques.VALID_ACCOUNTS,
        }

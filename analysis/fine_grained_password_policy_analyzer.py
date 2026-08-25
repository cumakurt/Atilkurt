"""Compare fine-grained password policies with the domain default policy."""

import logging
from datetime import timedelta
from typing import Any, Optional

from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)

PASSWORD_COMPLEXITY = 0x01
PASSWORD_STORE_CLEARTEXT = 0x10
SEVERITY_RANK = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FineGrainedPasswordPolicyAnalyzer:
    """Detect password settings objects that weaken domain defaults."""

    DOMAIN_ATTRIBUTES = [
        "minPwdLength",
        "pwdHistoryLength",
        "pwdProperties",
        "lockoutThreshold",
        "lockoutDuration",
        "lockoutObservationWindow",
    ]
    PSO_ATTRIBUTES = [
        "name",
        "distinguishedName",
        "msDS-PasswordSettingsPrecedence",
        "msDS-MinimumPasswordLength",
        "msDS-PasswordHistoryLength",
        "msDS-PasswordComplexityEnabled",
        "msDS-PasswordReversibleEncryptionEnabled",
        "msDS-LockoutThreshold",
        "msDS-LockoutDuration",
        "msDS-LockoutObservationWindow",
        "msDS-PSOAppliesTo",
    ]

    def __init__(self, ldap_connection: Any):
        """Initialize the analyzer with a read-only LDAP connection."""
        self.ldap = ldap_connection

    def analyze(self) -> list[dict[str, Any]]:
        """Return findings for weaker or independently unsafe PSO settings."""
        domain_policy = self._read_domain_policy()
        policies = self._read_password_settings_objects()
        risks: list[dict[str, Any]] = []

        for policy in policies:
            finding = self._assess_policy(policy, domain_policy)
            if finding:
                risks.append(finding)

        logger.info("Found %d weak fine-grained password policy risks", len(risks))
        return risks

    def _read_domain_policy(self) -> dict[str, Any]:
        """Read and normalize the domain default password and lockout policy."""
        try:
            results = self.ldap.search(
                search_base=self.ldap.base_dn,
                search_filter="(objectClass=domainDNS)",
                attributes=self.DOMAIN_ATTRIBUTES,
                size_limit=1,
            )
        except Exception as exc:
            logger.warning("Could not read the domain policy for PSO comparison: %s", exc)
            return {}

        if not results:
            logger.warning("Domain policy was unavailable for PSO comparison")
            return {}

        policy = results[0]
        properties = self._as_int(self._get(policy, "pwdProperties"))
        return {
            "minimum_password_length": self._as_int(self._get(policy, "minPwdLength")),
            "password_history_length": self._as_int(self._get(policy, "pwdHistoryLength")),
            "complexity_enabled": bool(properties & PASSWORD_COMPLEXITY) if properties is not None else None,
            "reversible_encryption_enabled": (
                bool(properties & PASSWORD_STORE_CLEARTEXT) if properties is not None else None
            ),
            "lockout_threshold": self._as_int(self._get(policy, "lockoutThreshold")),
            "lockout_duration_seconds": self._timespan_seconds(self._get(policy, "lockoutDuration")),
            "lockout_observation_window_seconds": self._timespan_seconds(
                self._get(policy, "lockoutObservationWindow")
            ),
        }

    def _read_password_settings_objects(self) -> list[dict[str, Any]]:
        """Read all password settings objects from the domain naming context."""
        try:
            results = self.ldap.search(
                search_base=self.ldap.base_dn,
                search_filter="(objectClass=msDS-PasswordSettings)",
                attributes=self.PSO_ATTRIBUTES,
            )
            return results or []
        except Exception as exc:
            logger.warning("Could not read fine-grained password policies: %s", exc)
            return []

    def _assess_policy(
        self,
        policy: dict[str, Any],
        domain_policy: dict[str, Any],
    ) -> Optional[dict[str, Any]]:
        """Compare one PSO with the domain defaults and build one finding."""
        policy_settings = {
            "minimum_password_length": self._as_int(self._get(policy, "msDS-MinimumPasswordLength")),
            "password_history_length": self._as_int(self._get(policy, "msDS-PasswordHistoryLength")),
            "complexity_enabled": self._as_bool(self._get(policy, "msDS-PasswordComplexityEnabled")),
            "reversible_encryption_enabled": self._as_bool(
                self._get(policy, "msDS-PasswordReversibleEncryptionEnabled")
            ),
            "lockout_threshold": self._as_int(self._get(policy, "msDS-LockoutThreshold")),
            "lockout_duration_seconds": self._timespan_seconds(self._get(policy, "msDS-LockoutDuration")),
            "lockout_observation_window_seconds": self._timespan_seconds(
                self._get(policy, "msDS-LockoutObservationWindow")
            ),
        }
        issues: list[dict[str, str]] = []

        self._compare_lower_value(
            issues,
            policy_settings,
            domain_policy,
            "minimum_password_length",
            "Minimum password length",
        )
        self._compare_lower_value(
            issues,
            policy_settings,
            domain_policy,
            "password_history_length",
            "Password history length",
        )

        if (
            policy_settings["complexity_enabled"] is False
            and domain_policy.get("complexity_enabled") is True
        ):
            issues.append({
                "severity": Severity.HIGH,
                "issue": "Password complexity is disabled while the domain default enables it.",
            })

        if policy_settings["reversible_encryption_enabled"] is True:
            issues.append({
                "severity": Severity.CRITICAL,
                "issue": "Reversible password encryption is enabled for the policy.",
            })

        pso_threshold = policy_settings["lockout_threshold"]
        domain_threshold = domain_policy.get("lockout_threshold")
        if pso_threshold == 0 and domain_threshold not in (None, 0):
            issues.append({
                "severity": Severity.HIGH,
                "issue": "Account lockout is disabled while the domain default enables it.",
            })
        elif (
            pso_threshold is not None
            and domain_threshold not in (None, 0)
            and pso_threshold > domain_threshold
        ):
            issues.append({
                "severity": Severity.MEDIUM,
                "issue": (
                    f"Lockout threshold is {pso_threshold}, weaker than the domain default "
                    f"of {domain_threshold}."
                ),
            })

        if pso_threshold not in (None, 0):
            self._compare_lockout_timespan(
                issues,
                policy_settings,
                domain_policy,
                "lockout_duration_seconds",
                "Lockout duration",
            )
            self._compare_lockout_timespan(
                issues,
                policy_settings,
                domain_policy,
                "lockout_observation_window_seconds",
                "Lockout observation window",
            )

        if not issues:
            return None

        name = str(
            self._get(policy, "name")
            or self._get(policy, "distinguishedName")
            or "Unnamed password settings object"
        )
        applies_to = self._as_list(self._get(policy, "msDS-PSOAppliesTo"))
        severity = max(issues, key=lambda issue: SEVERITY_RANK[issue["severity"]])["severity"]
        issue_text = " ".join(issue["issue"] for issue in issues)

        return {
            "type": RiskTypes.WEAK_FINE_GRAINED_PASSWORD_POLICY,
            "severity": severity,
            "title": f"Weak fine-grained password policy: {name}",
            "description": issue_text,
            "affected_object": name,
            "object_type": "policy",
            "impact": (
                "Users targeted by this password settings object can receive weaker credential and lockout "
                "protections than the domain default, creating a focused password-attack path."
            ),
            "mitigation": (
                "Review the policy precedence and target principals. Make every PSO at least as strong as the "
                "domain default, disable reversible encryption, and validate the effective policy for affected users."
            ),
            "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
            "policy_issues": issues,
            "policy_precedence": self._as_int(self._get(policy, "msDS-PasswordSettingsPrecedence")),
            "applies_to": applies_to,
            "domain_policy": domain_policy,
            "policy_settings": policy_settings,
        }

    @staticmethod
    def _compare_lower_value(
        issues: list[dict[str, str]],
        policy: dict[str, Any],
        domain: dict[str, Any],
        key: str,
        label: str,
    ) -> None:
        """Append an issue when a lower numeric value weakens the PSO."""
        policy_value = policy.get(key)
        domain_value = domain.get(key)
        if policy_value is not None and domain_value is not None and policy_value < domain_value:
            issues.append({
                "severity": Severity.MEDIUM,
                "issue": f"{label} is {policy_value}, lower than the domain default of {domain_value}.",
            })

    @staticmethod
    def _compare_lockout_timespan(
        issues: list[dict[str, str]],
        policy: dict[str, Any],
        domain: dict[str, Any],
        key: str,
        label: str,
    ) -> None:
        """Append an issue when a finite PSO lockout interval is shorter."""
        policy_seconds = policy.get(key)
        domain_seconds = domain.get(key)
        if policy_seconds is None or domain_seconds is None:
            return
        # Zero means that administrative unlock is required and is not weaker.
        if policy_seconds > 0 and (domain_seconds == 0 or policy_seconds < domain_seconds):
            issues.append({
                "severity": Severity.MEDIUM,
                "issue": (
                    f"{label} is {policy_seconds // 60} minute(s), shorter than the domain default "
                    f"of {domain_seconds // 60} minute(s)."
                ),
            })

    @staticmethod
    def _get(entry: dict[str, Any], attribute: str) -> Any:
        """Read an LDAP attribute without relying on server-returned casing."""
        target = attribute.casefold()
        for key, value in entry.items():
            if str(key).casefold() == target:
                return value
        return None

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
    def _as_bool(cls, value: Any) -> Optional[bool]:
        """Convert LDAP boolean representations without treating unknown text as true."""
        if isinstance(value, (list, tuple)):
            if len(value) != 1:
                return None
            value = value[0]
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().casefold()
            if normalized in {"true", "1", "yes"}:
                return True
            if normalized in {"false", "0", "no"}:
                return False
            return None
        if isinstance(value, int):
            return bool(value)
        return None

    @staticmethod
    def _timespan_seconds(value: Any) -> Optional[int]:
        """Convert AD interval or timedelta values to absolute seconds."""
        if isinstance(value, (list, tuple)):
            if len(value) != 1:
                return None
            value = value[0]
        if isinstance(value, timedelta):
            return abs(int(value.total_seconds()))
        if value in (None, ""):
            return None
        try:
            return abs(int(value)) // 10_000_000
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _as_list(value: Any) -> list[Any]:
        """Normalize a single LDAP value or a multi-valued attribute to a list."""
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            return list(value)
        return [value]

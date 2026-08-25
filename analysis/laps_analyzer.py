"""
LAPS (Local Administrator Password Solution) Analyzer Module
Detects LAPS configuration and access rights
"""

import logging
from typing import Any
from core.ad_identity import schema_supports_attribute
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)

LEGACY_LAPS_EXPIRY_ATTRIBUTES = (
    "ms-Mcs-AdmPwdExpirationTime",
    "msMcs-AdmPwdExpirationTime",
    "msMcsAdmPwdExpirationTime",
)
WINDOWS_LAPS_EXPIRY_ATTRIBUTES = (
    "msLAPS-PasswordExpirationTime",
    "msLAPS-EncryptedPasswordExpirationTime",
)


def _attribute_is_populated(obj: dict[str, Any], names: tuple[str, ...]) -> bool:
    """Return True when any named LDAP attribute is present and non-empty."""
    for name in names:
        value = obj.get(name)
        if value not in (None, "", [], ()):
            return True
    return False


class LAPSAnalyzer:
    """Analyzes LAPS configuration and access rights."""

    def __init__(self, ldap_connection):
        """
        Initialize LAPS analyzer.

        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection

    def analyze_laps(self, computers: list[dict[str, Any]],
                    users: list[dict[str, Any]],
                    groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Analyze LAPS configuration and access.

        Args:
            computers: List of computer dictionaries
            users: List of user dictionaries
            groups: List of group dictionaries

        Returns:
            List of risk dictionaries for LAPS issues
        """
        risks = []

        try:
            computers_with_laps = [
                str(computer.get("name") or computer.get("sAMAccountName") or "Unknown")
                for computer in (computers or [])
                if _attribute_is_populated(computer, LEGACY_LAPS_EXPIRY_ATTRIBUTES)
            ]
            computers_with_windows_laps = [
                computer for computer in (computers or [])
                if _attribute_is_populated(computer, WINDOWS_LAPS_EXPIRY_ATTRIBUTES)
            ]

            if not computers_with_laps and not computers_with_windows_laps:
                discovered_legacy, discovered_windows = self._discover_laps_coverage()
                computers_with_laps.extend(discovered_legacy)
                computers_with_windows_laps.extend(discovered_windows)

            laps_installed = bool(computers_with_laps or computers_with_windows_laps)

            # Check LAPS configuration
            if not laps_installed:
                risks.append({
                    'type': RiskTypes.LAPS_NOT_CONFIGURED,
                    'severity': Severity.HIGH,
                    'title': 'LAPS Not Configured',
                    'description': (
                        'Local Administrator Password Solution (LAPS) is not configured. '
                        'Computers may have weak or shared local administrator passwords.'
                    ),
                    'affected_object': 'Domain',
                    'object_type': 'configuration',
                    'impact': (
                        'Without LAPS, local administrator passwords may be weak, shared, or never rotated. '
                        'This allows attackers to use the same password across multiple systems after '
                        'compromising one system.'
                    ),
                    'attack_scenario': (
                        'An attacker who compromises one system can use the local administrator password '
                        'to access other systems with the same password. This enables lateral movement.'
                    ),
                    'mitigation': (
                        'Install and configure LAPS. LAPS automatically manages unique, complex passwords '
                        'for local administrator accounts and rotates them regularly. Grant read access '
                        'only to authorized accounts.'
                    ),
                    'cis_reference': 'CIS Benchmark recommends using LAPS for local admin password management',
                    'mitre_attack': MITRETechniques.LATERAL_MOVEMENT
                })
            else:
                # Check who can read LAPS passwords
                # LAPS passwords are readable by accounts with "Read ms-Mcs-AdmPwd" permission
                # Typically granted to specific groups or users

                # Check if too many accounts can read LAPS passwords
                # This would require ACL analysis which is complex
                # For now, we'll provide general guidance

                if len(computers_with_laps) > 0:
                    risks.append({
                        'type': RiskTypes.LAPS_ACCESS_ANALYSIS,
                        'severity': Severity.MEDIUM,
                        'title': f'LAPS Configured on {len(computers_with_laps)} Computers',
                        'description': (
                            f'LAPS is configured on {len(computers_with_laps)} computers. '
                            'Review who has access to read LAPS passwords.'
                        ),
                        'affected_object': f'{len(computers_with_laps)} computers',
                        'object_type': 'configuration',
                        'computers_with_laps': computers_with_laps,
                        'impact': (
                            'LAPS passwords should only be readable by authorized accounts. '
                            'Too many accounts with LAPS read access increases the risk of password exposure.'
                        ),
                        'attack_scenario': (
                            'An attacker who compromises an account with LAPS read permissions can '
                            'extract local administrator passwords for all computers, enabling lateral movement.'
                        ),
                        'mitigation': (
                            'Review and restrict LAPS read permissions. Only grant access to accounts '
                            'that absolutely need it. Use privileged access management solutions. '
                            'Monitor for unauthorized LAPS password reads.'
                        ),
                        'cis_reference': 'CIS Benchmark requires strict control over LAPS access',
                        'mitre_attack': MITRETechniques.LATERAL_MOVEMENT
                    })


            risks.extend(self._analyze_windows_laps(computers, computers_with_windows_laps))

            logger.info(f"Found {len(risks)} LAPS-related risks")
            return risks

        except Exception as e:
            logger.error(f"Error analyzing LAPS: {str(e)}")
            return []

    def _discover_laps_coverage(self) -> tuple[list[str], list[dict[str, Any]]]:
        """Find LAPS coverage with bounded searches that never read passwords."""
        ldap_expiry_attributes = [
            "ms-Mcs-AdmPwdExpirationTime",
            *WINDOWS_LAPS_EXPIRY_ATTRIBUTES,
        ]
        supported_attributes = [
            attribute for attribute in ldap_expiry_attributes
            if schema_supports_attribute(self.ldap, attribute) is not False
        ]
        if not supported_attributes:
            return [], []

        legacy_names: list[str] = []
        windows_rows: list[dict[str, Any]] = []
        seen_legacy: set[str] = set()
        seen_windows: set[str] = set()
        for attribute in supported_attributes:
            try:
                rows = self.ldap.search(
                    search_base=self.ldap.base_dn,
                    search_filter=f"({attribute}=*)",
                    attributes=["name", "sAMAccountName", attribute],
                ) or []
            except Exception as exc:
                logger.debug("LAPS coverage search failed for %s: %s", attribute, exc)
                continue

            for row in rows:
                name = str(row.get("name") or row.get("sAMAccountName") or "Unknown")
                identity = str(row.get("dn") or name).casefold()
                if attribute == "ms-Mcs-AdmPwdExpirationTime":
                    if identity not in seen_legacy:
                        seen_legacy.add(identity)
                        legacy_names.append(name)
                elif identity not in seen_windows:
                    seen_windows.add(identity)
                    windows_rows.append(row)
        return legacy_names, windows_rows

    def _plaintext_laps_readable_count(self) -> int:
        """Count computers whose plaintext LAPS attribute is readable without retrieving the secret."""
        if schema_supports_attribute(self.ldap, "msLAPS-Password") is False:
            return 0
        try:
            rows = self.ldap.search(
                search_base=self.ldap.base_dn,
                search_filter="(msLAPS-Password=*)",
                attributes=["name"],
                size_limit=50,
            ) or []
        except Exception as exc:
            logger.debug("Windows LAPS plaintext presence search failed: %s", exc)
            return 0
        return len(rows)

    def _analyze_windows_laps(
        self,
        computers: list[dict[str, Any]],
        windows_computers: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect Windows LAPS coverage versus legacy LAPS only."""
        risks: list[dict[str, Any]] = []
        plaintext_count = self._plaintext_laps_readable_count()
        if plaintext_count:
            risks.append({
                'type': RiskTypes.WINDOWS_LAPS_PLAINTEXT,
                'severity': Severity.HIGH,
                'title': f'Windows LAPS stores readable plaintext passwords on {plaintext_count} computers',
                'description': (
                    'msLAPS-Password is populated and readable by this assessment account. '
                    'The password values were not retrieved. Plaintext LAPS attributes should be '
                    'encrypted (msLAPS-EncryptedPassword) and tightly ACL-scoped.'
                ),
                'affected_object': 'Windows LAPS',
                'object_type': 'configuration',
                'impact': 'Any principal who can read msLAPS-Password obtains local administrator credentials.',
                'attack_scenario': 'An account with read access to msLAPS-Password can recover local administrator credentials.',
                'mitigation': 'Switch to encrypted Windows LAPS, restrict READ to a PAM group, and monitor 4662 on the attribute.',
                'mitre_attack': MITRETechniques.UNSECURED_CREDENTIALS,
            })
        computer_count = len(computers or [])
        if computer_count >= 5 and not windows_computers:
            risks.append({
                'type': RiskTypes.WINDOWS_LAPS_NOT_DEPLOYED,
                'severity': Severity.MEDIUM,
                'title': 'Windows LAPS is not deployed',
                'description': (
                    'No computer objects advertise msLAPS-PasswordExpirationTime or '
                    'msLAPS-EncryptedPasswordExpirationTime. Legacy Microsoft LAPS (ms-Mcs-AdmPwd) is obsolete.'
                ),
                'affected_object': 'Domain',
                'object_type': 'configuration',
                'impact': 'Shared or static local administrator passwords enable lateral movement after a single host compromise.',
                'attack_scenario': 'Dump a local admin hash from one workstation and reuse it across the estate.',
                'mitigation': 'Deploy Windows LAPS with encrypted passwords and automatic rotation. Retire legacy LAPS.',
                'mitre_attack': MITRETechniques.LATERAL_MOVEMENT,
            })
        return risks

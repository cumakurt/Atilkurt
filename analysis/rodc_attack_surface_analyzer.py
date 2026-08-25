"""Read-only domain controller password-replication attack surface."""

from __future__ import annotations

import logging
from typing import Any

from ldap3.utils.conv import escape_filter_chars

from core.ad_identity import is_privileged_principal_reference
from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)

PARTIAL_SECRETS_UAC = 0x4000000


class RODCAttackSurfaceAnalyzer:
    """Evaluate RODC password-replication policy and revealed privileged secrets."""

    def __init__(self, ldap_connection: Any):
        self.ldap = ldap_connection

    def analyze(self, computers: list[dict[str, Any]], groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return RODC findings from UAC flags and password-replication attributes."""
        risks: list[dict[str, Any]] = []
        rodcs = self._find_rodcs(computers)
        if not rodcs:
            logger.info("No RODCs detected")
            return risks
        for rodc in rodcs:
            risks.extend(self._assess_rodc(rodc))
        risks.extend(self._assess_allowed_replication_group(groups))
        logger.info("Found %d RODC attack-surface risks", len(risks))
        return risks

    def _search(self, search_filter: str, attributes: list[str], size_limit: int = 50) -> list[dict[str, Any]]:
        try:
            return self.ldap.search(
                search_base=self.ldap.base_dn,
                search_filter=search_filter,
                attributes=attributes,
                size_limit=size_limit,
            ) or []
        except Exception as exc:
            logger.debug("RODC search failed: %s", exc)
            return []

    def _uac(self, obj: dict[str, Any]) -> int:
        try:
            return int(obj.get("userAccountControl") or 0)
        except (TypeError, ValueError):
            return 0

    def _find_rodcs(self, computers: list[dict[str, Any]]) -> list[dict[str, Any]]:
        found = [
            computer for computer in (computers or [])
            if self._uac(computer) & PARTIAL_SECRETS_UAC
        ]
        if found:
            return found
        return self._search(
            f"(userAccountControl:1.2.840.113556.1.4.803:={PARTIAL_SECRETS_UAC})",
            [
                "sAMAccountName",
                "name",
                "userAccountControl",
                "msDS-RevealOnDemandGroup",
                "msDS-NeverRevealGroup",
                "msDS-RevealedUsers",
                "managedBy",
                "distinguishedName",
            ],
            size_limit=50,
        )

    def _as_list(self, value: Any) -> list[Any]:
        if value in (None, ""):
            return []
        if isinstance(value, list):
            return value
        return [value]

    def _assess_rodc(self, rodc: dict[str, Any]) -> list[dict[str, Any]]:
        risks: list[dict[str, Any]] = []
        name = str(rodc.get("name") or rodc.get("sAMAccountName") or "RODC")
        details = rodc
        distinguished_name = rodc.get("distinguishedName")
        if not rodc.get("msDS-RevealOnDemandGroup") and distinguished_name:
            extra = self._search(
                f"(distinguishedName={escape_filter_chars(str(distinguished_name))})",
                [
                    "msDS-RevealOnDemandGroup",
                    "msDS-NeverRevealGroup",
                    "msDS-RevealedUsers",
                    "managedBy",
                    "sAMAccountName",
                ],
                size_limit=1,
            )
            if extra:
                details = extra[0]
        reveal = self._as_list(details.get("msDS-RevealOnDemandGroup"))
        never = self._as_list(details.get("msDS-NeverRevealGroup"))
        revealed_users = self._as_list(details.get("msDS-RevealedUsers"))
        if not never:
            risks.append({
                "type": RiskTypes.RODC_MISSING_NEVER_REVEAL,
                "severity": Severity.HIGH,
                "title": f"RODC {name} has no NeverReveal group",
                "description": (
                    f"RODC '{name}' does not define msDS-NeverRevealGroup. Privileged secrets may be "
                    "cached if those accounts authenticate against the RODC."
                ),
                "affected_object": name,
                "object_type": "computer",
                "impact": "An attacker who steals an RODC can extract cached hashes for any user who authenticated to it.",
                "attack_scenario": "Promote or compromise an RODC, wait for admins to authenticate, then dump the cached secrets.",
                "mitigation": "Populate Denied RODC Password Replication Group with all Tier 0 identities and assign it as NeverReveal.",
                "mitre_attack": MITRETechniques.OS_CREDENTIAL_DUMP,
            })
        dangerous_reveal = [
            str(item) for item in reveal
            if is_privileged_principal_reference(item)
        ]
        if dangerous_reveal:
            risks.append({
                "type": RiskTypes.RODC_PRIVILEGED_REVEAL,
                "severity": Severity.CRITICAL,
                "title": f"RODC {name} may cache privileged secrets",
                "description": (
                    f"RODC '{name}' RevealOnDemand groups include privileged principals: "
                    + ", ".join(dangerous_reveal[:8])
                ),
                "affected_object": name,
                "object_type": "computer",
                "impact": "Privileged password hashes cached on an RODC enable domain takeover after RODC theft.",
                "attack_scenario": "Steal the RODC, extract KRBTGT_XXXXX or cached DA hashes, then forge tickets.",
                "mitigation": "Remove privileged groups from Allowed RODC Password Replication Group and add them to Denied.",
                "mitre_attack": MITRETechniques.STEAL_FORGE_KERBEROS_GOLDEN,
            })
        if len(revealed_users) >= 25:
            risks.append({
                "type": RiskTypes.RODC_BROAD_REVEALED_SECRETS,
                "severity": Severity.MEDIUM,
                "title": f"RODC {name} has revealed {len(revealed_users)} cached secrets",
                "description": (
                    f"msDS-RevealedUsers on '{name}' lists {len(revealed_users)} principals. "
                    "A large cache increases the value of physical or backup theft."
                ),
                "affected_object": name,
                "object_type": "computer",
                "impact": "RODC theft exposes a large set of credential material.",
                "attack_scenario": "Image the RODC disk or ntds.dit equivalent and extract cached secrets.",
                "mitigation": "Reduce Allowed RODC Password Replication Group membership and purge stale revealed users.",
                "mitre_attack": MITRETechniques.OS_CREDENTIAL_DUMP,
            })
        return risks

    def _assess_allowed_replication_group(self, groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
        risks: list[dict[str, Any]] = []
        for group in groups or []:
            name = str(group.get("name") or group.get("sAMAccountName") or "")
            if "ALLOWED RODC PASSWORD REPLICATION GROUP" not in name.upper():
                continue
            members = group.get("member") or []
            if not isinstance(members, list):
                members = [members] if members else []
            privileged = [
                str(member) for member in members
                if is_privileged_principal_reference(member)
            ]
            if privileged:
                risks.append({
                    "type": RiskTypes.RODC_ALLOWED_GROUP_PRIVILEGED,
                    "severity": Severity.HIGH,
                    "title": "Allowed RODC Password Replication Group contains privileged principals",
                    "description": "Privileged members: " + ", ".join(privileged[:8]),
                    "affected_object": name,
                    "object_type": "group",
                    "impact": "Any RODC using the default allowed group can cache privileged secrets.",
                    "attack_scenario": "Authenticate a Domain Admin against an RODC, then steal the RODC cache.",
                    "mitigation": "Keep the Allowed RODC Password Replication Group empty of Tier 0 identities.",
                    "mitre_attack": MITRETechniques.OS_CREDENTIAL_DUMP,
                })
        return risks

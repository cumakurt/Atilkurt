"""Hidden privileged membership via primaryGroupID and computer accounts in admin groups."""

from __future__ import annotations

import logging
from typing import Any

from core.ad_identity import is_privileged_group_record
from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)

PRIVILEGED_PRIMARY_RIDS = {
    512: "Domain Admins",
    516: "Domain Controllers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    544: "Administrators",
    548: "Account Operators",
    549: "Server Operators",
    550: "Print Operators",
    551: "Backup Operators",
}


class HiddenPrivilegeAnalyzer:
    """Find privileged access that is hidden from member/memberOf enumeration."""

    def analyze(
        self,
        users: list[dict[str, Any]],
        computers: list[dict[str, Any]],
        groups: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Return hidden-privilege findings from collected directory objects."""
        risks: list[dict[str, Any]] = []
        risks.extend(self._primary_group_risks(users, "user"))
        risks.extend(self._primary_group_risks(computers, "computer"))
        risks.extend(self._privileged_computer_members(groups, computers))
        risks.extend(self._built_in_administrator(users))
        logger.info("Found %d hidden privilege risks", len(risks))
        return risks

    def _as_int(self, value: Any) -> int | None:
        if isinstance(value, (list, tuple)):
            value = value[0] if value else None
        if value in (None, ""):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _account_name(self, obj: dict[str, Any], object_type: str) -> str:
        if object_type == "computer":
            return str(obj.get("name") or obj.get("sAMAccountName") or "Unknown")
        return str(obj.get("sAMAccountName") or obj.get("name") or "Unknown")

    def _is_enabled(self, obj: dict[str, Any]) -> bool:
        try:
            uac = int(obj.get("userAccountControl") or 0)
        except (TypeError, ValueError):
            return True
        return not bool(uac & 0x2)

    def _primary_group_risks(self, objects: list[dict[str, Any]], object_type: str) -> list[dict[str, Any]]:
        risks: list[dict[str, Any]] = []
        for obj in objects or []:
            if not self._is_enabled(obj):
                continue
            rid = self._as_int(obj.get("primaryGroupID"))
            if rid not in PRIVILEGED_PRIMARY_RIDS:
                continue
            name = self._account_name(obj, object_type)
            group_name = PRIVILEGED_PRIMARY_RIDS[rid]
            risks.append({
                "type": RiskTypes.HIDDEN_PRIMARY_GROUP_PRIVILEGE,
                "severity": Severity.CRITICAL if rid in {512, 518, 519} else Severity.HIGH,
                "title": f"Hidden privileged primary group: {name} -> {group_name}",
                "description": (
                    f"{object_type.title()} '{name}' has primaryGroupID {rid} ({group_name}). "
                    "Primary-group membership is omitted from the member attribute, so many ACL and "
                    "group-membership reviews miss this privilege."
                ),
                "affected_object": name,
                "object_type": object_type,
                "impact": "Attackers hide Domain Admin-equivalent access from memberOf-based hunting.",
                "attack_scenario": "Set primaryGroupID to 512 after joining Domain Admins, then remove the visible member entry.",
                "mitigation": (
                    f"Reset the primary group to Domain Users (513) or Domain Computers (515) "
                    f"and control {group_name} membership through visible member attributes."
                ),
                "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
                "primary_group": group_name,
            })
        return risks

    def _privileged_computer_members(
        self,
        groups: list[dict[str, Any]],
        computers: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        computer_dns = {
            str(computer.get("distinguishedName") or "").upper()
            for computer in (computers or [])
            if computer.get("distinguishedName")
        }
        risks: list[dict[str, Any]] = []
        for group in groups or []:
            if not is_privileged_group_record(group):
                continue
            group_name = str(group.get("name") or group.get("sAMAccountName") or "")
            members = group.get("member") or []
            if not isinstance(members, list):
                members = [members]
            for member in members:
                member_text = str(member)
                upper = member_text.upper()
                first_rdn = member_text.split(",")[0].upper() if member_text else ""
                looks_like_computer = first_rdn.endswith("$") or upper in computer_dns
                if not looks_like_computer:
                    continue
                risks.append({
                    "type": RiskTypes.PRIVILEGED_COMPUTER_ACCOUNT,
                    "severity": Severity.HIGH,
                    "title": f"Computer account in privileged group {group_name}",
                    "description": (
                        f"Privileged group '{group_name}' contains computer principal '{member_text}'. "
                        "Compromise of that host yields the group's directory rights."
                    ),
                    "affected_object": member_text,
                    "object_type": "computer",
                    "impact": "A workstation or server in a privileged group is a high-value lateral-movement target.",
                    "attack_scenario": "Steal the computer account credentials or abuse delegation on the host.",
                    "mitigation": (
                        f"Remove computer accounts from {group_name}. Use gMSA, just-in-time groups, "
                        "or PAM instead of persistent machine membership."
                    ),
                    "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
                    "group": group_name,
                })
        return risks

    def _built_in_administrator(self, users: list[dict[str, Any]]) -> list[dict[str, Any]]:
        risks: list[dict[str, Any]] = []
        for user in users or []:
            sid = str(user.get("objectSid") or "")
            if not sid.endswith("-500"):
                continue
            name = str(user.get("sAMAccountName") or "Administrator")
            if name.lower() == "administrator":
                continue
            risks.append({
                "type": RiskTypes.BUILTIN_ADMIN_RENAMED,
                "severity": Severity.MEDIUM,
                "title": f"Built-in Administrator (RID-500) is renamed to {name}",
                "description": (
                    "The RID-500 account has been renamed. Renaming does not remove the well-known SID; "
                    "attackers still target RID-500 directly."
                ),
                "affected_object": name,
                "object_type": "user",
                "impact": "Reviews that only look for sAMAccountName=Administrator miss the true built-in admin.",
                "attack_scenario": "Resolve SID ending in -500, then spray or forge tickets for that account.",
                "mitigation": "Treat RID-500 as break-glass: disable daily use, enroll in PAM, and monitor logons for SID *-500.",
                "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
            })
        return risks

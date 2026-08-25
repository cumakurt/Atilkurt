"""Helpers for Domain Admin / Enterprise Admin account status."""

from __future__ import annotations

from typing import Any

from core.ad_identity import (
    DOMAIN_ADMINS_RID,
    ENTERPRISE_ADMINS_RID,
    ROLE_DOMAIN_ADMINS,
    ROLE_ENTERPRISE_ADMINS,
    membership_names,
)
from core.constants import MITRETechniques, RiskTypes, Severity, UACFlags


def account_is_disabled(user: dict[str, Any]) -> bool:
    """Return True when the user account is disabled."""
    if user.get("isDisabled") is True:
        return True
    try:
        return bool(int(user.get("userAccountControl") or 0) & UACFlags.ACCOUNTDISABLE)
    except (TypeError, ValueError):
        return False


def _primary_group_rid(user: dict[str, Any]) -> int | None:
    raw = user.get("primaryGroupID")
    if raw in (None, ""):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def privileged_admin_roles(user: dict[str, Any]) -> list[str]:
    """Return Domain Admins / Enterprise Admins roles held by the user."""
    roles: list[str] = []
    names = set()
    for key in ("memberOf", "domainAdminGroups", "enterpriseAdminGroups", "adminGroups"):
        names.update(membership_names(user.get(key)))
    rid = _primary_group_rid(user)
    if "domain admins" in names or rid == DOMAIN_ADMINS_RID:
        roles.append(ROLE_DOMAIN_ADMINS)
    if "enterprise admins" in names or rid == ENTERPRISE_ADMINS_RID:
        roles.append(ROLE_ENTERPRISE_ADMINS)
    return roles


def list_disabled_privileged_admins(users: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Return disabled Domain Admin and Enterprise Admin accounts."""
    rows: list[dict[str, Any]] = []
    for user in users or []:
        if not account_is_disabled(user):
            continue
        roles = privileged_admin_roles(user)
        if not roles:
            continue
        rows.append(
            {
                "username": user.get("sAMAccountName") or "Unknown",
                "displayName": user.get("displayName") or "",
                "roles": roles,
                "distinguishedName": user.get("distinguishedName") or "",
            }
        )
    rows.sort(key=lambda item: (item["username"].lower(), ",".join(item["roles"])))
    return rows


def build_disabled_privileged_admin_risk(user: dict[str, Any], role: str) -> dict[str, Any]:
    """Build a high-severity finding for a disabled Tier 0 admin account."""
    username = user.get("sAMAccountName") or "Unknown"
    if role == ROLE_ENTERPRISE_ADMINS:
        risk_type = RiskTypes.DISABLED_ENTERPRISE_ADMIN
        title = "Disabled Enterprise Admin account"
        forest_note = "forest-wide (Enterprise Admins)"
    else:
        risk_type = RiskTypes.DISABLED_DOMAIN_ADMIN
        title = "Disabled Domain Admin account"
        forest_note = "domain-wide (Domain Admins)"
        role = ROLE_DOMAIN_ADMINS
    return {
        "type": risk_type,
        "severity": Severity.HIGH,
        "title": title,
        "description": (
            f"Account '{username}' is disabled but remains a member of {role}. "
            f"Re-enabling it immediately restores {forest_note} rights."
        ),
        "affected_object": username,
        "object_type": "user",
        "is_privileged": True,
        "admin_role": role,
        "impact": (
            "Disabled Tier 0 accounts still hold group membership, SID history, and often a usable password hash. "
            "An attacker who can enable the account, or an operator who re-enables it without a review, "
            "gains Domain Admin or Enterprise Admin access without changing group membership."
        ),
        "attack_scenario": (
            "Compromise a helpdesk or Account Operators identity, enable the leftover admin account, "
            "and authenticate as Domain Admin or Enterprise Admin."
        ),
        "mitigation": (
            f"Remove '{username}' from {role} (and nested privileged groups), rotate the password, "
            "clear adminCount if SDProp no longer applies, then delete the account if it is no longer required."
        ),
        "cis_reference": "CIS Benchmark 5.1 Privileged Account Inventory",
        "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
    }


def risks_for_disabled_privileged_admin(user: dict[str, Any]) -> list[dict[str, Any]]:
    """Return dedicated findings when a disabled user still holds DA or EA."""
    if not account_is_disabled(user):
        return []
    return [build_disabled_privileged_admin_risk(user, role) for role in privileged_admin_roles(user)]


def resolve_group_member(
    member: Any,
    users_by_dn: dict[str, dict[str, Any]],
    users_by_sam: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """Map a group member DN or SAM to a collected user object."""
    raw = str(member or "").strip()
    if not raw:
        return None
    user = users_by_dn.get(raw.lower())
    if user:
        return user
    if raw.upper().startswith("CN="):
        cn = raw.split(",", 1)[0][3:]
        return users_by_sam.get(cn.lower())
    return users_by_sam.get(raw.lower())

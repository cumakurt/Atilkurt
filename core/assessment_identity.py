"""Resolve the LDAP bind account used for this assessment."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from core.ad_identity import first_ldap_rdn, ldap_scalar_text
from core.ad_security import as_list, as_text, sid_text

logger = logging.getLogger(__name__)


def bind_sam(username: str) -> str:
    """Return the sAMAccountName portion of a bind username."""
    text = str(username or "").strip()
    if not text:
        return ""
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1]
    if "@" in text:
        text = text.split("@", 1)[0]
    return text.strip()


def parse_who_am_i(value: str) -> dict[str, str]:
    """Parse ldap3 ``who_am_i`` output into a DN or SAM."""
    text = str(value or "").strip()
    if text.lower().startswith("u:"):
        return {"sam": bind_sam(text[2:]), "dn": ""}
    if text.lower().startswith("dn:"):
        dn = text[3:].strip()
        return {"sam": first_ldap_rdn(dn), "dn": dn}
    if "=" in text and "," in text:
        return {"sam": first_ldap_rdn(text), "dn": text}
    return {"sam": bind_sam(text), "dn": ""}


def read_who_am_i(ldap: Any) -> str:
    """Return the directory's whoami string when the extension is available."""
    connection = getattr(ldap, "connection", None)
    extend = getattr(connection, "extend", None)
    standard = getattr(extend, "standard", None)
    who_am_i = getattr(standard, "who_am_i", None)
    if not callable(who_am_i):
        return ""
    try:
        return str(who_am_i() or "").strip()
    except Exception as exc:
        logger.debug("LDAP who_am_i failed: %s", type(exc).__name__)
        return ""


def match_inventory_principal(
    users: list[dict[str, Any]],
    computers: list[dict[str, Any]],
    *,
    sam: str,
    dn: str,
) -> dict[str, Any] | None:
    """Find the collected user or computer that matches the bind identity."""
    sam_key = sam.casefold()
    dn_key = dn.casefold()
    matches = []
    for obj in [*(users or []), *(computers or [])]:
        obj_dn = as_text(obj.get("distinguishedName") or obj.get("dn")).casefold()
        obj_sam = ldap_scalar_text(obj.get("sAMAccountName") or obj.get("name")).casefold()
        # whoami's DN is authoritative. Its CN need not equal sAMAccountName.
        matches_identity = obj_dn == dn_key if dn_key else bool(sam_key and obj_sam == sam_key)
        if matches_identity:
            matches.append(obj)
    return matches[0] if len(matches) == 1 else None


def collect_token_groups(ldap: Any, account: dict[str, Any]) -> dict[str, Any]:
    """Read tokenGroups for one account. Failures stay unknown."""
    dn = as_text(account.get("distinguishedName") or account.get("dn"))
    sid = sid_text(account.get("objectSid"))
    record: dict[str, Any] = {"status": "unknown", "sids": []}
    if not dn or not sid or ldap is None or not hasattr(ldap, "base_search"):
        record["reason"] = "principal_incomplete"
        return record
    try:
        rows = ldap.base_search(dn, ["tokenGroups", "objectSid", "sIDHistory"])
        if not rows:
            record["reason"] = "unreadable"
            return record
        if len(rows) != 1:
            record["reason"] = "ambiguous"
            return record
        row = rows[0]
        if sid_text(row.get("objectSid")) != sid:
            record["reason"] = "sid_mismatch"
            return record
        groups = [sid_text(value) for value in as_list(row.get("tokenGroups"))]
        if not groups or None in groups:
            record["reason"] = "unreadable"
            return record
        account["tokenGroups"] = groups
        history = [sid_text(value) for value in as_list(row.get("sIDHistory")) if sid_text(value)]
        if history:
            account["sIDHistory"] = history
        record.update(
            status="collected",
            sids=groups,
            collected_at=datetime.now(timezone.utc).isoformat(),
            group_count=len(groups),
        )
        return record
    except Exception as exc:
        record["reason"] = type(exc).__name__
        logger.debug("Assessment tokenGroups read failed: %s", record["reason"])
        return record


def resolve_assessment_identity(
    ldap: Any,
    users: list[dict[str, Any]] | None = None,
    groups: list[dict[str, Any]] | None = None,
    computers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Identify the bind account and attach token-group SIDs when readable."""
    del groups  # reserved for nested-group expansion from inventory
    username = str(getattr(ldap, "username", "") or "")
    who = read_who_am_i(ldap)
    parsed = parse_who_am_i(who) if who else {"sam": bind_sam(username), "dn": ""}
    sam = parsed.get("sam") or bind_sam(username)
    dn = parsed.get("dn") or ""
    principal = match_inventory_principal(users or [], computers or [], sam=sam, dn=dn)
    identity: dict[str, Any] = {
        "sam": ldap_scalar_text((principal or {}).get("sAMAccountName")) or sam,
        "dn": as_text((principal or {}).get("distinguishedName") or (principal or {}).get("dn")) or dn,
        "sid": sid_text((principal or {}).get("objectSid")) if principal else None,
        "who_am_i": who,
        "bind_username": username,
        "resolved": principal is not None,
        "kind": "computer" if principal and principal in (computers or []) else "user" if principal else "unknown",
        "token_groups": {"status": "skipped", "sids": []},
    }
    if principal is not None:
        identity["token_groups"] = collect_token_groups(ldap, principal)
    return identity

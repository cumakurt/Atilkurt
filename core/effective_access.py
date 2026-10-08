"""Bounded token-group reads to strengthen existing AD access calculations."""

from __future__ import annotations

from datetime import datetime, timezone
import time
from typing import Any

from core.ad_security import as_list, as_text, principal_group_tokens, sid_text
from core.exceptions import ValidationError


def collect_effective_tokens(
    ldap, data: dict[str, Any], risks: list[dict[str, Any]], *, limit: int = 50, delay: float = 0.1
) -> dict[str, Any]:
    if not 1 <= limit <= 500 or not 0 <= delay <= 60:
        raise ValidationError("Token collection limit or delay is out of range")
    accounts = [*(data.get("users") or []), *(data.get("computers") or [])]
    nested = principal_group_tokens(accounts, data.get("groups") or [])
    trustees = {
        as_text(risk.get("trustee") or (risk.get("evidence") or {}).get("trustee_sid"))
        for risk in risks
        if isinstance(risk.get("evidence") or {}, dict)
    }
    names = {
        str(risk.get("affected_object") or "").casefold()
        for risk in risks
        if "dcsync" in str(risk.get("type") or "") or risk.get("severity") == "critical"
    }
    selected = [
        account
        for account in accounts
        if sid_text(account.get("objectSid")) in trustees
        or nested.get(sid_text(account.get("objectSid")), set()) & trustees
        or as_text(account.get("sAMAccountName") or account.get("name")).casefold() in names
    ]
    records = []
    for index, account in enumerate(selected[:limit]):
        label = as_text(account.get("sAMAccountName") or account.get("name"))
        dn = as_text(account.get("distinguishedName") or account.get("dn"))
        record = {"principal": label, "sid": sid_text(account.get("objectSid")), "source": "ldap:tokenGroups"}
        account.pop("token_group_evidence", None)
        try:
            if not dn or not record['sid']:
                raise ValidationError("Principal DN or SID is unavailable")
            if index and delay:
                time.sleep(delay)
            rows = ldap.base_search(dn, ["tokenGroups", "objectSid", "sIDHistory"])
            row = rows[0] if len(rows) == 1 else {}
            if sid_text(row.get("objectSid")) != record["sid"]:
                raise ValidationError("Token response does not match the requested principal")
            values = as_list(row.get("tokenGroups"))
            groups = {sid_text(value) for value in values}
            if not values or None in groups:
                raise ValidationError("Token groups are absent, malformed, or not readable")
            account["tokenGroups"] = sorted(groups)
            account["sIDHistory"] = [sid_text(value) for value in as_list(row.get("sIDHistory")) if sid_text(value)]
            record.update(
                status="collected", collected_at=datetime.now(timezone.utc).isoformat(), group_count=len(groups)
            )
            account["token_group_evidence"] = dict(record)
        except Exception as exc:
            record.update(status="unknown", reason=type(exc).__name__)
            account["token_group_evidence"] = dict(record)
        records.append(record)
    return {
        "requested": len(selected),
        "collected": sum(row["status"] == "collected" for row in records),
        "limited": max(0, len(selected) - limit),
        "principals": records,
        "limitation": "Token groups strengthen group-based access checks. Conditional ACEs, claims and endpoint access still need independent validation.",
    }

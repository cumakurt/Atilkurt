"""Small, read-only helpers shared by modern AD security analyzers."""

from __future__ import annotations

from typing import Any
from uuid import UUID
from datetime import datetime, timedelta, timezone

from core.security_descriptor_parser import effective_allow_aces, parse_security_descriptor


BROAD_PRINCIPAL_SIDS = frozenset({
    "S-1-1-0",       # Everyone
    "S-1-5-11",      # Authenticated Users
    "S-1-5-32-545",  # BUILTIN\\Users
    "S-1-5-32-546",  # BUILTIN\\Guests
})

DANGEROUS_DIRECTORY_PERMISSIONS = frozenset({
    "GenericAll",
    "GenericWrite",
    "WriteDACL",
    "WriteOwner",
    "WriteProperty",
    "AllExtendedRights",
})


def filetime_utc(value: Any) -> datetime | None:
    """Decode AD FILETIME without local-time shifts or floating-point rounding."""
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    try:
        ticks = int(value)
        if ticks <= 0 or ticks == 0x7fffffffffffffff:
            return None
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)
    except (ValueError, OverflowError):
        return None


def as_list(value: Any) -> list[Any]:
    """Normalize a single- or multi-valued LDAP attribute."""
    if value in (None, ""):
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def as_text(value: Any) -> str:
    """Return the first LDAP value as trimmed text."""
    values = as_list(value)
    return str(values[0]).strip() if values else ""


def as_int(value: Any) -> int | None:
    """Parse an LDAP integer without inventing a default."""
    text = as_text(value)
    if not text:
        return None
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        return None


def truthy_ldap(value: Any) -> bool:
    """Interpret common LDAP boolean encodings."""
    return as_text(value).casefold() in {"1", "true", "yes"}


def security_descriptor_bytes(value: Any) -> bytes | None:
    """Normalize an LDAP security descriptor to bytes."""
    values = as_list(value)
    if not values:
        return None
    raw = values[0]
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, (bytearray, memoryview)):
        return bytes(raw)
    if isinstance(raw, str):
        try:
            return raw.encode("latin-1")
        except UnicodeEncodeError:
            return None
    return None


def parsed_security_descriptor(value: Any) -> dict[str, Any] | None:
    """Parse an LDAP security descriptor, returning ``None`` when unavailable."""
    raw = security_descriptor_bytes(value)
    if not raw:
        return None
    parsed = parse_security_descriptor(raw)
    if not parsed or not isinstance(parsed, dict) or parsed.get('parse_valid') is False:
        return None
    return parsed


def guid_text(raw: Any) -> str | None:
    """Convert a little-endian AD GUID byte sequence to canonical text."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 16:
        return None
    try:
        return str(UUID(bytes_le=bytes(raw)))
    except (ValueError, TypeError):
        return None


def sid_text(value: Any) -> str | None:
    """Normalize an SDDL or binary SID to its full string form."""
    values = as_list(value)
    if not values:
        return None
    raw = values[0]
    if isinstance(raw, str):
        text = raw.strip()
        return text if text.upper().startswith("S-") else None
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        return None
    data = bytes(raw)
    if len(data) < 8:
        return None
    count = data[1]
    if len(data) < 8 + (count * 4):
        return None
    authority = int.from_bytes(data[2:8], "big")
    parts = [f"S-{data[0]}-{authority}"]
    parts.extend(
        str(int.from_bytes(data[8 + index * 4:12 + index * 4], "little"))
        for index in range(count)
    )
    return "-".join(parts)


def ace_permission_names(ace: dict[str, Any]) -> set[str]:
    """Return permission labels emitted by ``SecurityDescriptorParser``."""
    permissions = ace.get("permissions") or {}
    return {str(name) for name in permissions} if isinstance(permissions, dict) else set()


def principal_group_tokens(accounts: list[dict[str, Any]], groups: list[dict[str, Any]]) -> dict[str, set[str]]:
    """Resolve collected direct, nested, and primary-group SIDs for access checks."""
    from core.ad_identity import is_security_group

    distribution_sids = {sid_text(group.get("objectSid")) for group in groups if not is_security_group(group)}
    objects = [*accounts, *groups]
    by_dn = {
        as_text(obj.get('distinguishedName') or obj.get('dn')).casefold(): sid_text(obj.get('objectSid'))
        for obj in objects if as_text(obj.get('distinguishedName') or obj.get('dn'))
    }
    parents: dict[str, set[str]] = {}
    for obj in objects:
        sid = sid_text(obj.get('objectSid'))
        if not sid or sid in distribution_sids:
            continue
        memberships = parents.setdefault(sid, set())
        for dn in as_list(obj.get('memberOf')):
            group_sid = by_dn.get(as_text(dn).casefold())
            if group_sid and group_sid not in distribution_sids:
                memberships.add(group_sid)
        primary = as_int(obj.get('primaryGroupID'))
        if primary is not None and sid.startswith('S-1-5-21-'):
            primary_sid = f'{sid.rsplit("-", 1)[0]}-{primary}'
            if primary_sid not in distribution_sids:
                memberships.add(primary_sid)
    for group in groups:
        group_sid = sid_text(group.get('objectSid'))
        if not group_sid or group_sid in distribution_sids:
            continue
        for dn in as_list(group.get('member')):
            member_sid = by_dn.get(as_text(dn).casefold())
            if member_sid:
                parents.setdefault(member_sid, set()).add(group_sid)
    tokens = {}
    for sid in parents:
        seen: set[str] = set()
        pending = list(parents[sid])
        while pending:
            parent = pending.pop()
            if parent in seen or parent == sid:
                continue
            seen.add(parent)
            pending.extend(parents.get(parent, set()) - seen)
        tokens[sid] = seen
    for account in accounts:
        sid = sid_text(account.get('objectSid'))
        if sid and (account.get('token_group_evidence') or {}).get('status') == 'collected':
            for value in as_list(account.get('tokenGroups')) + as_list(account.get('sIDHistory')):
                group_sid = sid_text(value)
                if group_sid and group_sid != sid:
                    tokens.setdefault(sid, set()).add(group_sid)
    return tokens


def dacl_fingerprint(parsed: dict[str, Any] | None) -> tuple[tuple[Any, ...], ...]:
    """Return an order-independent DACL fingerprint suitable for drift checks."""
    if not parsed:
        return ()
    rows: list[tuple[Any, ...]] = []
    for ace in parsed.get("dacl") or []:
        rows.append((
            ace.get("type"),
            ace.get("sid"),
            int(ace.get("access_mask") or 0),
            guid_text(ace.get("object_type")),
            guid_text(ace.get("inherited_object_type")),
            bool(ace.get("is_inherited")),
        ))
    return tuple(sorted(rows, key=lambda item: tuple(str(part) for part in item)))


def dangerous_broad_aces(parsed: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Return broad-principal ACEs that grant directory-control permissions."""
    findings: list[dict[str, Any]] = []
    if not parsed:
        return findings
    for ace in effective_allow_aces(parsed):
        permissions = ace_permission_names(ace)
        if (
            ace.get("sid") in BROAD_PRINCIPAL_SIDS
            and permissions.intersection(DANGEROUS_DIRECTORY_PERMISSIONS)
        ):
            findings.append(ace)
    return findings

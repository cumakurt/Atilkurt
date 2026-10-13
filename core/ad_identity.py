"""Helpers for matching well-known Active Directory identities.

Name matching uses the first RDN / sAMAccountName, never a substring of a DN.
Well-known RIDs remain valid when a group has been renamed.
"""

from __future__ import annotations

from typing import Any
from core.ad_security import as_list, sid_text

DOMAIN_ADMINS_RID = 512
DOMAIN_CONTROLLERS_RID = 516
SCHEMA_ADMINS_RID = 518
ENTERPRISE_ADMINS_RID = 519
GROUP_POLICY_CREATOR_OWNERS_RID = 520
ADMINISTRATORS_RID = 544
ACCOUNT_OPERATORS_RID = 548
SERVER_OPERATORS_RID = 549
PRINT_OPERATORS_RID = 550
BACKUP_OPERATORS_RID = 551
REPLICATOR_RID = 552

ROLE_DOMAIN_ADMINS = "Domain Admins"
ROLE_ENTERPRISE_ADMINS = "Enterprise Admins"
ROLE_SCHEMA_ADMINS = "Schema Admins"
ROLE_ADMINISTRATORS = "Administrators"
ROLE_ACCOUNT_OPERATORS = "Account Operators"
ROLE_BACKUP_OPERATORS = "Backup Operators"
ROLE_SERVER_OPERATORS = "Server Operators"
ROLE_PRINT_OPERATORS = "Print Operators"
ROLE_DOMAIN_CONTROLLERS = "Domain Controllers"
ROLE_REPLICATOR = "Replicator"
ROLE_DNS_ADMINS = "DnsAdmins"
ROLE_GROUP_POLICY_CREATOR_OWNERS = "Group Policy Creator Owners"

ROLE_RIDS: dict[str, int] = {
    ROLE_DOMAIN_ADMINS: DOMAIN_ADMINS_RID,
    ROLE_DOMAIN_CONTROLLERS: DOMAIN_CONTROLLERS_RID,
    ROLE_SCHEMA_ADMINS: SCHEMA_ADMINS_RID,
    ROLE_ENTERPRISE_ADMINS: ENTERPRISE_ADMINS_RID,
    ROLE_GROUP_POLICY_CREATOR_OWNERS: GROUP_POLICY_CREATOR_OWNERS_RID,
    ROLE_ADMINISTRATORS: ADMINISTRATORS_RID,
    ROLE_ACCOUNT_OPERATORS: ACCOUNT_OPERATORS_RID,
    ROLE_SERVER_OPERATORS: SERVER_OPERATORS_RID,
    ROLE_PRINT_OPERATORS: PRINT_OPERATORS_RID,
    ROLE_BACKUP_OPERATORS: BACKUP_OPERATORS_RID,
    ROLE_REPLICATOR: REPLICATOR_RID,
}

PRIVILEGED_GROUP_RIDS = frozenset(ROLE_RIDS.values())
_DOMAIN_PRIVILEGED_RIDS = frozenset(rid for rid in PRIVILEGED_GROUP_RIDS if rid < 544)
_BUILTIN_PRIVILEGED_RIDS = frozenset(rid for rid in PRIVILEGED_GROUP_RIDS if rid >= 544)

_PRIVILEGED_GROUP_NAMES = frozenset({
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
    "server operators",
    "print operators",
    "domain controllers",
    "replicator",
    "dnsadmins",
    "dns admins",
    "group policy creator owners",
})


def sid_rid(value: Any) -> int | None:
    """Return the RID of an SDDL SID, binary SID, or nested LDAP value."""
    if isinstance(value, (list, tuple)):
        if not value:
            return None
        value = value[0]
    if value is None or value == "":
        return None
    if isinstance(value, bytes):
        if len(value) < 8:
            return None
        return int.from_bytes(value[-4:], "little")
    text = str(value).strip()
    if not text:
        return None
    upper = text.upper()
    if upper.startswith("S-"):
        try:
            return int(text.rsplit("-", 1)[-1])
        except ValueError:
            return None
    return None


def first_ldap_rdn(value: Any) -> str:
    """Return the first RDN value (CN=...) or the raw name when no DN is present."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    text = str(value or "").strip()
    if not text or text.upper().startswith("S-1-"):
        return ""
    first = text.split(",", 1)[0].strip()
    if "=" in first:
        return first.split("=", 1)[1].strip()
    return first


def is_privileged_group_name(name: Any) -> bool:
    """Return True when a display name or SAM matches a well-known privileged group."""
    text = str(name or "").strip()
    if not text:
        return False
    return text.casefold() in _PRIVILEGED_GROUP_NAMES


def is_privileged_group_record(group: dict[str, Any] | None) -> bool:
    """Return True when a collected group is a well-known privileged group."""
    if not group:
        return False
    sid = sid_text(group.get('objectSid'))
    if sid:
        return any(group_is_role(group, role) for role in ROLE_RIDS) or any(
            str(group.get(key) or '').casefold() in {'dnsadmins', 'dns admins'}
            for key in ('name', 'sAMAccountName')
        )
    for key in ("name", "sAMAccountName"):
        if is_privileged_group_name(group.get(key)):
            return True
    return is_privileged_group_name(
        first_ldap_rdn(group.get("distinguishedName") or group.get("dn"))
    )


def group_is_role(group: dict[str, Any], role_name: str) -> bool:
    """Return True if the group is the named well-known privileged group."""
    expected_rid = ROLE_RIDS.get(role_name)
    sid = sid_text(group.get('objectSid'))
    if expected_rid is not None and sid:
        # Names can be copied or renamed. A present SID is authoritative, and
        # built-in group RIDs are meaningful only in the BUILTIN authority.
        if expected_rid >= 544:
            return sid == f'S-1-5-32-{expected_rid}'
        return sid.startswith('S-1-5-21-') and len(sid.split('-')) == 8 and sid_rid(sid) == expected_rid
    target = role_name.casefold()
    for key in ("name", "sAMAccountName"):
        candidate = group.get(key)
        if candidate and str(candidate).strip().casefold() == target:
            return True
    rdn = first_ldap_rdn(group.get("distinguishedName") or group.get("dn"))
    return bool(rdn) and rdn.casefold() == target


def sid_is_domain_well_known(value: Any, rids: frozenset[int]) -> bool:
    """Return True for a domain SID whose RID is in the given well-known set.

    Built-in RIDs such as 544 live in S-1-5-32. A domain principal that happens
    to end in the same number is not that group.
    """
    text = str(value or "").strip()
    rid = sid_rid(text)
    return (
        rid in rids
        and text.upper().startswith("S-1-5-21-")
        and len(text.split("-")) == 8
    )


def sid_is_builtin_privileged(value: Any) -> bool:
    """Return True only for an exact BUILTIN privileged group SID."""
    text = str(value or "").strip()
    rid = sid_rid(text)
    return rid in _BUILTIN_PRIVILEGED_RIDS and text.upper() == f"S-1-5-32-{rid}"


def is_privileged_principal_reference(value: Any) -> bool:
    """Return True when a DN, name, or SID refers to a privileged group or krbtgt."""
    if sid_is_domain_well_known(value, _DOMAIN_PRIVILEGED_RIDS) or sid_is_builtin_privileged(value):
        return True
    name = first_ldap_rdn(value)
    if not name:
        return False
    return is_privileged_group_name(name) or name.casefold() in {"krbtgt", "administrator"}


def account_has_privileged_evidence(account: dict[str, Any] | None) -> bool:
    """Return True when adminCount or exact privileged-group membership is present.

    adminCount alone means AdminSDHolder still treats the account as protected.
    It does not prove the account is currently in a privileged group. Callers
    that need current privilege should use ``account_has_current_privileged_membership``.
    """
    if not account:
        return False
    if str(account.get("adminCount") or "").strip().lower() in {"1", "true"}:
        return True
    return account_has_current_privileged_membership(account)


def account_has_current_privileged_membership(account: dict[str, Any] | None) -> bool:
    """Return True only for a current well-known privileged group.

    primaryGroupID is the RID of the account's primary group. Active Directory
    omits that group from memberOf, so the RID is checked separately. A stale
    adminCount flag is not current membership.
    """
    if not account:
        return False
    if any(is_privileged_group_name(name) for name in membership_names(account.get("memberOf"))):
        return True
    raw = account.get("primaryGroupID")
    try:
        rid = int(raw)
    except (TypeError, ValueError):
        return False
    return rid in {DOMAIN_ADMINS_RID, ENTERPRISE_ADMINS_RID, SCHEMA_ADMINS_RID}


def nested_privileged_groups(
    account: dict[str, Any] | None,
    groups: list[dict[str, Any]] | None = None,
    *,
    max_hops: int = 8,
) -> list[str]:
    """Return well-known privileged groups reachable through nested memberOf.

    The walk uses collected group records only. Direct membership is included.
    Cycles and very deep nesting stop at ``max_hops``.
    """
    if not account:
        return []
    from collections import deque

    records = [group for group in groups or [] if isinstance(group, dict)]
    by_dn = {
        str(group.get("distinguishedName") or group.get("dn") or "").casefold(): group
        for group in records if group.get("distinguishedName") or group.get("dn")
    }
    by_name: dict[str, list[dict]] = {}
    for group in records:
        for name in {str(group.get(key) or "").casefold() for key in ("name", "sAMAccountName", "cn")} - {""}:
            by_name.setdefault(name, []).append(group)
    queue = deque((item, 0) for item in as_list(account.get("memberOf")))
    account_dn = str(account.get("distinguishedName") or account.get("dn") or "").casefold()
    account_sid = sid_text(account.get("objectSid"))
    primary = str(account.get("primaryGroupID") or "")
    for group in records:
        members = {str(item).casefold() for item in as_list(group.get("member"))}
        group_sid = sid_text(group.get("objectSid"))
        if (account_dn and account_dn in members) or (
            account_sid and primary and group_sid == account_sid.rsplit("-", 1)[0] + "-" + primary
        ):
            queue.append((group.get("distinguishedName") or group.get("name"), 0))
    found: list[str] = []
    visited: set[str] = set()
    while queue:
        item, depth = queue.popleft()
        token = str(item or "").strip()
        folded = token.casefold()
        if not token or folded in visited:
            continue
        visited.add(folded)
        # A DN never falls back to a same-CN object in another OU.
        candidates = [by_dn[folded]] if folded in by_dn else (
            by_name.get(folded, []) if "=" not in token else []
        )
        group = candidates[0] if len(candidates) == 1 else None
        if group and not is_security_group(group):
            continue
        name = first_ldap_rdn(token) or token
        privileged = is_privileged_group_record(group) if group else (
            not candidates and is_privileged_group_name(name)
        )
        if privileged:
            label = str((group or {}).get("name") or name)
            if label not in found:
                found.append(label)
        if group and depth < max_hops:
            queue.extend((parent, depth + 1) for parent in as_list(group.get("memberOf")))
    return found


def membership_names(value: Any) -> set[str]:
    """Normalize memberOf / member values to casefolded first-RDN names."""
    names: set[str] = set()
    for item in as_list(value):
        name = first_ldap_rdn(item)
        if name:
            names.add(name.casefold())
    return names


def privileged_membership_values(value: Any) -> list[Any]:
    """Return memberOf values whose first RDN is a well-known privileged group.

    Matching uses the first RDN only. A group stored under OU=Domain Admins is
    not treated as Domain Admins.
    """
    matches: list[Any] = []
    for item in as_list(value):
        if is_privileged_group_name(first_ldap_rdn(item)):
            matches.append(item)
    return matches


def ldap_scalar_text(value: Any) -> str:
    """Return a single LDAP attribute as text."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    if value is None:
        return ""
    return str(value).strip()


def root_dse_attributes(ldap: Any, attributes: list[str]) -> dict[str, Any]:
    """Read RootDSE values from ldap3's bound-server metadata when available.

    RootDSE operational attributes are not part of the directory schema.  With
    ldap3 name checking enabled, asking for them through a normal object search
    can therefore raise ``invalid attribute type`` even though the values were
    already returned while binding with ``get_info=ALL``.
    """
    connection = getattr(ldap, "connection", None)
    server = getattr(connection, "server", None)
    info = getattr(server, "info", None)
    other = getattr(info, "other", None)
    if other is not None:
        row: dict[str, Any] = {}
        for attribute in attributes:
            if attribute.casefold() == "namingcontexts":
                value = getattr(info, "naming_contexts", None)
            else:
                try:
                    value = other.get(attribute)
                except (AttributeError, TypeError):
                    value = None
            if value is not None:
                row[attribute] = value
        return row

    # Test doubles and LDAP wrappers other than LDAPConnection may not expose
    # ldap3 server metadata, so retain the portable RootDSE search fallback.
    try:
        rows = ldap.search(
            search_base="",
            search_filter="(objectClass=*)",
            attributes=attributes,
            size_limit=1,
        ) or []
    except Exception:
        return {}
    return rows[0] if rows else {}


def schema_supports_attribute(ldap: Any, attribute: str) -> bool | None:
    """Return schema support for an attribute, or None if schema is unavailable."""
    connection = getattr(ldap, "connection", None)
    server = getattr(connection, "server", None)
    schema = getattr(server, "schema", None)
    attribute_types = getattr(schema, "attribute_types", None)
    if attribute_types is None:
        return None
    return attribute in attribute_types


def schema_supports_object_class(ldap: Any, object_class: str) -> bool | None:
    """Return schema support for an object class, or None if unavailable."""
    connection = getattr(ldap, "connection", None)
    server = getattr(connection, "server", None)
    schema = getattr(server, "schema", None)
    object_classes = getattr(schema, "object_classes", None)
    if object_classes is None:
        return None
    return object_class in object_classes


def forest_configuration_dn(ldap: Any) -> str | None:
    """Return configurationNamingContext from RootDSE.

    Child-domain base DNs must not be prefixed with CN=Configuration; the forest
    configuration naming context is only authoritative from RootDSE.
    """
    root = root_dse_attributes(ldap, ["configurationNamingContext"])
    text = ldap_scalar_text(root.get("configurationNamingContext"))
    return text or None


def _uac_value(value: Any) -> int | None:
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def computer_is_domain_controller(computer: dict[str, Any] | None) -> bool:
    """Return True when UAC, primary group, or OU evidence shows a DC.

    A hostname that merely contains the letters DC (for example ADCS01) is not
    treated as a domain controller.
    """
    if not computer:
        return False
    uac = _uac_value(computer.get("userAccountControl"))
    if uac is not None and uac & 0x2000:  # SERVER_TRUST_ACCOUNT
        return True
    primary_rid = _uac_value(computer.get("primaryGroupID"))
    if primary_rid == DOMAIN_CONTROLLERS_RID:
        return True
    compact_dn = "".join(
        ldap_scalar_text(computer.get("distinguishedName") or computer.get("dn")).upper().split()
    )
    return ",OU=DOMAINCONTROLLERS," in f",{compact_dn},"


def computer_has_unexpected_unconstrained_delegation(computer: dict[str, Any] | None) -> bool:
    """Return True when unconstrained delegation is not the DC default.

    Domain controllers are trusted for delegation by design. A disabled
    computer cannot accept delegated authentication, so that flag is not an
    active finding either.
    """
    if not computer or computer_is_domain_controller(computer):
        return False
    if computer.get("isDisabled") is True:
        return False
    uac = _uac_value(computer.get("userAccountControl"))
    if uac is not None and uac & 0x2:  # ACCOUNTDISABLE
        return False
    # A readable UAC value is authoritative. The boolean is only a fallback
    # when the flag itself was not collected.
    if uac is not None:
        return bool(uac & 0x80000)  # TRUSTED_FOR_DELEGATION
    return bool(computer.get("unconstrainedDelegation"))


def is_security_group(group: dict[str, Any]) -> bool:
    """Distribution groups cannot grant token rights; old snapshots may omit type."""
    raw = group.get("groupType")
    if raw is None:
        return True
    try:
        return bool(int(raw) & 0x80000000)
    except (TypeError, ValueError):
        return False


TIER0_ROLES = frozenset({ROLE_DOMAIN_ADMINS, ROLE_ENTERPRISE_ADMINS, ROLE_SCHEMA_ADMINS, ROLE_ADMINISTRATORS, ROLE_DOMAIN_CONTROLLERS})


def is_tier0_group_record(group: dict[str, Any]) -> bool:
    """DNS/operator administration is sensitive, but is not itself Domain Admin."""
    return is_security_group(group) and any(group_is_role(group, role) for role in TIER0_ROLES)

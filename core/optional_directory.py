"""Discover optional directory containers without hiding LDAP failures."""

from typing import Any

from ldap3.utils.conv import escape_filter_chars


def optional_subtree(ldap: Any, root: str, base: str, **kwargs: Any) -> list[dict]:
    """Search a visible optional container, probing from an existing naming context.

    An empty discovery means not observed with this token, not proof of absence.
    Permission, network, and schema errors propagate to the query audit.
    """
    present = ldap.search(
        search_base=root,
        search_filter=f"(distinguishedName={escape_filter_chars(base)})",
        attributes=["distinguishedName"],
    )
    if not present:
        return []
    return ldap.search(search_base=base, **kwargs) or []

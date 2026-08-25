"""LDAP directory exposure and anonymous-enumeration attack surface."""

from __future__ import annotations

import logging
from typing import Any

from core.ad_identity import root_dse_attributes
from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)

PRE_WIN2K_GROUP = "PRE-WINDOWS 2000 COMPATIBLE ACCESS"
DANGEROUS_PRE_WIN2K_PRINCIPALS = (
    "EVERYONE",
    "ANONYMOUS LOGON",
    "AUTHENTICATED USERS",
    "S-1-1-0",
    "S-1-5-7",
    "S-1-5-11",
)
FUNCTIONAL_LEVEL_LABELS = {
    0: "Windows 2000",
    1: "Windows Server 2003 interim",
    2: "Windows Server 2003",
    3: "Windows Server 2008",
    4: "Windows Server 2008 R2",
    5: "Windows Server 2012",
    6: "Windows Server 2012 R2",
    7: "Windows Server 2016",
    10: "Windows Server 2025",
}


class LDAPDirectoryExposureAnalyzer:
    """Detect LDAP anonymous access, legacy compatible-access, and outdated forest levels."""

    def __init__(self, ldap_connection: Any):
        self.ldap = ldap_connection

    def analyze(self, users: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        """Return directory-exposure findings from RootDSE, dsHeuristics, and well-known accounts."""
        risks: list[dict[str, Any]] = []
        checks = (
            self._check_dsheuristics,
            self._check_pre_windows_2000_access,
            lambda: self._check_guest_account(users),
            self._check_functional_level,
        )
        for check in checks:
            risks.extend(check())
        logger.info("Found %d LDAP directory exposure risks", len(risks))
        return risks

    def _search(
        self,
        search_filter: str,
        attributes: list[str],
        search_base: str | None = None,
        size_limit: int = 0,
    ) -> list[dict[str, Any]]:
        base = self.ldap.base_dn if search_base is None else search_base
        try:
            return self.ldap.search(
                search_base=base,
                search_filter=search_filter,
                attributes=attributes,
                size_limit=size_limit,
            ) or []
        except TypeError:
            try:
                return self.ldap.search(base, search_filter, attributes) or []
            except Exception as exc:
                logger.debug("LDAP search failed for %s: %s", search_filter, exc)
                return []
        except Exception as exc:
            logger.debug("LDAP search failed for %s: %s", search_filter, exc)
            return []

    def _rootdse(self) -> dict[str, Any]:
        return root_dse_attributes(
            self.ldap,
            [
                "configurationNamingContext",
                "defaultNamingContext",
                "domainFunctionality",
                "forestFunctionality",
                "domainControllerFunctionality",
            ],
        )

    def _as_text(self, value: Any) -> str:
        if isinstance(value, (list, tuple)):
            value = value[0] if value else ""
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        return str(value)

    def _as_int(self, value: Any) -> int | None:
        text = self._as_text(value)
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            return None

    def _check_dsheuristics(self) -> list[dict[str, Any]]:
        risks: list[dict[str, Any]] = []
        root = self._rootdse()
        config_dn = self._as_text(root.get("configurationNamingContext"))
        if not config_dn:
            logger.debug("Skipping dSHeuristics check: configuration naming context is unavailable")
            return risks
        ds_dn = f"CN=Directory Service,CN=Windows NT,CN=Services,{config_dn}"
        rows = self._search("(objectClass=*)", ["dSHeuristics", "cn"], search_base=ds_dn, size_limit=1)
        heuristics = self._as_text((rows[0] if rows else {}).get("dSHeuristics"))
        if len(heuristics) >= 7 and heuristics[6] == "2":
            risks.append(self._risk(
                RiskTypes.LDAP_ANONYMOUS_ENABLED,
                Severity.CRITICAL,
                "Anonymous LDAP operations are enabled (dSHeuristics)",
                (
                    f"dSHeuristics is set to '{heuristics}'. Character 7 equals 2, which allows "
                    "anonymous LDAP operations against directory objects permitted by ACLs."
                ),
                ds_dn,
                "configuration",
                "Anonymous binds enable unauthenticated reconnaissance of users, groups, and attributes used for targeting.",
                "Clear dSHeuristics character 7 or restore the Microsoft-recommended value that disables anonymous LDAP. Verify anonymous binds fail.",
            ))
        return risks

    def _check_pre_windows_2000_access(self) -> list[dict[str, Any]]:
        risks: list[dict[str, Any]] = []
        rows = self._search(
            "(&(objectClass=group)(cn=Pre-Windows 2000 Compatible Access))",
            ["cn", "member", "distinguishedName"],
            size_limit=5,
        )
        if not rows:
            return risks
        members = rows[0].get("member") or []
        if not isinstance(members, list):
            members = [members]
        matched = []
        for member in members:
            upper = str(member).upper()
            if any(token in upper for token in DANGEROUS_PRE_WIN2K_PRINCIPALS):
                matched.append(str(member))
        if not matched:
            return risks
        everyone = any(
            "EVERYONE" in item.upper() or "S-1-1-0" in item.upper() or "ANONYMOUS" in item.upper()
            for item in matched
        )
        risks.append(self._risk(
            RiskTypes.LDAP_PREWIN2K_BROAD_MEMBERSHIP,
            Severity.HIGH if everyone else Severity.MEDIUM,
            "Pre-Windows 2000 Compatible Access includes broad principals",
            (
                "The Pre-Windows 2000 Compatible Access group contains "
                + ", ".join(matched[:8])
                + ". This legacy right grants extensive directory read access and remains a primary LDAP enumeration path."
            ),
            str(rows[0].get("cn") or PRE_WIN2K_GROUP),
            "group",
            "Authenticated Users or Everyone in this group lets any domain user list users, groups, and attributes used for password spraying.",
            "Remove Everyone, Anonymous Logon, and Authenticated Users from Pre-Windows 2000 Compatible Access.",
        ))
        return risks

    def _check_guest_account(self, users: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        risks: list[dict[str, Any]] = []
        candidates: list[dict[str, Any]] = []
        seen: set[str] = set()

        def add_candidate(row: dict[str, Any]) -> None:
            key = str(row.get("objectSid") or row.get("sAMAccountName") or row.get("distinguishedName") or id(row))
            if key in seen:
                return
            seen.add(key)
            candidates.append(row)

        for user in users or []:
            rid = self._sid_rid(user.get("objectSid"))
            name = str(user.get("sAMAccountName") or "").lower()
            if rid == 501 or name in {"guest", "misafir"}:
                add_candidate(user)

        if not candidates:
            rows = self._search(
                "(&(objectClass=user)(objectCategory=person)(|(sAMAccountName=Guest)(sAMAccountName=Misafir)))",
                ["sAMAccountName", "userAccountControl", "distinguishedName", "objectSid"],
                size_limit=5,
            )
            for row in rows:
                add_candidate(row)

        for row in candidates:
            try:
                uac = int(row.get("userAccountControl") or 0)
            except (TypeError, ValueError):
                uac = 0
            if uac & 0x2:
                continue
            name = row.get("sAMAccountName") or "Guest"
            risks.append(self._risk(
                RiskTypes.LDAP_GUEST_ENABLED,
                Severity.HIGH,
                f"Guest account is enabled: {name}",
                "The built-in Guest account (RID-501) is enabled. Guest expands LDAP and SMB enumeration options.",
                str(name),
                "user",
                "An enabled Guest account is a foothold for anonymous-style access.",
                "Disable Guest, deny interactive logon, and monitor logon events for RID-501.",
            ))
        return risks

    @staticmethod
    def _sid_rid(sid: Any) -> int | None:
        """Return the RID portion of an SDDL SID string."""
        text = str(sid or "")
        if not text:
            return None
        try:
            return int(text.rsplit("-", 1)[-1])
        except ValueError:
            return None

    def _check_functional_level(self) -> list[dict[str, Any]]:
        risks: list[dict[str, Any]] = []
        root = self._rootdse()
        domain_level = self._as_int(root.get("domainFunctionality"))
        forest_level = self._as_int(root.get("forestFunctionality"))
        if domain_level is None:
            domain_rows = self._search(
                "(objectClass=domainDNS)",
                ["msDS-Behavior-Version", "distinguishedName"],
                size_limit=1,
            )
            if domain_rows:
                domain_level = self._as_int(domain_rows[0].get("msDS-Behavior-Version"))
        for label, level in (("Domain", domain_level), ("Forest", forest_level)):
            if level is None or level >= 7:
                continue
            level_name = FUNCTIONAL_LEVEL_LABELS.get(level, f"unknown ({level})")
            risks.append(self._risk(
                RiskTypes.LDAP_LEGACY_FUNCTIONAL_LEVEL,
                Severity.MEDIUM,
                f"{label} functional level is outdated: {level_name}",
                (
                    f"The {label.lower()} functional level is {level_name}. Legacy functional levels "
                    "keep older Kerberos, ACL, and replication behaviors available."
                ),
                self.ldap.base_dn,
                "configuration",
                "Outdated functional levels block modern hardening features such as Authentication Policies and newer Kerberos protections.",
                "Raise domain and forest functional levels to at least Windows Server 2016 after confirming DC support.",
            ))
        return risks

    @staticmethod
    def _risk(
        risk_type: str,
        severity: str,
        title: str,
        description: str,
        affected_object: str,
        object_type: str,
        impact: str,
        mitigation: str,
    ) -> dict[str, Any]:
        return {
            "type": risk_type,
            "severity": severity,
            "title": title,
            "description": description,
            "affected_object": affected_object,
            "object_type": object_type,
            "impact": impact,
            "attack_scenario": impact,
            "mitigation": mitigation,
            "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
        }

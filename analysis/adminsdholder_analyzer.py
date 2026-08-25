"""AdminSDHolder and SDProp drift assessment."""

from __future__ import annotations

import logging
from typing import Any

from core.ad_identity import is_privileged_group_record
from core.ad_security import (
    ace_permission_names,
    as_list,
    as_text,
    dacl_fingerprint,
    dangerous_broad_aces,
    parsed_security_descriptor,
)
from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)


class AdminSDHolderAnalyzer:
    """Compare protected-object ACL state with the AdminSDHolder template."""

    def __init__(self, ldap_connection: Any):
        self.ldap = ldap_connection

    def analyze(
        self,
        users: list[dict[str, Any]],
        groups: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        admin_dn = f"CN=AdminSDHolder,CN=System,{self.ldap.base_dn}"
        try:
            admin_rows = self.ldap.search(
                search_base=admin_dn,
                search_filter="(objectClass=*)",
                attributes=["distinguishedName", "nTSecurityDescriptor"],
                size_limit=1,
            ) or []
        except Exception as exc:
            logger.debug("AdminSDHolder template search failed: %s", exc)
            return []
        if not admin_rows:
            return []

        admin_sd = parsed_security_descriptor(admin_rows[0].get("nTSecurityDescriptor"))
        risks: list[dict[str, Any]] = []
        for ace in dangerous_broad_aces(admin_sd):
            permissions = sorted(ace_permission_names(ace))
            risks.append({
                "type": RiskTypes.ADMINSDHOLDER_DANGEROUS_ACE,
                "severity": Severity.CRITICAL,
                "title": f"Broad principal {ace.get('sid')} controls AdminSDHolder",
                "description": (
                    "AdminSDHolder grants a broad principal dangerous permissions. SDProp can propagate "
                    "this access to protected users and groups."
                ),
                "affected_object": admin_dn,
                "object_type": "configuration",
                "impact": "A single template ACE can grant control over every protected administrative identity.",
                "attack_scenario": "An attacker uses the propagated permission to reset, modify, or persist on a privileged account.",
                "mitigation": "Remove the broad ACE, restore an approved AdminSDHolder DACL, and force/verify SDProp convergence.",
                "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
                "evidence": {"trustee_sid": ace.get("sid"), "permissions": permissions},
            })

        try:
            protected_rows = self.ldap.search(
                search_base=self.ldap.base_dn,
                search_filter="(adminCount=1)",
                attributes=[
                    "sAMAccountName", "cn", "distinguishedName", "objectClass",
                    "memberOf", "adminCount", "nTSecurityDescriptor",
                ],
            ) or []
        except Exception as exc:
            logger.debug("SDProp protected-object search failed: %s", exc)
            return risks

        expected_dns = self._expected_protected_dns(users, groups)
        orphaned: list[str] = []
        inherited: list[str] = []
        drifted: list[str] = []
        template_fingerprint = dacl_fingerprint(admin_sd)

        for row in protected_rows:
            dn = as_text(row.get("distinguishedName"))
            name = as_text(row.get("sAMAccountName") or row.get("cn") or dn) or "protected object"
            parsed = parsed_security_descriptor(row.get("nTSecurityDescriptor"))
            if dn and dn.casefold() not in expected_dns:
                orphaned.append(name)
            if parsed and not parsed.get("is_protected"):
                inherited.append(name)
            fingerprint = dacl_fingerprint(parsed)
            if template_fingerprint and fingerprint and fingerprint != template_fingerprint:
                drifted.append(name)

        if orphaned:
            risks.append(self._summary_risk(
                RiskTypes.ADMINSDHOLDER_ORPHANED_ADMINCOUNT,
                Severity.MEDIUM,
                f"{len(orphaned)} objects retain adminCount=1 outside the protected membership graph",
                "The objects are no longer reachable from the collected protected-group membership graph but retain SDProp markers.",
                orphaned,
                {"object_count": len(orphaned)},
            ))
        if inherited:
            risks.append(self._summary_risk(
                RiskTypes.ADMINSDHOLDER_INHERITANCE_ENABLED,
                Severity.HIGH,
                f"ACL inheritance is enabled on {len(inherited)} protected objects",
                "Protected objects should normally have a protected DACL maintained through AdminSDHolder/SDProp.",
                inherited,
                {"object_count": len(inherited)},
            ))
        if drifted:
            risks.append(self._summary_risk(
                RiskTypes.ADMINSDHOLDER_ACL_DRIFT,
                Severity.HIGH,
                f"{len(drifted)} protected objects drift from the AdminSDHolder allowed-ACE template",
                "The parsed allowed ACE set differs from the current AdminSDHolder template and requires SDProp or ACL investigation.",
                drifted,
                {"object_count": len(drifted), "comparison": "allowed_ace_fingerprint"},
            ))
        return risks

    @staticmethod
    def _expected_protected_dns(
        users: list[dict[str, Any]], groups: list[dict[str, Any]],
    ) -> set[str]:
        group_by_dn = {
            as_text(group.get("distinguishedName") or group.get("dn")).casefold(): group
            for group in groups if as_text(group.get("distinguishedName") or group.get("dn"))
        }
        expected = {
            dn for dn, group in group_by_dn.items() if is_privileged_group_record(group)
        }
        queue = list(expected)
        while queue:
            group_dn = queue.pop()
            group = group_by_dn.get(group_dn)
            if not group:
                continue
            for member in as_list(group.get("member")):
                member_dn = as_text(member).casefold()
                if member_dn and member_dn not in expected:
                    expected.add(member_dn)
                    if member_dn in group_by_dn:
                        queue.append(member_dn)
        # Collected memberOf evidence protects against incomplete `member`
        # attributes from constrained directory views.
        privileged_group_dns = {
            dn for dn, group in group_by_dn.items() if is_privileged_group_record(group)
        }
        for obj in [*users, *groups]:
            dn = as_text(obj.get("distinguishedName") or obj.get("dn")).casefold()
            memberships = {as_text(item).casefold() for item in as_list(obj.get("memberOf"))}
            if dn and memberships.intersection(privileged_group_dns):
                expected.add(dn)
        return expected

    @staticmethod
    def _summary_risk(risk_type: str, severity: str, title: str, description: str,
                      names: list[str], evidence: dict[str, Any]) -> dict[str, Any]:
        ordered = sorted(set(names), key=str.casefold)
        affected = ", ".join(ordered[:15]) + (f" ... (+{len(ordered) - 15} more)" if len(ordered) > 15 else "")
        return {
            "type": risk_type,
            "severity": severity,
            "title": title,
            "description": description,
            "affected_object": affected,
            "object_type": "configuration",
            "impact": "Incorrect SDProp protection can leave privileged objects overexposed or preserve stale administrative controls.",
            "attack_scenario": "An attacker abuses an unexpected ACE or inheritance path on a protected identity.",
            "mitigation": "Validate protected membership, restore approved ACLs, clear stale adminCount only after review, and verify SDProp.",
            "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
            "evidence": evidence,
        }

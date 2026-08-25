"""Authentication Policy and Authentication Policy Silo assessment."""

from __future__ import annotations

import logging
from typing import Any

from core.ad_identity import account_has_privileged_evidence, forest_configuration_dn
from core.ad_security import as_int, as_text, truthy_ldap
from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)


class AuthenticationPolicyAnalyzer:
    """Assess high-value credential restrictions stored in AD DS."""

    MAX_PRIVILEGED_TGT_SECONDS = 4 * 60 * 60

    def __init__(self, ldap_connection: Any):
        self.ldap = ldap_connection

    def analyze(self, users: list[dict[str, Any]]) -> list[dict[str, Any]]:
        config_dn = forest_configuration_dn(self.ldap)
        if not config_dn:
            return []

        silos = self._search(
            config_dn,
            "(objectClass=msDS-AuthNPolicySilo)",
            [
                "cn", "distinguishedName", "msDS-AuthNPolicySiloEnforced",
                "msDS-AuthNPolicySiloMembers", "msDS-UserAuthNPolicy",
                "msDS-ComputerAuthNPolicy", "msDS-ServiceAuthNPolicy",
            ],
        )
        policies = self._search(
            config_dn,
            "(objectClass=msDS-AuthNPolicy)",
            [
                "cn", "distinguishedName", "msDS-AuthNPolicyEnforced",
                "msDS-UserTGTLifetime", "msDS-ServiceTGTLifetime",
                "msDS-ComputerTGTLifetime", "msDS-UserAllowedToAuthenticateFrom",
                "msDS-UserAllowedToAuthenticateTo",
                "msDS-ServiceAllowedToAuthenticateFrom",
                "msDS-ServiceAllowedToAuthenticateTo",
            ],
        )

        # An absent schema/object class yields an empty search on supported test
        # doubles and a handled invalid-attribute/object-class error on AD.
        if silos is None and policies is None:
            return []
        silos = silos or []
        policies = policies or []
        risks: list[dict[str, Any]] = []

        if not silos and not policies:
            privileged = [u for u in users if account_has_privileged_evidence(u)]
            if privileged:
                risks.append({
                    "type": RiskTypes.AUTH_POLICY_NOT_DEPLOYED,
                    "severity": Severity.MEDIUM,
                    "title": "Authentication policies are not deployed",
                    "description": (
                        f"{len(privileged)} privileged account(s) were identified, but no Authentication "
                        "Policy or Authentication Policy Silo object was found in the forest."
                    ),
                    "affected_object": self.ldap.base_dn,
                    "object_type": "configuration",
                    "impact": "High-value credentials are not constrained to approved hosts and services by AD authentication policy.",
                    "attack_scenario": "A stolen privileged credential can be replayed from a broader set of systems.",
                    "mitigation": "Pilot Authentication Policy Silos in audit mode, validate events, then enforce them for Tier-0 identities.",
                    "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
                    "evidence": {"privileged_account_count": len(privileged)},
                })
            return risks

        valid_policy_dns = {
            as_text(item.get("distinguishedName")).casefold()
            for item in policies if as_text(item.get("distinguishedName"))
        }
        valid_silo_dns = {
            as_text(item.get("distinguishedName")).casefold()
            for item in silos if as_text(item.get("distinguishedName"))
        }

        for silo in silos:
            name = as_text(silo.get("cn") or silo.get("distinguishedName")) or "Authentication Policy Silo"
            if not truthy_ldap(silo.get("msDS-AuthNPolicySiloEnforced")):
                risks.append(self._risk(
                    RiskTypes.AUTH_POLICY_AUDIT_ONLY,
                    Severity.MEDIUM,
                    f'Authentication Policy Silo "{name}" is audit-only',
                    "The silo records audit events but does not enforce its authentication restrictions.",
                    name,
                ))
            for attribute in (
                "msDS-UserAuthNPolicy", "msDS-ComputerAuthNPolicy", "msDS-ServiceAuthNPolicy",
            ):
                linked = as_text(silo.get(attribute))
                if linked and linked.casefold() not in valid_policy_dns:
                    risks.append(self._risk(
                        RiskTypes.AUTH_POLICY_BROKEN_ASSIGNMENT,
                        Severity.HIGH,
                        f'Authentication silo "{name}" references a missing policy',
                        f"{attribute} points to {linked}, which was not found among forest authentication policies.",
                        name,
                        evidence={"attribute": attribute, "linked_policy": linked},
                    ))

        for policy in policies:
            name = as_text(policy.get("cn") or policy.get("distinguishedName")) or "Authentication Policy"
            if not truthy_ldap(policy.get("msDS-AuthNPolicyEnforced")):
                risks.append(self._risk(
                    RiskTypes.AUTH_POLICY_AUDIT_ONLY,
                    Severity.MEDIUM,
                    f'Authentication Policy "{name}" is audit-only',
                    "The policy is configured for auditing and does not yet block authentication outside its rules.",
                    name,
                ))
            for attribute in ("msDS-UserTGTLifetime", "msDS-ServiceTGTLifetime"):
                lifetime = as_int(policy.get(attribute))
                if lifetime and lifetime > self.MAX_PRIVILEGED_TGT_SECONDS:
                    risks.append(self._risk(
                        RiskTypes.AUTH_POLICY_EXCESSIVE_TGT_LIFETIME,
                        Severity.MEDIUM,
                        f'Authentication Policy "{name}" permits a long TGT lifetime',
                        f"{attribute} is {lifetime} seconds; privileged non-renewable TGTs should use a tightly bounded lifetime.",
                        name,
                        evidence={"attribute": attribute, "seconds": lifetime},
                    ))

        # Prefer freshly queried assignment attributes when possible, while
        # retaining collected users as a fallback for offline/unit scenarios.
        privileged_rows = self._search(
            self.ldap.base_dn,
            "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
            ["sAMAccountName", "distinguishedName", "memberOf", "adminCount",
             "msDS-AssignedAuthNPolicy", "msDS-AssignedAuthNPolicySilo"],
        )
        if privileged_rows is None:
            privileged_rows = [u for u in users if account_has_privileged_evidence(u)]
        for user in privileged_rows:
            if not account_has_privileged_evidence(user):
                continue
            name = as_text(user.get("sAMAccountName") or user.get("distinguishedName")) or "privileged account"
            assigned_policy = as_text(user.get("msDS-AssignedAuthNPolicy"))
            assigned_silo = as_text(user.get("msDS-AssignedAuthNPolicySilo"))
            if not assigned_policy and not assigned_silo:
                risks.append(self._risk(
                    RiskTypes.AUTH_POLICY_PRIVILEGED_UNPROTECTED,
                    Severity.HIGH,
                    f'Privileged account "{name}" has no authentication policy',
                    "The account is marked as privileged but has neither a direct Authentication Policy nor a silo assignment.",
                    name,
                ))
            elif assigned_silo and assigned_silo.casefold() not in valid_silo_dns:
                risks.append(self._risk(
                    RiskTypes.AUTH_POLICY_BROKEN_ASSIGNMENT,
                    Severity.HIGH,
                    f'Privileged account "{name}" references a missing authentication silo',
                    f"msDS-AssignedAuthNPolicySilo points to {assigned_silo}, which was not found.",
                    name,
                    evidence={"assigned_silo": assigned_silo},
                ))
            elif assigned_policy and assigned_policy.casefold() not in valid_policy_dns:
                risks.append(self._risk(
                    RiskTypes.AUTH_POLICY_BROKEN_ASSIGNMENT,
                    Severity.HIGH,
                    f'Privileged account "{name}" references a missing authentication policy',
                    f"msDS-AssignedAuthNPolicy points to {assigned_policy}, which was not found.",
                    name,
                    evidence={"assigned_policy": assigned_policy},
                ))
        return risks

    def _search(self, base: str, ldap_filter: str, attributes: list[str]) -> list[dict[str, Any]] | None:
        try:
            return self.ldap.search(
                search_base=base,
                search_filter=ldap_filter,
                attributes=attributes,
            ) or []
        except Exception as exc:
            text = str(exc).casefold()
            if any(token in text for token in ("invalid attribute", "invalid class", "objectclass", "no such object")):
                logger.debug("Authentication policy schema is unavailable: %s", exc)
                return None
            logger.debug("Authentication policy search failed: %s", exc)
            return []

    @staticmethod
    def _risk(risk_type: str, severity: str, title: str, description: str,
              affected: str, **extra: Any) -> dict[str, Any]:
        risk = {
            "type": risk_type,
            "severity": severity,
            "title": title,
            "description": description,
            "affected_object": affected,
            "object_type": "configuration",
            "impact": "Weak authentication-policy enforcement increases credential replay and lateral-movement exposure.",
            "attack_scenario": "An attacker authenticates a privileged identity from a host or service that should have been outside the allowed boundary.",
            "mitigation": "Repair policy links, validate audit events, use short TGT lifetimes, and enforce silos for Tier-0 accounts.",
            "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
        }
        risk.update(extra)
        return risk

"""Delegated Managed Service Account (dMSA) BadSuccessor attack surface."""

from __future__ import annotations

import logging
from typing import Any

from core.ad_identity import (
    forest_configuration_dn,
    is_privileged_principal_reference,
    root_dse_attributes,
    schema_supports_attribute,
    schema_supports_object_class,
)
from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)


class DelegatedMSAAnalyzer:
    """Detect Windows Server 2025 dMSA objects used in BadSuccessor-style takeover."""

    def __init__(self, ldap_connection: Any):
        self.ldap = ldap_connection

    def analyze(self) -> list[dict[str, Any]]:
        """Return dMSA/BadSuccessor findings, or an empty list when the schema is absent."""
        risks: list[dict[str, Any]] = []
        accounts = self._get_dmsa_accounts()
        if accounts is None:
            logger.info("dMSA schema not present")
            return risks
        if not accounts:
            if not self._schema_defines_dmsa():
                return risks
            risks.append({
                "type": RiskTypes.DMSA_SCHEMA_ENABLED,
                "severity": Severity.MEDIUM,
                "title": "Delegated MSA schema is present with no dMSA objects",
                "description": (
                    "The forest understands msDS-DelegatedManagedServiceAccount. Any principal who can "
                    "create a dMSA in an OU and write msDS-ManagedAccountPrecededByLink can perform "
                    "the BadSuccessor attack and inherit the superseded account's privileges."
                ),
                "affected_object": self.ldap.base_dn,
                "object_type": "configuration",
                "impact": "CreateChild on an OU becomes a domain-takeover primitive once a privileged account is linked as predecessor.",
                "attack_scenario": "Create a dMSA, set msDS-ManagedAccountPrecededByLink to a Domain Admin, then authenticate as the dMSA.",
                "mitigation": (
                    "Restrict CreateChild for msDS-DelegatedManagedServiceAccount on every OU, "
                    "monitor creation of dMSA objects, and apply Microsoft's BadSuccessor mitigations."
                ),
                "mitre_attack": MITRETechniques.EXPLOITATION_PRIVILEGE_ESCALATION,
            })
            logger.info("Found %d delegated MSA risks", len(risks))
            return risks
        for account in accounts:
            risks.extend(self._assess_account(account))
        logger.info("Found %d delegated MSA risks", len(risks))
        return risks

    def _get_dmsa_accounts(self) -> list[dict[str, Any]] | None:
        if schema_supports_object_class(
            self.ldap,
            "msDS-DelegatedManagedServiceAccount",
        ) is False:
            return None

        attributes = [
            "sAMAccountName",
            "distinguishedName",
            "msDS-DelegatedMSAState",
            "msDS-ManagedAccountPrecededByLink",
            "msDS-GroupMSAMembership",
            "servicePrincipalName",
        ]
        attributes = [
            attribute for attribute in attributes
            if schema_supports_attribute(self.ldap, attribute) is not False
        ]
        try:
            return self.ldap.search(
                search_base=self.ldap.base_dn,
                search_filter="(objectClass=msDS-DelegatedManagedServiceAccount)",
                attributes=attributes,
            ) or []
        except Exception as exc:
            message = str(exc).lower()
            if "objectclass" in message or "no such" in message or "invalid" in message:
                return None
            logger.debug("dMSA search failed: %s", exc)
            return []

    def _schema_naming_context(self) -> str | None:
        """Return the forest schema NC from RootDSE, not the domain DN."""
        root = root_dse_attributes(
            self.ldap,
            ["schemaNamingContext", "configurationNamingContext"],
        )
        schema = self._as_text(root.get("schemaNamingContext"))
        if schema:
            return schema
        config = self._as_text(root.get("configurationNamingContext"))
        if config:
            return config if config.upper().startswith("CN=SCHEMA,") else f"CN=Schema,{config}"
        return None

    def _schema_defines_dmsa(self) -> bool:
        """Return True when the forest schema includes the dMSA class."""
        schema_dn = self._schema_naming_context()
        if not schema_dn:
            config_dn = forest_configuration_dn(self.ldap)
            schema_dn = f"CN=Schema,{config_dn}" if config_dn else None
        if not schema_dn:
            return False
        try:
            rows = self.ldap.search(
                search_base=schema_dn,
                search_filter="(lDAPDisplayName=msDS-DelegatedManagedServiceAccount)",
                attributes=["lDAPDisplayName", "cn"],
                size_limit=1,
            ) or []
            return bool(rows)
        except Exception as exc:
            logger.debug("dMSA schema probe failed: %s", exc)
            return False

    def _as_text(self, value: Any) -> str:
        if isinstance(value, (list, tuple)):
            value = value[0] if value else ""
        if value is None:
            return ""
        return str(value)

    def _assess_account(self, account: dict[str, Any]) -> list[dict[str, Any]]:
        risks: list[dict[str, Any]] = []
        name = self._as_text(account.get("sAMAccountName") or account.get("distinguishedName") or "dMSA")
        predecessor = self._as_text(account.get("msDS-ManagedAccountPrecededByLink"))
        state = self._as_text(account.get("msDS-DelegatedMSAState"))
        if predecessor:
            privileged = is_privileged_principal_reference(predecessor)
            risks.append({
                "type": RiskTypes.DMSA_PREDECESSOR_LINK,
                "severity": Severity.CRITICAL if privileged else Severity.HIGH,
                "title": f"dMSA {name} supersedes {predecessor}",
                "description": (
                    f"Delegated MSA '{name}' has msDS-ManagedAccountPrecededByLink={predecessor} "
                    f"(state={state or 'unknown'}). BadSuccessor-style abuse inherits the predecessor's SID history/keys."
                ),
                "affected_object": name,
                "object_type": "user",
                "impact": "Authentication as the dMSA can impersonate the superseded privileged account.",
                "attack_scenario": "Authenticate with the dMSA after linking it to a privileged predecessor.",
                "mitigation": "Remove unexpected predecessor links, restrict who can write msDS-ManagedAccountPrecededByLink, and audit dMSA creation.",
                "mitre_attack": MITRETechniques.EXPLOITATION_PRIVILEGE_ESCALATION,
                "predecessor": predecessor,
            })
        else:
            risks.append({
                "type": RiskTypes.DMSA_OBJECT_PRESENT,
                "severity": Severity.MEDIUM,
                "title": f"Delegated MSA present: {name}",
                "description": (
                    f"dMSA '{name}' exists without a predecessor link. The object is still a BadSuccessor "
                    "target if an attacker can write msDS-ManagedAccountPrecededByLink."
                ),
                "affected_object": name,
                "object_type": "user",
                "impact": "Write access to this dMSA is a privilege-inheritance primitive.",
                "attack_scenario": "Write a privileged account DN into msDS-ManagedAccountPrecededByLink.",
                "mitigation": "Lock down ACLs on dMSA objects and monitor attribute writes to predecessor links.",
                "mitre_attack": MITRETechniques.EXPLOITATION_PRIVILEGE_ESCALATION,
            })
        return risks

"""SCCM / Configuration Manager System Management container attack surface."""

from __future__ import annotations

import logging
from typing import Any

from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)


class SCCMAttackSurfaceAnalyzer:
    """Detect SCCM site-publication objects that often lead to client takeover."""

    def __init__(self, ldap_connection: Any):
        self.ldap = ldap_connection

    def analyze(self) -> list[dict[str, Any]]:
        """Return SCCM attack-surface findings from the System Management container."""
        risks: list[dict[str, Any]] = []
        container_dn = f"CN=System Management,CN=System,{self.ldap.base_dn}"
        objects = self._search_container(container_dn)
        if objects is None:
            logger.info("System Management container not present")
            return risks
        management_points = [
            obj for obj in objects
            if "mssmsmanagementpoint" in str(obj.get("objectClass") or "").lower()
            or str(obj.get("cn") or "").upper().startswith("SMS-MP-")
            or obj.get("mSSMSManagementPoint")
        ]
        site_servers = [
            obj for obj in objects
            if str(obj.get("cn") or "").upper().startswith("SMS-")
        ]
        risks.append({
            "type": RiskTypes.SCCM_SYSTEM_MANAGEMENT_PRESENT,
            "severity": Severity.HIGH if site_servers else Severity.MEDIUM,
            "title": f"SCCM System Management container published ({len(objects)} objects)",
            "description": (
                "CN=System Management,CN=System contains Configuration Manager publication objects. "
                "Site-server computer accounts often have GenericAll on this container and can become "
                "a path to client push, network access accounts, or site takeover."
            ),
            "affected_object": container_dn,
            "object_type": "configuration",
            "impact": "SCCM site takeover yields SYSTEM on enrolled clients and frequently Domain Admin via client push.",
            "attack_scenario": "Abuse the site-server computer account or container ACLs, then perform SCCM client push to a DC or DA workstation.",
            "mitigation": (
                "Treat SCCM site servers as Tier 0, restrict System Management ACLs to the site-server "
                "computers only, and disable automatic client push to domain controllers."
            ),
            "mitre_attack": MITRETechniques.EXPLOITATION_PRIVILEGE_ESCALATION,
            "object_count": len(objects),
            "management_point_count": len(management_points),
        })
        for obj in management_points[:15]:
            name = str(obj.get("dNSHostName") or obj.get("cn") or obj.get("distinguishedName") or "SMS-MP")
            risks.append({
                "type": RiskTypes.SCCM_MANAGEMENT_POINT,
                "severity": Severity.MEDIUM,
                "title": f"SCCM management point: {name}",
                "description": (
                    f"Management point '{name}' is published in AD. Management points issue policy "
                    "and are high-value NTLM-relay and HTTP coercion targets."
                ),
                "affected_object": name,
                "object_type": "computer",
                "impact": "Compromise of a management point can deploy arbitrary applications to clients.",
                "attack_scenario": "Relay or coerce the management point, then push a malicious application.",
                "mitigation": "Require HTTPS/mutual TLS, isolate management-point hosts, and monitor client-push events.",
                "mitre_attack": MITRETechniques.EXPLOITATION_PRIVILEGE_ESCALATION,
            })
        logger.info("Found %d SCCM attack-surface risks", len(risks))
        return risks

    def _search_container(self, container_dn: str) -> list[dict[str, Any]] | None:
        try:
            return self.ldap.search(
                search_base=container_dn,
                search_filter="(objectClass=*)",
                attributes=["cn", "objectClass", "dNSHostName", "distinguishedName", "mSSMSSiteCode"],
            ) or []
        except Exception as exc:
            message = str(exc).lower()
            if "no such object" in message or "not exist" in message or "32" in message:
                return None
            logger.debug("System Management search failed: %s", exc)
            return None

"""Trust Security v2: correct flag decoding, hardening checks, and graph data."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any

from core.ad_security import as_int, as_text
from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)


class TrustSecurityV2Analyzer:
    """Assess trustedDomain attributes without equating trustType with forest trust."""

    NON_TRANSITIVE = 0x00000001
    QUARANTINED_DOMAIN = 0x00000004
    FOREST_TRANSITIVE = 0x00000008
    CROSS_ORGANIZATION = 0x00000010
    WITHIN_FOREST = 0x00000020
    TREAT_AS_EXTERNAL = 0x00000040
    USES_RC4_ENCRYPTION = 0x00000080
    NO_TGT_DELEGATION = 0x00000200
    PIM_TRUST = 0x00000400
    ENABLE_TGT_DELEGATION = 0x00000800
    AES_MASK = 0x18

    def __init__(self, ldap_connection: Any):
        self.ldap = ldap_connection

    def analyze(self) -> dict[str, Any]:
        try:
            rows = self.ldap.search(
                search_base=f"CN=System,{self.ldap.base_dn}",
                search_filter="(objectClass=trustedDomain)",
                attributes=[
                    "cn", "name", "flatName", "trustPartner", "distinguishedName",
                    "trustDirection", "trustType", "trustAttributes",
                    "msDS-SupportedEncryptionTypes", "whenCreated", "whenChanged",
                ],
            ) or []
        except Exception as exc:
            logger.debug("Trust Security v2 search failed: %s", exc)
            return {"risks": [], "graph": {"nodes": [], "edges": [], "summary": {}}}

        risks: list[dict[str, Any]] = []
        local_id = f"domain:{self.ldap.base_dn.casefold()}"
        nodes: list[dict[str, Any]] = [{"id": local_id, "label": self.ldap.base_dn, "kind": "domain"}]
        edges: list[dict[str, Any]] = []
        for trust in rows:
            name = as_text(
                trust.get("trustPartner") or trust.get("name") or trust.get("flatName") or trust.get("cn")
            ) or "trusted domain"
            direction = as_int(trust.get("trustDirection")) or 0
            trust_type = as_int(trust.get("trustType")) or 0
            attributes = as_int(trust.get("trustAttributes")) or 0
            encryption = as_int(trust.get("msDS-SupportedEncryptionTypes"))
            kind = self._kind(attributes, trust_type)
            trust_id = f"domain:{name.casefold()}"
            nodes.append({"id": trust_id, "label": name, "kind": "trusted_domain", "trust_kind": kind})
            if direction in (1, 3):
                edges.append({"source": trust_id, "target": local_id, "type": "InboundTrust"})
            if direction in (2, 3):
                edges.append({"source": local_id, "target": trust_id, "type": "OutboundTrust"})

            if direction in (1, 3) and not attributes & self.CROSS_ORGANIZATION:
                risks.append(self._risk(
                    RiskTypes.TRUST_SELECTIVE_AUTH_DISABLED,
                    Severity.MEDIUM,
                    f'Selective authentication is not enabled for trust "{name}"',
                    "The trust accepts inbound authentication without the CROSS_ORGANIZATION selective-authentication flag.",
                    name, direction, kind, attributes,
                ))
            is_external_boundary = not attributes & (self.WITHIN_FOREST | self.FOREST_TRANSITIVE)
            if is_external_boundary and direction in (1, 3) and not attributes & self.QUARANTINED_DOMAIN:
                risks.append(self._risk(
                    RiskTypes.TRUST_SID_FILTERING_WEAK,
                    Severity.CRITICAL,
                    f'SID filtering is not evidenced for external trust "{name}"',
                    "The external inbound trust does not advertise TRUST_ATTRIBUTE_QUARANTINED_DOMAIN.",
                    name, direction, kind, attributes,
                ))
            if attributes & self.ENABLE_TGT_DELEGATION:
                risks.append(self._risk(
                    RiskTypes.TRUST_TGT_DELEGATION_ENABLED,
                    Severity.HIGH,
                    f'TGT delegation is explicitly enabled across trust "{name}"',
                    "TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION is set.",
                    name, direction, kind, attributes,
                ))
            if attributes & self.USES_RC4_ENCRYPTION or (
                encryption is not None and not encryption & self.AES_MASK
            ):
                risks.append(self._risk(
                    RiskTypes.TRUST_RC4_DEPENDENCY,
                    Severity.HIGH,
                    f'Trust "{name}" has an RC4 dependency',
                    "Trust attributes or supported-encryption metadata indicate that AES is not fully available.",
                    name, direction, kind, attributes,
                    encryption_types=encryption,
                ))
            age_days = self._age_days(trust.get("whenChanged"))
            if age_days is not None and age_days > 365:
                risks.append(self._risk(
                    RiskTypes.TRUST_STALE_CONFIGURATION,
                    Severity.LOW,
                    f'Trust "{name}" has not changed for {age_days} days',
                    "The trust object is old enough to require ownership, necessity, and secret-rotation review.",
                    name, direction, kind, attributes,
                    age_days=age_days,
                ))

        graph = {
            "schema_version": "1.0", "nodes": nodes, "edges": edges,
            "summary": {"trust_count": len(rows), "edge_count": len(edges), "finding_count": len(risks)},
        }
        return {"risks": risks, "graph": graph}

    @classmethod
    def _kind(cls, attributes: int, trust_type: int) -> str:
        if attributes & cls.WITHIN_FOREST:
            return "parent_child"
        if attributes & cls.FOREST_TRANSITIVE:
            return "forest"
        if attributes & cls.NON_TRANSITIVE or trust_type in (1, 3):
            return "external"
        return "uplevel_external" if trust_type == 2 else "unknown"

    @staticmethod
    def _age_days(value: Any) -> int | None:
        if isinstance(value, datetime):
            moment = value
        else:
            text = as_text(value)
            if not text:
                return None
            try:
                if text.endswith("Z") and len(text) >= 15 and "T" not in text:
                    moment = datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
                else:
                    moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                return None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - moment.astimezone(timezone.utc)).days)

    @staticmethod
    def _risk(risk_type: str, severity: str, title: str, description: str,
              affected: str, direction: int, kind: str, attributes: int,
              **evidence: Any) -> dict[str, Any]:
        details = {"direction": direction, "trust_kind": kind, "trust_attributes": attributes}
        details.update(evidence)
        return {
            "type": risk_type, "severity": severity, "title": title,
            "description": description, "affected_object": affected, "object_type": "trust",
            "impact": "Weak trust controls expand credential, SID, and ticket abuse across domain or forest boundaries.",
            "attack_scenario": "An attacker compromises one side of the trust and crosses the boundary through permissive authentication or ticket behavior.",
            "mitigation": "Use one-way/selective trust where possible, enforce SID filtering and AES, disable TGT delegation, and rotate trust secrets.",
            "mitre_attack": MITRETechniques.LATERAL_MOVEMENT,
            "evidence": details,
        }

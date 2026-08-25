"""AD-integrated DNS object, record, and ACL security assessment."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any

from core.ad_security import ace_permission_names, as_list, as_text, dangerous_broad_aces, parsed_security_descriptor
from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)


class ADDNSSecurityAnalyzer:
    """Assess directory-integrated zones without contacting the DNS service."""

    RECORD_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 28: "AAAA", 33: "SRV"}
    HIGH_RISK_NAMES = frozenset({"wpad", "isatap", "*"})

    def __init__(self, ldap_connection: Any):
        self.ldap = ldap_connection

    def analyze(self) -> dict[str, Any]:
        bases = [
            f"DC=DomainDnsZones,{self.ldap.base_dn}",
            f"DC=ForestDnsZones,{self.ldap.base_dn}",
        ]
        risks: list[dict[str, Any]] = []
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        zone_count = 0
        record_count = 0

        for base in bases:
            zones = self._search(base, "(objectClass=dnsZone)", [
                "dc", "name", "distinguishedName", "dnsProperty", "nTSecurityDescriptor",
            ])
            for zone in zones:
                zone_count += 1
                zone_dn = as_text(zone.get("distinguishedName"))
                zone_name = as_text(zone.get("dc") or zone.get("name") or zone_dn) or "DNS zone"
                zone_id = f"dns-zone:{zone_dn.casefold() or zone_name.casefold()}"
                nodes[zone_id] = {"id": zone_id, "label": zone_name, "kind": "dns_zone", "dn": zone_dn}
                for ace in dangerous_broad_aces(parsed_security_descriptor(zone.get("nTSecurityDescriptor"))):
                    permissions = sorted(ace_permission_names(ace))
                    sid = str(ace.get("sid") or "unknown")
                    risks.append({
                        "type": RiskTypes.AD_DNS_BROAD_ZONE_ACL,
                        "severity": Severity.HIGH,
                        "title": f"Broad principal {sid} controls DNS zone {zone_name}",
                        "description": f"The AD-integrated zone DACL grants {', '.join(permissions)} to {sid}.",
                        "affected_object": zone_name,
                        "object_type": "configuration",
                        "impact": "Zone control can redirect authentication, management, software-distribution, or service-discovery traffic.",
                        "attack_scenario": "An attacker writes a record that redirects privileged clients to an attacker-controlled host.",
                        "mitigation": "Remove broad zone-control ACEs and delegate record management only to scoped DNS administration groups.",
                        "mitre_attack": MITRETechniques.LATERAL_MOVEMENT,
                        "evidence": {"trustee_sid": sid, "permissions": permissions, "zone_dn": zone_dn},
                    })

                search_base = zone_dn or base
                records = self._search(search_base, "(objectClass=dnsNode)", [
                    "dc", "name", "distinguishedName", "dnsRecord", "dNSTombstoned", "whenChanged",
                ])
                for record in records:
                    if as_text(record.get("dNSTombstoned")).casefold() in {"1", "true"}:
                        continue
                    record_count += 1
                    record_name = as_text(record.get("dc") or record.get("name")) or "@"
                    record_dn = as_text(record.get("distinguishedName"))
                    types = sorted({kind for raw in as_list(record.get("dnsRecord")) if (kind := self.record_type(raw))})
                    record_id = f"dns-node:{record_dn.casefold() or (zone_name + '/' + record_name).casefold()}"
                    nodes[record_id] = {
                        "id": record_id, "label": record_name, "kind": "dns_node",
                        "record_types": types, "dn": record_dn,
                    }
                    edges.append({"source": record_id, "target": zone_id, "type": "RecordInZone"})
                    if record_name.casefold() in self.HIGH_RISK_NAMES:
                        risks.append({
                            "type": RiskTypes.AD_DNS_HIGH_RISK_NODE,
                            "severity": Severity.HIGH if record_name.casefold() in {"wpad", "*"} else Severity.MEDIUM,
                            "title": f"High-risk DNS node {record_name}.{zone_name}",
                            "description": "A WPAD, ISATAP, or wildcard node exists in AD-integrated DNS and requires ownership validation.",
                            "affected_object": f"{record_name}.{zone_name}",
                            "object_type": "configuration",
                            "impact": "High-impact names can redirect many clients or enable proxy/autodiscovery credential interception.",
                            "attack_scenario": "An attacker controls a high-risk record and captures or relays client authentication.",
                            "mitigation": "Validate ownership, remove unused high-risk names, block WPAD where unused, and monitor dnsNode changes.",
                            "mitre_attack": MITRETechniques.LATERAL_MOVEMENT,
                            "evidence": {"record_types": types, "record_dn": record_dn},
                        })
                    age_days = self._age_days(record.get("whenChanged"))
                    if "NS" in types and age_days is not None and age_days > 365:
                        risks.append({
                            "type": RiskTypes.AD_DNS_STALE_DELEGATION,
                            "severity": Severity.MEDIUM,
                            "title": f"Stale DNS delegation candidate {record_name}.{zone_name}",
                            "description": f"An NS record has not changed for {age_days} days and should be checked for orphaned delegation.",
                            "affected_object": f"{record_name}.{zone_name}",
                            "object_type": "configuration",
                            "impact": "An abandoned delegated namespace can be reclaimed or redirected outside the intended administration boundary.",
                            "attack_scenario": "An attacker takes control of the delegated target and serves authoritative answers for the stale child zone.",
                            "mitigation": "Verify the delegated nameserver and child-zone owner; remove obsolete NS records and glue records.",
                            "mitre_attack": MITRETechniques.LATERAL_MOVEMENT,
                            "evidence": {"age_days": age_days, "record_dn": record_dn},
                        })

        graph = {
            "schema_version": "1.0", "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
            "edges": edges,
            "summary": {"zone_count": zone_count, "record_count": record_count, "finding_count": len(risks)},
        }
        return {"risks": risks, "graph": graph}

    def _search(self, base: str, ldap_filter: str, attributes: list[str]) -> list[dict[str, Any]]:
        try:
            return self.ldap.search(
                search_base=base, search_filter=ldap_filter, attributes=attributes,
            ) or []
        except Exception as exc:
            logger.debug("AD DNS search failed for %s: %s", base, exc)
            return []

    @classmethod
    def record_type(cls, raw: Any) -> str | None:
        """Return a DNS_RPC_RECORD type name from binary or test-friendly data."""
        if isinstance(raw, dict):
            value = raw.get("type") or raw.get("record_type")
            if isinstance(value, str) and not value.isdigit():
                return value.upper()
            try:
                return cls.RECORD_TYPES.get(int(value))
            except (TypeError, ValueError):
                return None
        if isinstance(raw, str):
            text = raw.strip().upper()
            if text in cls.RECORD_TYPES.values():
                return text
            try:
                raw = bytes.fromhex(text)
            except ValueError:
                return None
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            return None
        data = bytes(raw)
        if len(data) < 4:
            return None
        return cls.RECORD_TYPES.get(int.from_bytes(data[2:4], "little"))

    @staticmethod
    def _age_days(value: Any) -> int | None:
        if isinstance(value, datetime):
            moment = value
        else:
            text = as_text(value)
            if not text:
                return None
            try:
                moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                try:
                    moment = datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
                except ValueError:
                    return None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - moment.astimezone(timezone.utc)).days)

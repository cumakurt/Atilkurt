"""Effective gMSA managed-password reader graph."""

from __future__ import annotations

import logging
from typing import Any

from core.ad_identity import account_has_privileged_evidence, is_privileged_group_record
from core.ad_security import as_list, as_text, parsed_security_descriptor, sid_text
from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)


class GMSAReaderGraphAnalyzer:
    """Decode msDS-GroupMSAMembership and resolve nested reader groups."""

    EFFECTIVE_READER_THRESHOLD = 20

    def __init__(self, ldap_connection: Any):
        self.ldap = ldap_connection

    def analyze(
        self,
        users: list[dict[str, Any]],
        groups: list[dict[str, Any]],
        computers: list[dict[str, Any]],
    ) -> dict[str, Any]:
        try:
            accounts = self.ldap.search(
                search_base=self.ldap.base_dn,
                search_filter="(objectClass=msDS-GroupManagedServiceAccount)",
                attributes=[
                    "sAMAccountName", "distinguishedName", "objectSid", "adminCount",
                    "memberOf", "servicePrincipalName", "msDS-GroupMSAMembership",
                ],
            ) or []
        except Exception as exc:
            logger.debug("gMSA reader-graph search failed: %s", exc)
            return {"risks": [], "graph": {"nodes": [], "edges": [], "summary": {}}}

        objects = [*users, *groups, *computers]
        by_sid: dict[str, dict[str, Any]] = {}
        by_dn: dict[str, dict[str, Any]] = {}
        for obj in objects:
            sid = sid_text(obj.get("objectSid"))
            dn = as_text(obj.get("distinguishedName") or obj.get("dn"))
            if sid:
                by_sid[sid] = obj
            if dn:
                by_dn[dn.casefold()] = obj

        risks: list[dict[str, Any]] = []
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        for account in accounts:
            name = as_text(account.get("sAMAccountName") or account.get("distinguishedName")) or "gMSA"
            gmsa_id = f"gmsa:{name.casefold()}"
            privileged_gmsa = account_has_privileged_evidence(account)
            nodes[gmsa_id] = {"id": gmsa_id, "label": name, "kind": "gmsa", "privileged": privileged_gmsa}
            parsed = parsed_security_descriptor(account.get("msDS-GroupMSAMembership"))
            reader_sids = {
                str(ace.get("sid")) for ace in (parsed or {}).get("dacl", []) if ace.get("sid")
            }
            effective_names: set[str] = set()
            low_trust_readers: set[str] = set()
            for reader_sid in sorted(reader_sids):
                reader = by_sid.get(reader_sid)
                label = self._name(reader) if reader else reader_sid
                reader_id = f"principal:{reader_sid.casefold()}"
                reader_privileged = bool(reader and (
                    account_has_privileged_evidence(reader) or is_privileged_group_record(reader)
                ))
                nodes[reader_id] = {
                    "id": reader_id, "label": label, "kind": self._kind(reader),
                    "sid": reader_sid, "privileged": reader_privileged,
                }
                edges.append({"source": reader_id, "target": gmsa_id, "type": "ReadGMSAPassword"})
                expanded = self._expand_principal(reader, by_dn)
                if not expanded:
                    expanded = {label}
                effective_names.update(expanded)
                if not reader_privileged:
                    low_trust_readers.update(expanded)

                if reader_sid in {"S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-546"}:
                    risks.append(self._risk(
                        RiskTypes.GMSA_BROAD_PASSWORD_READER,
                        Severity.CRITICAL if privileged_gmsa else Severity.HIGH,
                        f'Broad principal {label} can retrieve the password for "{name}"',
                        "The gMSA retrieval security descriptor grants managed-password access to a broad principal.",
                        name,
                        {"reader_sid": reader_sid, "effective_reader_count": len(expanded)},
                    ))

            if privileged_gmsa and low_trust_readers:
                risks.append(self._risk(
                    RiskTypes.GMSA_PRIVILEGED_READER_PATH,
                    Severity.CRITICAL,
                    f'Low-trust principals can retrieve privileged gMSA "{name}"',
                    "A privileged gMSA is reachable through one or more non-privileged password-reader principals.",
                    name,
                    {"effective_readers": sorted(low_trust_readers)[:50], "effective_reader_count": len(low_trust_readers)},
                ))
            if len(effective_names) > self.EFFECTIVE_READER_THRESHOLD:
                risks.append(self._risk(
                    RiskTypes.GMSA_EXCESSIVE_EFFECTIVE_READERS,
                    Severity.HIGH if privileged_gmsa else Severity.MEDIUM,
                    f'gMSA "{name}" has {len(effective_names)} effective password readers',
                    "Nested group expansion produces a large managed-password retrieval scope.",
                    name,
                    {"effective_reader_count": len(effective_names), "sample": sorted(effective_names)[:50]},
                ))

        graph = {
            "schema_version": "1.0",
            "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
            "edges": edges,
            "summary": {
                "gmsa_count": len(accounts),
                "node_count": len(nodes),
                "edge_count": len(edges),
                "finding_count": len(risks),
            },
        }
        return {"risks": risks, "graph": graph}

    def _expand_principal(
        self, principal: dict[str, Any] | None, by_dn: dict[str, dict[str, Any]],
    ) -> set[str]:
        if not principal:
            return set()
        members = as_list(principal.get("member"))
        if not members:
            return {self._name(principal)}
        effective: set[str] = set()
        queue = [as_text(member).casefold() for member in members if as_text(member)]
        visited: set[str] = set()
        while queue:
            dn = queue.pop()
            if dn in visited:
                continue
            visited.add(dn)
            obj = by_dn.get(dn)
            if not obj:
                effective.add(dn)
                continue
            nested = as_list(obj.get("member"))
            if nested:
                queue.extend(as_text(member).casefold() for member in nested if as_text(member))
            else:
                effective.add(self._name(obj))
        return effective

    @staticmethod
    def _name(obj: dict[str, Any] | None) -> str:
        if not obj:
            return "unknown principal"
        return as_text(
            obj.get("sAMAccountName") or obj.get("name") or obj.get("cn")
            or obj.get("distinguishedName")
        ) or "unknown principal"

    @staticmethod
    def _kind(obj: dict[str, Any] | None) -> str:
        if not obj:
            return "principal"
        if obj.get("member") is not None:
            return "group"
        name = as_text(obj.get("sAMAccountName"))
        return "computer" if name.endswith("$") else "user"

    @staticmethod
    def _risk(risk_type: str, severity: str, title: str, description: str,
              affected: str, evidence: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": risk_type,
            "severity": severity,
            "title": title,
            "description": description,
            "affected_object": affected,
            "object_type": "user",
            "impact": "Retrieving a gMSA password grants the service identity's effective privileges on every host and service where it is accepted.",
            "attack_scenario": "An attacker joins or compromises an allowed reader group, retrieves the managed password, and authenticates as the gMSA.",
            "mitigation": "Reduce the retrieval descriptor to required hosts, remove nested broad groups, and isolate privileged gMSAs in Tier 0.",
            "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
            "evidence": evidence,
        }

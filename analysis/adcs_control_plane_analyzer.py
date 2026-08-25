"""AD CS control-plane ACL graph based on directory security descriptors."""

from __future__ import annotations

import logging
from typing import Any

from core.ad_identity import account_has_privileged_evidence, forest_configuration_dn, is_privileged_group_record
from core.ad_security import (
    DANGEROUS_DIRECTORY_PERMISSIONS,
    ace_permission_names,
    as_text,
    parsed_security_descriptor,
    sid_text,
)
from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)


class ADCSControlPlaneAnalyzer:
    """Find non-administrative control over PKI containers, CAs, and templates."""

    BROAD_SIDS = frozenset({"S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-546"})

    def __init__(self, ldap_connection: Any):
        self.ldap = ldap_connection

    def analyze(self, users: list[dict[str, Any]], groups: list[dict[str, Any]]) -> dict[str, Any]:
        config_dn = forest_configuration_dn(self.ldap)
        if not config_dn:
            return {"risks": [], "graph": {"nodes": [], "edges": [], "summary": {}}}

        principals: dict[str, dict[str, Any]] = {}
        for obj in [*users, *groups]:
            sid = sid_text(obj.get("objectSid"))
            if sid:
                principals[sid] = obj

        pki_base = f"CN=Public Key Services,CN=Services,{config_dn}"
        targets: list[tuple[str, str, str]] = [
            (pki_base, "(objectClass=*)", "pki_root"),
            (f"CN=Certificate Templates,{pki_base}", "(objectClass=pKICertificateTemplate)", "template"),
            (f"CN=Enrollment Services,{pki_base}", "(objectClass=pKIEnrollmentService)", "ca"),
            (f"CN=NTAuthCertificates,{pki_base}", "(objectClass=*)", "ntauth"),
            (f"CN=OID,{pki_base}", "(objectClass=*)", "oid"),
        ]

        risks: list[dict[str, Any]] = []
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        seen_findings: set[tuple[str, str, tuple[str, ...]]] = set()
        scanned_objects = 0

        for base, ldap_filter, kind in targets:
            try:
                rows = self.ldap.search(
                    search_base=base,
                    search_filter=ldap_filter,
                    attributes=["cn", "displayName", "distinguishedName", "nTSecurityDescriptor"],
                ) or []
            except Exception as exc:
                logger.debug("AD CS control-plane search failed for %s: %s", base, exc)
                continue
            for row in rows:
                scanned_objects += 1
                dn = as_text(row.get("distinguishedName")) or base
                label = as_text(row.get("displayName") or row.get("cn")) or dn
                target_id = f"adcs:{dn.casefold()}"
                nodes[target_id] = {"id": target_id, "label": label, "kind": kind, "dn": dn}
                parsed = parsed_security_descriptor(row.get("nTSecurityDescriptor"))
                for ace in (parsed or {}).get("dacl", []):
                    permissions = ace_permission_names(ace).intersection(DANGEROUS_DIRECTORY_PERMISSIONS)
                    if not permissions:
                        continue
                    trustee_sid = str(ace.get("sid") or "")
                    principal = principals.get(trustee_sid)
                    broad = trustee_sid in self.BROAD_SIDS
                    privileged = bool(principal and (
                        account_has_privileged_evidence(principal) or is_privileged_group_record(principal)
                    ))
                    # Unknown SIDs are retained in graph evidence, but not
                    # promoted to a finding without low-trust evidence.
                    if not broad and (principal is None or privileged):
                        continue
                    trustee = self._name(principal) if principal else trustee_sid
                    key = (trustee_sid, dn.casefold(), tuple(sorted(permissions)))
                    if key in seen_findings:
                        continue
                    seen_findings.add(key)
                    trustee_id = f"principal:{trustee_sid.casefold()}"
                    nodes[trustee_id] = {
                        "id": trustee_id, "label": trustee, "kind": "principal",
                        "sid": trustee_sid, "privileged": privileged,
                    }
                    edges.append({
                        "source": trustee_id, "target": target_id,
                        "type": "ControlADCSObject", "permissions": sorted(permissions),
                    })
                    risk_type = RiskTypes.ADCS_NTAUTH_ACL if kind == "ntauth" else RiskTypes.ADCS_CONTROL_PLANE_ACL
                    severity = Severity.CRITICAL if kind in {"ntauth", "pki_root", "ca"} else Severity.HIGH
                    risks.append({
                        "type": risk_type,
                        "severity": severity,
                        "title": f'{trustee} can modify AD CS {kind} object "{label}"',
                        "description": (
                            f"A broad or non-privileged principal has {', '.join(sorted(permissions))} on {dn}. "
                            "This is direct ACL evidence rather than an inferred ESC checklist item."
                        ),
                        "affected_object": label,
                        "object_type": "configuration",
                        "impact": "Control-plane modification can alter trusted CAs, enrollment behavior, templates, or issuance-policy mappings.",
                        "attack_scenario": "An attacker changes a PKI object to issue or trust an authentication certificate for a privileged identity.",
                        "mitigation": "Remove non-PKI administrative control, restore approved ACLs, and audit changes to PKI configuration containers.",
                        "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
                        "evidence": {
                            "trustee_sid": trustee_sid, "trustee": trustee,
                            "permissions": sorted(permissions), "target_dn": dn, "target_kind": kind,
                        },
                    })

        graph = {
            "schema_version": "1.0",
            "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
            "edges": edges,
            "summary": {
                "scanned_object_count": scanned_objects,
                "node_count": len(nodes), "edge_count": len(edges), "finding_count": len(risks),
            },
        }
        return {"risks": risks, "graph": graph}

    @staticmethod
    def _name(obj: dict[str, Any] | None) -> str:
        if not obj:
            return "unknown principal"
        return as_text(obj.get("sAMAccountName") or obj.get("name") or obj.get("cn")) or "unknown principal"

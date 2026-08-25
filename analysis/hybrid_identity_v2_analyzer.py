"""Hybrid identity v2: Cloud Kerberos, Connect rights, SSO age, and ADFS DKM."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from typing import Any

from core.ad_security import ace_permission_names, as_int, as_text, dangerous_broad_aces, parsed_security_descriptor, sid_text
from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)

CONNECT_PREFIXES = ("MSOL_", "SYNC_", "AAD_")


class HybridIdentityV2Analyzer:
    """Correlate the on-premises control objects behind hybrid authentication."""

    AES_MASK = 0x18

    def __init__(self, ldap_connection: Any):
        self.ldap = ldap_connection

    def analyze(
        self, users: list[dict[str, Any]], computers: list[dict[str, Any]],
    ) -> dict[str, Any]:
        risks: list[dict[str, Any]] = []
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        risks.extend(self._cloud_kerberos(nodes, edges))
        risks.extend(self._seamless_sso_age(users, computers, nodes))
        risks.extend(self._connect_rights(users, nodes, edges))
        risks.extend(self._adfs_dkm(nodes, edges))
        return {
            "risks": risks,
            "graph": {
                "schema_version": "1.0", "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
                "edges": edges,
                "summary": {"component_count": len(nodes), "edge_count": len(edges), "finding_count": len(risks)},
            },
        }

    def _cloud_kerberos(self, nodes: dict[str, dict[str, Any]], edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
        try:
            rows = self.ldap.search(
                search_base=self.ldap.base_dn,
                search_filter="(|(cn=AzureADKerberos)(sAMAccountName=krbtgt_AzureAD)(sAMAccountName=krbtgt_AzureAD$))",
                attributes=[
                    "cn", "sAMAccountName", "distinguishedName", "pwdLastSet", "whenChanged",
                    "msDS-SupportedEncryptionTypes", "objectSid", "userAccountControl",
                ],
            ) or []
        except Exception as exc:
            logger.debug("Cloud Kerberos object search failed: %s", exc)
            return []
        risks: list[dict[str, Any]] = []
        for row in rows:
            name = as_text(row.get("sAMAccountName") or row.get("cn")) or "AzureADKerberos"
            node_id = f"hybrid:{name.casefold()}"
            nodes[node_id] = {"id": node_id, "label": name, "kind": "cloud_kerberos", "dn": as_text(row.get("distinguishedName"))}
            age = self._age_days(row.get("pwdLastSet") or row.get("whenChanged"))
            encryption = as_int(row.get("msDS-SupportedEncryptionTypes"))
            if age is not None and age > 180:
                risks.append(self._risk(
                    RiskTypes.HYBRID_CLOUD_KERBEROS_STALE_KEY,
                    Severity.HIGH,
                    f'Cloud Kerberos object "{name}" has a {age}-day-old key',
                    "The on-premises Entra Kerberos server/account key has not been rotated within the assessment threshold.",
                    name,
                    {"password_age_days": age, "dn": as_text(row.get("distinguishedName"))},
                ))
            if encryption is not None and not encryption & self.AES_MASK:
                risks.append(self._risk(
                    RiskTypes.HYBRID_CLOUD_KERBEROS_ACCOUNT,
                    Severity.HIGH,
                    f'Cloud Kerberos object "{name}" is not AES-ready',
                    "The directory encryption metadata for this hybrid Kerberos component does not include AES128/AES256.",
                    name,
                    {"supported_encryption_types": encryption},
                ))
        return risks

    def _seamless_sso_age(
        self, users: list[dict[str, Any]], computers: list[dict[str, Any]],
        nodes: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        risks: list[dict[str, Any]] = []
        for row in [*users, *computers]:
            name = as_text(row.get("sAMAccountName") or row.get("name"))
            if name.upper().rstrip("$") != "AZUREADSSOACC":
                continue
            node_id = f"hybrid:{name.casefold()}"
            nodes[node_id] = {"id": node_id, "label": name, "kind": "seamless_sso"}
            age = self._age_days(row.get("pwdLastSet") or row.get("whenChanged"))
            if age is not None and age > 60:
                risks.append(self._risk(
                    RiskTypes.HYBRID_SEAMLESS_SSO_STALE_KEY,
                    Severity.HIGH,
                    f'Seamless SSO account "{name}" has a {age}-day-old key',
                    "The AZUREADSSOACC Kerberos decryption key exceeds the rotation assessment threshold.",
                    name,
                    {"password_age_days": age},
                ))
        return risks

    def _connect_rights(
        self, users: list[dict[str, Any]], nodes: dict[str, dict[str, Any]], edges: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        connect_accounts = {
            sid_text(user.get("objectSid")): user for user in users
            if any(as_text(user.get("sAMAccountName")).upper().startswith(prefix) for prefix in CONNECT_PREFIXES)
            and sid_text(user.get("objectSid"))
        }
        if not connect_accounts:
            return []
        try:
            rows = self.ldap.search(
                search_base=self.ldap.base_dn,
                search_filter="(objectClass=domain)",
                attributes=["distinguishedName", "nTSecurityDescriptor"],
                size_limit=1,
            ) or []
        except Exception as exc:
            logger.debug("Entra Connect domain-rights search failed: %s", exc)
            return []
        if not rows:
            return []
        parsed = parsed_security_descriptor(rows[0].get("nTSecurityDescriptor"))
        risks: list[dict[str, Any]] = []
        for ace in (parsed or {}).get("dacl", []):
            sid = str(ace.get("sid") or "")
            if sid not in connect_accounts:
                continue
            permissions = ace_permission_names(ace)
            replication = sorted(name for name in permissions if name.startswith("DS-Replication") or name == "AllExtendedRights")
            if not replication:
                continue
            account = connect_accounts[sid]
            name = as_text(account.get("sAMAccountName")) or sid
            node_id = f"hybrid:{name.casefold()}"
            domain_id = f"domain:{self.ldap.base_dn.casefold()}"
            nodes[node_id] = {"id": node_id, "label": name, "kind": "entra_connect", "sid": sid}
            nodes[domain_id] = {"id": domain_id, "label": self.ldap.base_dn, "kind": "domain"}
            edges.append({"source": node_id, "target": domain_id, "type": "ReplicationRight", "permissions": replication})
            risks.append(self._risk(
                RiskTypes.HYBRID_ENTRA_CONNECT_EXCESSIVE_RIGHTS,
                Severity.CRITICAL,
                f'Entra Connect account "{name}" has domain replication rights',
                "The account SID appears in a domain-root ACE that grants replication or all extended rights.",
                name,
                {"trustee_sid": sid, "permissions": replication},
            ))
        return risks

    def _adfs_dkm(self, nodes: dict[str, dict[str, Any]], edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
        base = f"CN=ADFS,CN=Microsoft,CN=Program Data,{self.ldap.base_dn}"
        try:
            rows = self.ldap.search(
                search_base=base,
                search_filter="(objectClass=*)",
                attributes=["cn", "distinguishedName", "nTSecurityDescriptor"],
            ) or []
        except Exception as exc:
            logger.debug("ADFS DKM search failed: %s", exc)
            return []
        risks: list[dict[str, Any]] = []
        for row in rows:
            dn = as_text(row.get("distinguishedName")) or base
            label = as_text(row.get("cn")) or dn
            dkm_id = f"hybrid-dkm:{dn.casefold()}"
            nodes[dkm_id] = {"id": dkm_id, "label": label, "kind": "adfs_dkm", "dn": dn}
            for ace in dangerous_broad_aces(parsed_security_descriptor(row.get("nTSecurityDescriptor"))):
                sid = str(ace.get("sid") or "unknown")
                permissions = sorted(ace_permission_names(ace))
                principal_id = f"principal:{sid.casefold()}"
                nodes[principal_id] = {"id": principal_id, "label": sid, "kind": "principal", "sid": sid}
                edges.append({"source": principal_id, "target": dkm_id, "type": "ControlADFSDKM", "permissions": permissions})
                risks.append(self._risk(
                    RiskTypes.HYBRID_ADFS_DKM_BROAD_ACL,
                    Severity.CRITICAL,
                    f"Broad principal {sid} controls ADFS DKM object {label}",
                    "A broad directory principal has dangerous control over an ADFS Distributed Key Manager object.",
                    label,
                    {"trustee_sid": sid, "permissions": permissions, "target_dn": dn},
                ))
        return risks

    @staticmethod
    def _age_days(value: Any) -> int | None:
        if isinstance(value, datetime):
            moment = value
        else:
            text = as_text(value)
            if not text:
                return None
            if text.isdigit():
                ticks = int(text)
                if ticks <= 0:
                    return None
                moment = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks / 10)
            else:
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

    @staticmethod
    def _risk(risk_type: str, severity: str, title: str, description: str,
              affected: str, evidence: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": risk_type, "severity": severity, "title": title,
            "description": description, "affected_object": affected, "object_type": "configuration",
            "impact": "Hybrid control-plane compromise can bridge on-premises access into cloud or federation identity takeover.",
            "attack_scenario": "An attacker steals or modifies a synchronization, Kerberos, Seamless SSO, or ADFS key and impersonates users.",
            "mitigation": "Treat hybrid components as Tier 0, rotate keys, minimize replication rights, and restrict DKM and service-account ACLs.",
            "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
            "evidence": evidence,
        }

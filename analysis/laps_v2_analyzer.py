"""Deep Windows LAPS coverage, encryption, DSRM, history, and ACL checks."""

from __future__ import annotations

import logging
from typing import Any

from core.ad_identity import computer_is_domain_controller, schema_supports_attribute
from core.ad_security import as_text, dangerous_broad_aces, parsed_security_descriptor
from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)


class WindowsLAPSV2Analyzer:
    """Assess Windows LAPS without retrieving any password value."""

    def __init__(self, ldap_connection: Any):
        self.ldap = ldap_connection

    def analyze(self, computers: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if schema_supports_attribute(self.ldap, "msLAPS-EncryptedPassword") is False:
            return []

        covered = self._presence("msLAPS-PasswordExpirationTime")
        encrypted = self._presence("msLAPS-EncryptedPassword")
        history = self._presence("msLAPS-EncryptedPasswordHistory")
        if covered is None and encrypted is None:
            return []

        covered = covered or []
        encrypted = encrypted or []
        history = history or []
        covered_dns = self._dns(covered)
        encrypted_dns = self._dns(encrypted)
        history_dns = self._dns(history)
        risks: list[dict[str, Any]] = []

        plaintext_or_unencrypted = covered_dns - encrypted_dns
        if plaintext_or_unencrypted:
            risks.append({
                "type": RiskTypes.WINDOWS_LAPS_ENCRYPTION_GAP,
                "severity": Severity.HIGH,
                "title": f"Windows LAPS encryption gap on {len(plaintext_or_unencrypted)} computers",
                "description": (
                    "Windows LAPS expiration metadata is present, but no encrypted password value was "
                    "observed for these computer objects. No password content was requested."
                ),
                "affected_object": self._sample(plaintext_or_unencrypted),
                "object_type": "computer",
                "impact": "Plaintext or incomplete LAPS deployment can expose reusable local administrator credentials.",
                "attack_scenario": "A principal with directory read access retrieves a non-encrypted local administrator password.",
                "mitigation": "Enable ADPasswordEncryptionEnabled, verify DFL 2016+, rotate affected passwords, and restrict LAPS rights.",
                "mitre_attack": MITRETechniques.UNSECURED_CREDENTIALS,
                "evidence": {"covered_count": len(covered_dns), "encrypted_count": len(encrypted_dns)},
            })

        history_missing = encrypted_dns - history_dns
        if encrypted_dns and history_missing == encrypted_dns:
            risks.append({
                "type": RiskTypes.WINDOWS_LAPS_HISTORY_DISABLED,
                "severity": Severity.LOW,
                "title": "Windows LAPS encrypted password history is not observed",
                "description": (
                    "Encrypted Windows LAPS passwords are deployed, but no encrypted password-history "
                    "value was observed. The default history size is zero."
                ),
                "affected_object": self.ldap.base_dn,
                "object_type": "configuration",
                "impact": "Incident response and controlled rollback options are reduced when encrypted history is disabled.",
                "attack_scenario": "A newly rotated credential cannot be compared with prior protected values during investigation.",
                "mitigation": "Consider a bounded ADEncryptedPasswordHistorySize after reviewing retention and access requirements.",
                "evidence": {"encrypted_computer_count": len(encrypted_dns)},
            })

        dc_dns = {
            as_text(item.get("distinguishedName") or item.get("dn")).casefold()
            for item in computers if computer_is_domain_controller(item)
            and as_text(item.get("distinguishedName") or item.get("dn"))
        }
        if dc_dns and schema_supports_attribute(self.ldap, "msLAPS-EncryptedDSRMPassword") is not False:
            dsrm_rows = self._presence("msLAPS-EncryptedDSRMPassword") or []
            dsrm_dns = self._dns(dsrm_rows)
            missing_dc_dns = dc_dns - dsrm_dns
            if missing_dc_dns:
                risks.append({
                    "type": RiskTypes.WINDOWS_LAPS_DSRM_NOT_BACKED_UP,
                    "severity": Severity.MEDIUM,
                    "title": f"Windows LAPS DSRM backup missing on {len(missing_dc_dns)} domain controllers",
                    "description": "No encrypted DSRM password backup was observed on the affected domain controller objects.",
                    "affected_object": self._sample(missing_dc_dns),
                    "object_type": "computer",
                    "impact": "Unmanaged DSRM credentials weaken domain-controller recovery and credential-rotation assurance.",
                    "attack_scenario": "A stale or shared DSRM password remains usable during offline recovery access.",
                    "mitigation": "Enable ADBackupDSRMPassword with Windows LAPS and verify successful encrypted backups on every writable DC.",
                    "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
                    "evidence": {"domain_controller_count": len(dc_dns), "dsrm_backup_count": len(dc_dns & dsrm_dns)},
                })

        risks.extend(self._analyze_broad_acls(encrypted_dns or covered_dns))
        return risks

    def _presence(self, attribute: str) -> list[dict[str, Any]] | None:
        if schema_supports_attribute(self.ldap, attribute) is False:
            return []
        try:
            return self.ldap.search(
                search_base=self.ldap.base_dn,
                search_filter=f"(&(objectClass=computer)({attribute}=*))",
                attributes=["distinguishedName", "sAMAccountName"],
            ) or []
        except Exception as exc:
            message = str(exc).casefold()
            if "invalid attribute" in message:
                return None
            logger.debug("Windows LAPS presence search failed for %s: %s", attribute, exc)
            return []

    def _analyze_broad_acls(self, target_dns: set[str]) -> list[dict[str, Any]]:
        if not target_dns:
            return []
        try:
            rows = self.ldap.search(
                search_base=self.ldap.base_dn,
                search_filter="(&(objectClass=computer)(msLAPS-PasswordExpirationTime=*))",
                attributes=["distinguishedName", "nTSecurityDescriptor"],
            ) or []
        except Exception as exc:
            logger.debug("Windows LAPS ACL search failed: %s", exc)
            return []

        by_sid: dict[str, set[str]] = {}
        permissions_by_sid: dict[str, set[str]] = {}
        for row in rows:
            dn = as_text(row.get("distinguishedName"))
            if not dn or dn.casefold() not in target_dns:
                continue
            for ace in dangerous_broad_aces(parsed_security_descriptor(row.get("nTSecurityDescriptor"))):
                sid = str(ace.get("sid") or "unknown")
                by_sid.setdefault(sid, set()).add(dn)
                permissions_by_sid.setdefault(sid, set()).update((ace.get("permissions") or {}).keys())

        findings: list[dict[str, Any]] = []
        for sid, dns in sorted(by_sid.items()):
            findings.append({
                "type": RiskTypes.WINDOWS_LAPS_BROAD_ACL,
                "severity": Severity.HIGH,
                "title": f"Broad principal {sid} controls Windows LAPS computer objects",
                "description": (
                    f"{sid} has dangerous directory-control permissions on {len(dns)} Windows LAPS-managed "
                    "computer object(s). This is an ACL control-path finding; no password was read."
                ),
                "affected_object": self._sample(dns),
                "object_type": "computer",
                "impact": "Broad write or ownership rights can be converted into LAPS secret access or policy tampering.",
                "attack_scenario": "A low-trust principal changes an object ACL or LAPS-related attribute to obtain local administrator access.",
                "mitigation": "Remove broad control ACEs and delegate LAPS administration only to tightly scoped support groups.",
                "mitre_attack": MITRETechniques.UNSECURED_CREDENTIALS,
                "evidence": {"trustee_sid": sid, "permissions": sorted(permissions_by_sid[sid]), "object_count": len(dns)},
            })
        return findings

    @staticmethod
    def _dns(rows: list[dict[str, Any]]) -> set[str]:
        return {
            as_text(row.get("distinguishedName") or row.get("dn")).casefold()
            for row in rows if as_text(row.get("distinguishedName") or row.get("dn"))
        }

    @staticmethod
    def _sample(values: set[str]) -> str:
        ordered = sorted(values)
        return ", ".join(ordered[:10]) + (f" ... (+{len(ordered) - 10} more)" if len(ordered) > 10 else "")

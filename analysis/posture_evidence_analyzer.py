"""Offline DC/GPO posture evidence collector and verifier."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import re
from typing import Any
import xml.etree.ElementTree as ET

from core.constants import MITRETechniques, RiskTypes, Severity
from core.control_evidence import evidence_status, observation_document
from core.evidence_signing import read_json, unwrap_document

logger = logging.getLogger(__name__)


def refresh_posture_findings(previous, result):
    """Keep previously observed weaknesses visible when their evidence expires."""
    from core.finding_evidence import invalidate_finding_evidence

    risks = list(result['risks'])
    states = {(str(row['target']).casefold(), row.get('policy')): row['status'] for row in result['checks']}
    for original in previous:
        if original.get('type') == RiskTypes.POSTURE_EVIDENCE_INCOMPLETE:
            continue
        basis = original.get('review_basis') or original
        unresolved = []
        for row in (basis.get('evidence') or {}).get('posture_values', []):
            policy = row.get('policy') or PostureEvidenceAnalyzer._normalize_key(row.get('name') or '')
            state = states.get((str(row.get('target') or '').casefold(), policy), 'unknown')
            if state not in ('secure', 'insecure', 'not_applicable'):
                unresolved.append(row)
        if not unresolved:
            continue
        current = next((risk for risk in risks if risk.get('type') == original.get('type')), None)
        if current:
            current['evidence']['unverified_previous_observations'] = unresolved
        else:
            retained = invalidate_finding_evidence(original, 'unknown')
            retained['evidence']['posture_values'] = unresolved
            risks.append(retained)
    return risks


class PostureEvidenceAnalyzer:
    """Verify controls that LDAP attributes alone cannot prove."""

    MAX_FILE_BYTES = 64 * 1024 * 1024
    CONTROL_ALIASES = {
        "ldap_signing": ("ldapserverintegrity", "ldapserverenforceintegrity"),
        "channel_binding": ("ldapenforcechannelbinding",),
        "ntlm_restriction": (
            "restrictntlmindomain", "restrictreceivingntlmtraffic", "restrictsendingntlmtraffic",
        ),
        "smb_signing": ("requiresecuritysignature",),
        "kerberos_encryption": ("defaultdomainsupportedenctypes", "supportedencryptiontypes"),
        "certificate_mapping": ("certificatemappingmethods",),
    }

    def analyze(self, paths: list[str], observations: list[dict[str, Any]] | None = None,
                *, domain=None, targets=None, now=None, max_age_days=30,
                trusted_keys=None, require_signed=False, expected_targets=None) -> dict[str, Any]:
        values: dict[str, list[dict[str, Any]]] = {}
        errors: list[dict[str, str]] = []
        for raw_path in paths:
            path = Path(raw_path)
            try:
                if path.suffix.casefold() == '.json':
                    document, signature = unwrap_document(read_json(str(path)), trusted_keys, require_signed)
                    expected_domain = domain or document.get('domain')
                    if not expected_domain:
                        raise ValueError('Posture evidence requires domain and target-bound observations')
                    rows = observation_document(document, expected_domain, now=now, max_age_days=max_age_days, targets=targets)
                    for row in rows:
                        row['signature_status'] = signature['status']
                        values.setdefault(self._normalize_key(row.get('name') or ''), []).append(row)
                else:
                    # Unbound exports are never authoritative endpoint observations.
                    if require_signed:
                        raise ValueError('Raw posture exports cannot satisfy signed-evidence policy')
                    for key, value in self._load(path).items():
                        values.setdefault(self._normalize_key(key), []).append(
                            {'value': value, 'source': str(path), 'status': 'unknown',
                             'reason': 'Raw export lacks target, domain and collection time'})
            except Exception as exc:
                if require_signed:
                    raise
                logger.warning("Could not parse posture evidence %s: %s", path, exc)
                errors.append({"path": str(path), "error": str(exc)})

        for observation in observations or []:
            row = dict(observation)
            # Reviewed collector documents have already checked domain binding.
            row.setdefault('domain', domain)
            reason = evidence_status(row, domain, now=now, max_age_days=max_age_days, targets=targets)
            row.update(status='unknown' if reason else 'available', reason=reason)
            values.setdefault(self._normalize_key(row.get('name') or ''), []).append(row)
        resolved: dict[str, list[dict[str, Any]]] = {}
        checks = []
        server2025 = set()
        older_servers = set()
        for record in values.get('operatingsystem', []):
            value = record.get('value')
            if record.get('status') == 'available' and isinstance(value, dict) and 'server' in str(value.get('caption', '')).casefold():
                build = self._int(value.get('build'))
                if build is not None:
                    (server2025 if build >= 26100 else older_servers).add(str(record.get('target') or '').casefold())
        for control, aliases in self.CONTROL_ALIASES.items():
            matches = []
            for key, records in values.items():
                if any(key.endswith(alias) for alias in aliases):
                    matches.extend({**record, 'policy': next(alias for alias in aliases if key.endswith(alias))}
                                   for record in records)
            if matches:
                grouped = {}
                for record in matches:
                    grouped.setdefault((str(record.get('target') or 'unknown').casefold(), record['policy']), []).append(record)
                for (target, policy), records in grouped.items():
                    evaluated = [self._policy_state(policy, record.get('value')) for record in records]
                    invalid = any(record.get('status') != 'available' for record in records)
                    conflict = len({self._int(record.get('value')) for record in records}) > 1
                    state = 'conflicting' if conflict else 'unknown' if invalid or 'unknown' in evaluated else evaluated[0]
                    if policy == 'ldapserverenforceintegrity':
                        if target in older_servers and target in server2025:
                            state = 'conflicting'
                        elif target in older_servers:
                            state = 'not_applicable'
                        elif target not in server2025:
                            state = 'unknown'
                    reason = next((record.get('reason') for record in records if record.get('reason')), None)
                    checks.append({'target': target, 'control': control, 'policy': policy, 'status': state,
                                   'source_count': len(records), 'reason': reason or ('Conflicting values' if conflict else
                                   'Invalid or unsupported policy value' if state == 'unknown' else None)})
                    if state in ('secure', 'insecure'):
                        resolved.setdefault(control, []).extend({**record, 'policy_status': state} for record in records)

        risks: list[dict[str, Any]] = []
        risks.extend(self._check_minimum(resolved, "ldap_signing", 2, RiskTypes.POSTURE_LDAP_SIGNING_WEAK,
                                         "LDAP signing is not required", Severity.HIGH))
        risks.extend(self._check_minimum(resolved, "channel_binding", 2, RiskTypes.POSTURE_CHANNEL_BINDING_WEAK,
                                         "LDAP channel binding is not fully enforced", Severity.HIGH))
        risks.extend(self._check_minimum(resolved, "ntlm_restriction", 2, RiskTypes.POSTURE_NTLM_RESTRICTION_WEAK,
                                         "NTLM restrictions are permissive", Severity.MEDIUM))
        risks.extend(self._check_minimum(resolved, "smb_signing", 1, RiskTypes.POSTURE_SMB_SIGNING_WEAK,
                                         "SMB signing is not required", Severity.HIGH))
        risks.extend(self._check_kerberos(resolved.get("kerberos_encryption") or []))
        risks.extend(self._check_certificate_mapping(resolved.get("certificate_mapping") or []))
        for target in expected_targets or []:
            for control in self.CONTROL_ALIASES:
                if not any(check['target'].casefold() == target.casefold() and check['control'] == control for check in checks):
                    checks.append({'target': target, 'control': control, 'status': 'unknown', 'source_count': 0,
                                   'reason': 'No fresh policy evidence for this assessed domain controller'})
        # Server 2025 enforcement takes precedence over the legacy signing setting.
        enforcing = {row['target'] for row in checks if row.get('policy') == 'ldapserverenforceintegrity' and row['status'] == 'secure'}
        if enforcing:
            for risk in list(risks):
                if risk['type'] == RiskTypes.POSTURE_LDAP_SIGNING_WEAK:
                    rows = [row for row in risk['evidence']['posture_values'] if str(row.get('target') or '').casefold() not in enforcing]
                    if not rows:
                        risks.remove(risk)
                    else:
                        risk['evidence']['posture_values'] = rows
            for check in checks:
                if check['control'] == 'ldap_signing' and check['target'] in enforcing and check['status'] == 'insecure':
                    check.update(status='secure', configured_status='insecure', effective_policy='LDAPServerEnforceIntegrity',
                                 reason='Server signing enforcement policy overrides the legacy setting')
        if (paths or observations) and len(resolved) < len(self.CONTROL_ALIASES):
            missing = sorted(set(self.CONTROL_ALIASES) - set(resolved))
            risks.append({
                "type": RiskTypes.POSTURE_EVIDENCE_INCOMPLETE,
                "severity": Severity.LOW,
                "title": f"Posture evidence does not cover {len(missing)} controls",
                "description": "The supplied DC/GPO evidence did not contain every supported registry or policy value.",
                "affected_object": ", ".join(missing),
                "object_type": "configuration",
                "impact": "Uncollected endpoint controls remain unknown rather than verified secure.",
                "attack_scenario": "A permissive DC policy remains hidden because the relevant exported setting was absent.",
                "mitigation": "Export the missing GPO/registry settings from every domain controller and repeat the assessment.",
                "evidence": {"missing_controls": missing, "source_files": paths, "requires_runtime_validation": True},
            })
        return {
            "risks": risks,
            "summary": {
                "input_files": len(paths), "parsed_values": sum(len(items) for items in values.values()),
                "covered_controls": sorted(resolved),
                "missing_controls": sorted(set(self.CONTROL_ALIASES) - set(resolved)),
                "parse_errors": errors, "finding_count": len(risks),
            },
            "evidence": resolved,
            "observations": [{**row, 'name': row.get('name') or name}
                             for name, records in values.items() for row in records],
            "checks": checks,
        }

    @classmethod
    def _policy_state(cls, policy, raw):
        value = cls._int(raw)
        enums = {'ldapserverintegrity': {0, 1, 2}, 'ldapserverenforceintegrity': {0, 1},
                 'ldapenforcechannelbinding': {0, 1, 2}, 'requiresecuritysignature': {0, 1},
                 'restrictntlmindomain': {0, 1, 2, 4, 7}, 'restrictreceivingntlmtraffic': {0, 1, 2},
                 'restrictsendingntlmtraffic': {0, 1, 2}}
        if policy in enums and value not in enums[policy]:
            return 'unknown'
        if value is None or value < 0:
            return 'unknown'
        if policy in ('defaultdomainsupportedenctypes', 'supportedencryptiontypes'):
            return 'unknown' if value & ~0x3ff else 'insecure' if value & 4 or not value & 0x18 else 'secure'
        if policy == 'certificatemappingmethods':
            return 'unknown' if value & ~0x1f else 'insecure' if value & 7 else 'secure'
        # Incoming value 1 denies domain accounts; outgoing value 1 is audit only.
        required = {'restrictntlmindomain': 7, 'restrictreceivingntlmtraffic': 1,
                    'restrictsendingntlmtraffic': 2, 'ldapserverintegrity': 2,
                    'ldapserverenforceintegrity': 1, 'ldapenforcechannelbinding': 2,
                    'requiresecuritysignature': 1}
        if policy == 'ldapserverenforceintegrity' and value == 0:
            return 'unknown'  # Disabled enforcement delegates to the legacy setting.
        return 'secure' if value >= required[policy] else 'insecure'

    def _load(self, path: Path) -> dict[str, Any]:
        if not path.is_file():
            raise ValueError("posture evidence path is not a regular file")
        if path.stat().st_size > self.MAX_FILE_BYTES:
            raise ValueError("posture evidence file exceeds the 64 MiB safety limit")
        text = path.read_text(encoding="utf-8-sig")
        if path.suffix.casefold() == ".json" or text.lstrip().startswith(("{", "[")):
            payload = json.loads(text)
            flattened: dict[str, Any] = {}
            self._flatten_json(payload, flattened)
            return flattened
        if path.suffix.casefold() == ".xml" or text.lstrip().startswith("<"):
            return self._load_xml(text)
        values: dict[str, Any] = {}
        for line in text.splitlines():
            match = re.match(r"\s*([^#;][^=:\r\n]+?)\s*(?:=|:)\s*(.*?)\s*$", line)
            if match:
                values[match.group(1)] = match.group(2)
        return values

    @classmethod
    def _flatten_json(cls, value: Any, out: dict[str, Any], prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_key = f"{prefix}.{key}" if prefix else str(key)
                cls._flatten_json(child, out, child_key)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                cls._flatten_json(child, out, f"{prefix}.{index}")
        else:
            out[prefix] = value

    @staticmethod
    def _load_xml(text: str) -> dict[str, Any]:
        root = ET.fromstring(text)
        values: dict[str, Any] = {}
        for element in root.iter():
            tag = element.tag.rsplit("}", 1)[-1]
            name = element.attrib.get("Name") or element.attrib.get("name")
            if name and (element.text or "").strip():
                values[f"{tag}.{name}"] = element.text.strip()
            for key, value in element.attrib.items():
                values[f"{tag}.{key}"] = value
        return values

    @staticmethod
    def _normalize_key(value: str) -> str:
        return re.sub(r"[^a-z0-9]", "", str(value).casefold())

    @staticmethod
    def _int(value: Any) -> int | None:
        if isinstance(value, bool):
            return int(value)
        text = str(value).strip()
        aliases = {"enabled": 1, "true": 1, "disabled": 0, "false": 0}
        if text.casefold() in aliases:
            return aliases[text.casefold()]
        try:
            return int(text, 0)
        except ValueError:
            return None

    def _check_minimum(self, resolved: dict[str, list[dict[str, Any]]], control: str,
                       minimum: int, risk_type: str, title: str, severity: str) -> list[dict[str, Any]]:
        weak = [record for record in resolved.get(control, []) if record.get('policy_status') == 'insecure']
        return [self._risk(
            risk_type, severity, title,
            f"One or more supplied posture values for {control} are below the required value {minimum}.",
            control, weak,
        )] if weak else []

    def _check_kerberos(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        weak = []
        for record in records:
            value = self._int(record["value"])
            if value is not None and (value & 0x04 or not value & 0x18):
                weak.append(record)
        return [self._risk(
            RiskTypes.POSTURE_KERBEROS_RC4_ALLOWED, Severity.HIGH,
            "Domain-controller Kerberos policy still permits RC4",
            "The supplied supported-encryption policy includes RC4 or omits both AES types.",
            "Kerberos KDC posture", weak,
        )] if weak else []

    def _check_certificate_mapping(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        weak = []
        for record in records:
            value = self._int(record["value"])
            if value is not None and value & 0x07:
                weak.append(record)
        return [self._risk(
            RiskTypes.POSTURE_CERTIFICATE_MAPPING_WEAK, Severity.HIGH,
            "Schannel weak certificate mapping methods are enabled",
            "CertificateMappingMethods enables one or more weak Subject/Issuer, Issuer, or UPN mapping bits.",
            "Schannel posture", weak,
        )] if weak else []

    @staticmethod
    def _risk(risk_type: str, severity: str, title: str, description: str,
              affected: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "type": risk_type, "severity": severity, "title": title, "description": description,
            "affected_object": affected, "object_type": "configuration",
            "impact": "A verified permissive domain-controller policy can enable relay, downgrade, or weak authentication paths.",
            "attack_scenario": "An attacker uses a protocol that the endpoint policy should have required, restricted, or disabled.",
            "mitigation": "Apply the hardened GPO value to every domain controller and verify resultant policy with fresh evidence.",
            "mitre_attack": MITRETechniques.LATERAL_MOVEMENT,
            "evidence": {"posture_values": records, "source": "offline_posture_import"},
        }

"""Offline DC/GPO posture evidence collector and verifier."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import re
from typing import Any
import xml.etree.ElementTree as ET

from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)


class PostureEvidenceAnalyzer:
    """Verify controls that LDAP attributes alone cannot prove."""

    MAX_FILE_BYTES = 64 * 1024 * 1024
    CONTROL_ALIASES = {
        "ldap_signing": ("ldapserverintegrity",),
        "channel_binding": ("ldapenforcechannelbinding",),
        "ntlm_restriction": (
            "restrictntlmindomain", "restrictreceivingntlmtraffic", "restrictsendingntlmtraffic",
        ),
        "smb_signing": ("requiresecuritysignature",),
        "kerberos_encryption": ("defaultdomainsupportedenctypes", "supportedencryptiontypes"),
        "certificate_mapping": ("certificatemappingmethods",),
    }

    def analyze(self, paths: list[str]) -> dict[str, Any]:
        values: dict[str, list[dict[str, Any]]] = {}
        errors: list[dict[str, str]] = []
        for raw_path in paths:
            path = Path(raw_path)
            try:
                loaded = self._load(path)
                for key, value in loaded.items():
                    normalized = self._normalize_key(key)
                    values.setdefault(normalized, []).append({"value": value, "source": str(path)})
            except Exception as exc:
                logger.warning("Could not parse posture evidence %s: %s", path, exc)
                errors.append({"path": str(path), "error": str(exc)})

        resolved: dict[str, list[dict[str, Any]]] = {}
        for control, aliases in self.CONTROL_ALIASES.items():
            matches = []
            for key, records in values.items():
                if any(key.endswith(alias) for alias in aliases):
                    matches.extend(records)
            if matches:
                resolved[control] = matches

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
        if paths and len(resolved) < len(self.CONTROL_ALIASES):
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
        }

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
        weak = [record for record in resolved.get(control, []) if (self._int(record["value"]) or 0) < minimum]
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

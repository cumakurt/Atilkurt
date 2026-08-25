"""Forensic, read-only analysis of ``msDS-KeyCredentialLink`` values."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import logging
from typing import Any
from uuid import UUID

from core.ad_identity import account_has_privileged_evidence
from core.ad_security import as_list, as_text
from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class KeyCredentialRecord:
    """Safely reportable metadata parsed from a KEYCREDENTIALLINK_BLOB."""

    valid: bool = False
    version: int | None = None
    key_usage: int | None = None
    key_source: int | None = None
    device_id: str | None = None
    creation_time: str | None = None
    approximate_last_logon: str | None = None
    key_id: str | None = None
    errors: list[str] = field(default_factory=list)

    def evidence(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "key_usage": self.key_usage,
            "key_source": self.key_source,
            "device_id": self.device_id,
            "creation_time": self.creation_time,
            "approximate_last_logon": self.approximate_last_logon,
            "key_id": self.key_id,
            "parse_errors": list(self.errors),
        }


class KeyCredentialParser:
    """Parse Binary-DN or raw KEYCREDENTIALLINK_BLOB values.

    The parser intentionally exposes only metadata and a short SHA-256 key ID;
    public-key material is never copied into findings or exports.
    """

    VERSION_2 = 0x00000200
    ENTRY_KEY_ID = 0x01
    ENTRY_KEY_HASH = 0x02
    ENTRY_KEY_MATERIAL = 0x03
    ENTRY_KEY_USAGE = 0x04
    ENTRY_KEY_SOURCE = 0x05
    ENTRY_DEVICE_ID = 0x06
    ENTRY_CUSTOM_KEY_INFORMATION = 0x07
    ENTRY_APPROXIMATE_LAST_LOGON = 0x08
    ENTRY_CREATION_TIME = 0x09

    @classmethod
    def parse(cls, value: Any) -> KeyCredentialRecord:
        record = KeyCredentialRecord()
        blob = cls._blob_bytes(value)
        if blob is None or len(blob) < 4:
            record.errors.append("value is not a valid Binary-DN or binary blob")
            return record

        record.version = int.from_bytes(blob[:4], "little")
        if record.version != cls.VERSION_2:
            record.errors.append(f"unexpected blob version {record.version:#x}")

        entries: dict[int, bytes] = {}
        offset = 4
        while offset < len(blob):
            if offset + 3 > len(blob):
                record.errors.append("truncated entry header")
                break
            length = int.from_bytes(blob[offset:offset + 2], "little")
            identifier = blob[offset + 2]
            offset += 3
            if length <= 0 or offset + length > len(blob):
                record.errors.append(f"invalid entry length for identifier {identifier:#x}")
                break
            if identifier in entries:
                record.errors.append(f"duplicate entry identifier {identifier:#x}")
            entries[identifier] = blob[offset:offset + length]
            offset += length

        record.key_usage = cls._little_int(entries.get(cls.ENTRY_KEY_USAGE))
        record.key_source = cls._little_int(entries.get(cls.ENTRY_KEY_SOURCE))
        record.device_id = cls._guid(entries.get(cls.ENTRY_DEVICE_ID))
        record.creation_time = cls._filetime(entries.get(cls.ENTRY_CREATION_TIME))
        record.approximate_last_logon = cls._filetime(entries.get(cls.ENTRY_APPROXIMATE_LAST_LOGON))
        key_id = entries.get(cls.ENTRY_KEY_ID)
        material = entries.get(cls.ENTRY_KEY_MATERIAL)
        if key_id:
            record.key_id = key_id.hex()[:32]
        elif material:
            record.key_id = hashlib.sha256(material).hexdigest()[:32]

        for required in (cls.ENTRY_KEY_ID, cls.ENTRY_KEY_MATERIAL, cls.ENTRY_KEY_USAGE, cls.ENTRY_KEY_SOURCE):
            if required not in entries:
                record.errors.append(f"required entry {required:#x} is missing")
        if record.key_usage not in (None, 1):
            record.errors.append(f"unexpected KeyUsage {record.key_usage}")
        if record.key_source not in (None, 0):
            record.errors.append(f"unexpected KeySource {record.key_source}")
        if cls.ENTRY_CUSTOM_KEY_INFORMATION in entries:
            record.errors.append("CustomKeyInformation is present")

        record.valid = not record.errors
        return record

    @staticmethod
    def _blob_bytes(value: Any) -> bytes | None:
        if isinstance(value, bytes):
            return value
        if isinstance(value, (bytearray, memoryview)):
            return bytes(value)
        text = str(value or "").strip()
        if not text:
            return None
        if text.upper().startswith("B:"):
            parts = text.split(":", 3)
            if len(parts) < 3:
                return None
            text = parts[2]
        try:
            return bytes.fromhex(text)
        except ValueError:
            return None

    @staticmethod
    def _little_int(value: bytes | None) -> int | None:
        return int.from_bytes(value, "little") if value else None

    @staticmethod
    def _guid(value: bytes | None) -> str | None:
        if not value or len(value) != 16:
            return None
        try:
            return str(UUID(bytes_le=value))
        except ValueError:
            return None

    @staticmethod
    def _filetime(value: bytes | None) -> str | None:
        if not value or len(value) != 8:
            return None
        ticks = int.from_bytes(value, "little")
        if ticks <= 0:
            return None
        try:
            moment = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks / 10)
            return moment.isoformat()
        except (OverflowError, ValueError):
            return None


class KeyCredentialAnalyzer:
    """Identify malformed, anomalous, duplicated, and privileged key credentials."""

    def __init__(self, ldap_connection: Any):
        self.ldap = ldap_connection

    def analyze(self) -> list[dict[str, Any]]:
        try:
            rows = self.ldap.search(
                search_base=self.ldap.base_dn,
                search_filter="(msDS-KeyCredentialLink=*)",
                attributes=[
                    "sAMAccountName", "distinguishedName", "objectClass", "adminCount",
                    "memberOf", "msDS-KeyCredentialLink",
                ],
            ) or []
        except Exception as exc:
            logger.debug("KeyCredentialLink forensic search failed: %s", exc)
            return []

        risks: list[dict[str, Any]] = []
        device_owners: dict[str, set[str]] = {}
        parsed_by_object: list[tuple[str, dict[str, Any], list[KeyCredentialRecord]]] = []

        for row in rows:
            name = as_text(row.get("sAMAccountName") or row.get("distinguishedName")) or "unknown account"
            records = [KeyCredentialParser.parse(value) for value in as_list(row.get("msDS-KeyCredentialLink"))]
            parsed_by_object.append((name, row, records))
            for record in records:
                if record.device_id:
                    device_owners.setdefault(record.device_id.casefold(), set()).add(name)

        duplicated = {device for device, owners in device_owners.items() if len(owners) > 1}
        for name, row, records in parsed_by_object:
            privileged = account_has_privileged_evidence(row)
            for index, record in enumerate(records, 1):
                evidence = record.evidence()
                evidence["credential_index"] = index
                if not record.valid:
                    risks.append(self._risk(
                        RiskTypes.KEY_CREDENTIAL_MALFORMED,
                        Severity.HIGH,
                        f'Malformed key credential on "{name}"',
                        "The KeyCredentialLink value violates the expected version, entry, usage, or source constraints.",
                        name,
                        evidence,
                    ))
                elif record.key_usage != 1 or record.key_source != 0:
                    risks.append(self._risk(
                        RiskTypes.KEY_CREDENTIAL_ANOMALY,
                        Severity.HIGH,
                        f'Unexpected key credential metadata on "{name}"',
                        "The key credential does not use the expected NGC usage and Active Directory source combination.",
                        name,
                        evidence,
                    ))
                if privileged:
                    risks.append(self._risk(
                        RiskTypes.KEY_CREDENTIAL_PRIVILEGED,
                        Severity.HIGH,
                        f'Privileged account "{name}" has a key credential',
                        "A passwordless key credential exists on a protected account and requires ownership validation.",
                        name,
                        evidence,
                    ))
                if record.device_id and record.device_id.casefold() in duplicated:
                    duplicate_evidence = dict(evidence)
                    duplicate_evidence["device_id_owners"] = sorted(device_owners[record.device_id.casefold()])
                    risks.append(self._risk(
                        RiskTypes.KEY_CREDENTIAL_DUPLICATE_DEVICE,
                        Severity.HIGH,
                        f'Device ID reused by multiple key credentials: {record.device_id}',
                        "The same DeviceID appears on more than one directory account, which is unusual and can indicate copied persistence material.",
                        name,
                        duplicate_evidence,
                    ))
        return risks

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
            "impact": "An attacker-controlled key credential can provide passwordless persistence and impersonation.",
            "attack_scenario": "An attacker with write access adds or reuses a key credential and authenticates with PKINIT.",
            "mitigation": "Validate every key owner, remove unexpected values, restrict attribute writes, and monitor directory change event 5136.",
            "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
            "evidence": evidence,
        }

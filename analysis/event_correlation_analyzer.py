"""Offline Windows event / SIEM export correlation for AD findings."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)


class EventCorrelationAnalyzer:
    """Read exported telemetry without contacting endpoints or a SIEM."""

    MAX_FILE_BYTES = 512 * 1024 * 1024
    MAX_EVENTS = 200_000
    SENSITIVE_ATTRIBUTES = frozenset({
        "msds-keycredentiallink", "altsecurityidentities", "ntsecuritydescriptor",
        "msds-allowedtoactonbehalfofotheridentity", "msds-managedaccountprecededbylink",
    })
    REPLICATION_GUID_MARKERS = ("1131f6aa", "1131f6ad", "89e95b76")

    def analyze(
        self, paths: list[str], existing_risks: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        events: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        formats: set[str] = set()
        for raw_path in paths:
            try:
                loaded, format_name = self._load(Path(raw_path))
                formats.add(format_name)
                remaining = self.MAX_EVENTS - len(events)
                if remaining <= 0:
                    break
                events.extend(loaded[:remaining])
            except Exception as exc:
                logger.warning("Could not parse event evidence %s: %s", raw_path, exc)
                errors.append({"path": str(raw_path), "error": str(exc)})

        normalized = [self._normalize(event) for event in events]
        normalized = [event for event in normalized if event.get("event_id") is not None]
        risks: list[dict[str, Any]] = []
        risks.extend(self._rc4_and_roasting(normalized))
        risks.extend(self._asrep(normalized))
        risks.extend(self._directory_changes(normalized))
        risks.extend(self._dcsync(normalized))
        risks.extend(self._certificate_events(normalized, existing_risks or []))
        summary = {
            "input_files": len(paths), "parsed_events": len(normalized),
            "formats": sorted(formats), "parse_errors": errors,
            "finding_count": len(risks),
            "event_id_counts": self._event_counts(normalized),
        }
        return {"risks": risks, "summary": summary}

    def _load(self, path: Path) -> tuple[list[dict[str, Any]], str]:
        if not path.is_file():
            raise ValueError("event evidence path is not a regular file")
        if path.stat().st_size > self.MAX_FILE_BYTES:
            raise ValueError("event evidence file exceeds the 512 MiB safety limit")
        suffix = path.suffix.casefold()
        if suffix == ".evtx":
            return self._load_evtx(path), "evtx"
        text = path.read_text(encoding="utf-8-sig")
        if suffix == ".xml" or text.lstrip().startswith("<"):
            return self._load_xml(text), "xml"
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            events = [json.loads(line) for line in text.splitlines() if line.strip()]
            return [item for item in events if isinstance(item, dict)], "ndjson"
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)], "json"
        if isinstance(payload, dict):
            for key in ("events", "value", "records", "data"):
                if isinstance(payload.get(key), list):
                    return [item for item in payload[key] if isinstance(item, dict)], "json"
            return [payload], "json"
        return [], "json"

    def _load_evtx(self, path: Path) -> list[dict[str, Any]]:
        try:
            from Evtx.Evtx import Evtx  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ValueError("native EVTX support requires the optional python-evtx package") from exc
        events: list[dict[str, Any]] = []
        with Evtx(str(path)) as log:
            for record in log.records():
                events.extend(self._load_xml(record.xml()))
                if len(events) >= self.MAX_EVENTS:
                    break
        return events

    @staticmethod
    def _load_xml(text: str) -> list[dict[str, Any]]:
        root = ET.fromstring(text)
        event_nodes = [root] if root.tag.rsplit("}", 1)[-1] == "Event" else [
            element for element in root.iter() if element.tag.rsplit("}", 1)[-1] == "Event"
        ]
        events: list[dict[str, Any]] = []
        for event_node in event_nodes:
            event: dict[str, Any] = {}
            data: dict[str, Any] = {}
            for element in event_node.iter():
                tag = element.tag.rsplit("}", 1)[-1]
                if tag == "EventID" and element.text:
                    event["EventID"] = element.text
                elif tag == "TimeCreated":
                    event["timestamp"] = element.attrib.get("SystemTime")
                elif tag == "Computer" and element.text:
                    event["Computer"] = element.text
                elif tag == "Provider":
                    event["Provider"] = element.attrib.get("Name")
                elif tag == "Data":
                    key = element.attrib.get("Name") or f"Data{len(data)}"
                    data[key] = element.text or ""
            event["EventData"] = data
            events.append(event)
        return events

    @classmethod
    def _normalize(cls, event: dict[str, Any]) -> dict[str, Any]:
        flat: dict[str, Any] = {}
        cls._flatten(event, flat)
        event_id = cls._first(flat, "eventid", "event_id", "winlog.event_id", "system.eventid")
        try:
            event_id = int(str(event_id).strip())
        except (TypeError, ValueError):
            event_id = None
        timestamp = cls._first(flat, "timestamp", "timecreated.systemtime", "@timestamp", "systemtime")
        fields = {key.casefold(): value for key, value in flat.items()}
        return {
            "event_id": event_id,
            "timestamp": str(timestamp or ""),
            "provider": str(cls._first(fields, "provider", "system.provider.name") or ""),
            "computer": str(cls._first(fields, "computer", "winlog.computer_name") or ""),
            "fields": fields,
        }

    @classmethod
    def _flatten(cls, value: Any, out: dict[str, Any], prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_key = f"{prefix}.{key}" if prefix else str(key)
                cls._flatten(child, out, child_key)
                out.setdefault(str(key), child)
        elif isinstance(value, list):
            out[prefix] = value
        else:
            out[prefix] = value

    @staticmethod
    def _first(mapping: dict[str, Any], *keys: str) -> Any:
        lowered = {str(key).casefold(): value for key, value in mapping.items()}
        for key in keys:
            value = lowered.get(key.casefold())
            if value not in (None, ""):
                return value
        return None

    def _rc4_and_roasting(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rc4: list[dict[str, Any]] = []
        bursts: dict[tuple[str, str], set[str]] = defaultdict(set)
        for event in events:
            if event["event_id"] != 4769:
                continue
            fields = event["fields"]
            encryption = self._first(fields, "ticketencryptiontype", "ticket_encryption_type", "eventdata.ticketencryptiontype")
            try:
                encryption_value = int(str(encryption), 0)
            except (TypeError, ValueError):
                encryption_value = None
            requester = str(self._first(fields, "targetusername", "subjectusername", "accountname", "clientaddress") or "unknown")
            service = str(self._first(fields, "servicename", "targetserverName", "service_name") or "unknown")
            bucket = self._time_bucket(event.get("timestamp"))
            bursts[(requester, bucket)].add(service)
            if encryption_value == 0x17:
                rc4.append(event)
        risks: list[dict[str, Any]] = []
        if rc4:
            risks.append(self._event_risk(
                RiskTypes.EVENT_KERBEROS_RC4_OBSERVED, Severity.HIGH,
                f"Kerberos RC4 ticket issuance observed in {len(rc4)} events",
                "Security event 4769 records show ticket encryption type 0x17 (RC4-HMAC).",
                "Kerberos KDC telemetry", [4769], len(rc4),
            ))
        for (requester, bucket), services in bursts.items():
            if len(services) < 10:
                continue
            risks.append(self._event_risk(
                RiskTypes.EVENT_KERBEROASTING_BURST, Severity.HIGH,
                f'Kerberoasting-style service-ticket burst by "{requester}"',
                f"The requester obtained tickets for {len(services)} distinct services in time bucket {bucket}.",
                requester, [4769], len(services),
                extra={"time_bucket": bucket, "distinct_services": sorted(services)[:50]},
            ))
        return risks

    def _asrep(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        matches = []
        for event in events:
            if event["event_id"] != 4768:
                continue
            preauth = self._first(event["fields"], "preauthtype", "pre_auth_type", "eventdata.preauthtype")
            if str(preauth).strip().casefold() in {"0", "-", "none"}:
                matches.append(event)
        return [self._event_risk(
            RiskTypes.EVENT_ASREP_ACTIVITY, Severity.HIGH,
            f"AS-REP activity without preauthentication observed in {len(matches)} events",
            "Event 4768 shows ticket requests with no Kerberos preauthentication.",
            "Kerberos KDC telemetry", [4768], len(matches),
        )] if matches else []

    def _directory_changes(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_attribute: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            if event["event_id"] != 5136:
                continue
            attribute = str(self._first(
                event["fields"], "attributeldapdisplayname", "attribute", "eventdata.attributeldapdisplayname",
            ) or "").casefold()
            if attribute in self.SENSITIVE_ATTRIBUTES:
                by_attribute[attribute].append(event)
        return [
            self._event_risk(
                RiskTypes.EVENT_SENSITIVE_DIRECTORY_CHANGE,
                Severity.CRITICAL if attribute in {"msds-keycredentiallink", "ntsecuritydescriptor"} else Severity.HIGH,
                f"Sensitive directory attribute changed: {attribute}",
                f"Event 5136 recorded {len(matches)} change(s) to {attribute}.",
                attribute, [5136], len(matches),
            )
            for attribute, matches in sorted(by_attribute.items())
        ]

    def _dcsync(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        matches = []
        for event in events:
            if event["event_id"] != 4662:
                continue
            text = json.dumps(event["fields"], default=str).casefold()
            if any(marker in text for marker in self.REPLICATION_GUID_MARKERS):
                matches.append(event)
        return [self._event_risk(
            RiskTypes.EVENT_DCSYNC_ACTIVITY, Severity.CRITICAL,
            f"Directory replication access observed in {len(matches)} event(s)",
            "Event 4662 contains one or more directory replication extended-right GUIDs.",
            "Domain replication", [4662], len(matches),
        )] if matches else []

    def _certificate_events(
        self, events: list[dict[str, Any]], existing_risks: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        risks: list[dict[str, Any]] = []
        mapping_failures = [event for event in events if event["event_id"] in {39, 40, 41}]
        if mapping_failures:
            risks.append(self._event_risk(
                RiskTypes.EVENT_CERTIFICATE_MAPPING_FAILURE, Severity.HIGH,
                f"Strong certificate-mapping failures observed in {len(mapping_failures)} events",
                "KDC events 39/40/41 indicate missing, backdated, or SID-mismatched strong certificate mappings.",
                "KDC certificate mapping", [39, 40, 41], len(mapping_failures),
            ))
        risky_templates = {
            str(risk.get("affected_object") or "").casefold()
            for risk in existing_risks if str(risk.get("type") or "").startswith("certificate_")
        }
        suspicious = []
        for event in events:
            if event["event_id"] not in {4886, 4887}:
                continue
            template = str(self._first(event["fields"], "certificatetemplatename", "template", "eventdata.certificatetemplatename") or "").casefold()
            if template and template in risky_templates:
                suspicious.append(event)
        if suspicious:
            risks.append(self._event_risk(
                RiskTypes.EVENT_SUSPICIOUS_CERTIFICATE_ISSUANCE, Severity.CRITICAL,
                f"Issuance activity observed for risky certificate templates ({len(suspicious)} events)",
                "Certificate Services events 4886/4887 match a template already flagged by the LDAP assessment.",
                "AD CS issuance", [4886, 4887], len(suspicious),
            ))
        return risks

    @staticmethod
    def _event_risk(risk_type: str, severity: str, title: str, description: str,
                    affected: str, event_ids: list[int], count: int,
                    extra: dict[str, Any] | None = None) -> dict[str, Any]:
        evidence = {"event_ids": event_ids, "event_count": count, "source": "offline_event_import"}
        evidence.update(extra or {})
        return {
            "type": risk_type, "severity": severity, "title": title, "description": description,
            "affected_object": affected, "object_type": "telemetry",
            "impact": "Observed telemetry raises confidence that the configured attack surface is being exercised.",
            "attack_scenario": "An attacker performs authentication, replication, certificate, or directory-change activity visible in Windows logs.",
            "mitigation": "Validate the initiating identity and host, contain suspicious sessions, rotate affected credentials, and preserve event evidence.",
            "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
            "evidence": evidence,
        }

    @staticmethod
    def _time_bucket(value: Any) -> str:
        text = str(value or "")
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
            minute = (moment.minute // 10) * 10
            return moment.replace(minute=minute, second=0, microsecond=0).isoformat()
        except ValueError:
            return "unknown-window"

    @staticmethod
    def _event_counts(events: Iterable[dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for event in events:
            counts[str(event.get("event_id"))] += 1
        return dict(sorted(counts.items()))

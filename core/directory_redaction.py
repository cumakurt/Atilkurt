"""Redact credential-like text stored in directory description fields.

Detection runs on the original values. Checkpoints, exports, and the HTML
inventory keep the field name and the fact that a value was present.
"""

from __future__ import annotations

import re
from typing import Any

_TEXT_FIELDS = frozenset({"description", "info", "comment"})
SECRET_FIELDS = r'password|passwd|pass|pwd|cpassword|secret|secret_value|ntlm|lm|kerberos_key|credential|private.?key|api[_-]?key|(?:access|refresh|auth)[_-]?token|tokenvalue|authorization|connection[_-]?string|ms.?mcs.?admpwd|mslaps.?password'
SECRET_KEYS = re.compile(r'(?i)(?:' + SECRET_FIELDS + r')$')
SECRET_ASSIGNMENT = re.compile(
    r'(?im)(\b(?:' + SECRET_FIELDS + r')\b\s*[=:]\s*)'
    r'''(?:"(?:\\.|[^"\\\r\n])*(?:"|$)|'(?:\\.|[^'\\\r\n])*(?:'|$)|(?:Bearer|Basic)\s+[^\s"';]+|[^\s"';]+)'''
)


def redact_credential_text(value: str) -> str:
    """Replace complete credential assignments, including quoted values."""
    return SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", value)


def redact_nested_secrets(value: Any) -> Any:
    """Copy publication evidence with secrets removed, preserving binary attributes."""
    if isinstance(value, dict):
        return {key: _redact_secret_value(item) if SECRET_KEYS.search(str(key))
                else redact_nested_secrets(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_nested_secrets(item) for item in value]
    return redact_credential_text(value) if isinstance(value, str) else value


def _redact_secret_value(value: Any) -> Any:
    """LDAP attributes and imported evidence can hold multivalued secrets."""
    if isinstance(value, dict):
        return {key: _redact_secret_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_secret_value(item) for item in value]
    return value if value is None or value == '' else '[REDACTED]'


def redact_directory_record(record: dict[str, Any]) -> None:
    """Redact credential assignments on one collected object, in place."""
    for key, value in list(record.items()):
        if str(key).casefold() not in _TEXT_FIELDS or value in (None, "", [], b""):
            continue
        record[key] = _redact_field_value(value)


def redact_assessment_secrets(data: dict[str, Any] | None, analysis: dict[str, Any] | None = None) -> None:
    """Redact collected objects and incremental-diff copies that share them."""
    if isinstance(data, dict):
        for record in (data.get('password_hashes') or {}).get('records', []):
            for field in ('ntlm', 'lm'):
                if record.get(field):
                    record[field] = '[REDACTED]'
            for entry in record.get('nt_history') or []:
                for field in ('ntlm', 'lm'):
                    if isinstance(entry, dict) and entry.get(field):
                        entry[field] = '[REDACTED]'
            for key in record.get('kerberos_keys', []):
                key['kerberos_key'] = '[REDACTED]'
        for name in ("users", "computers", "groups", "gpos"):
            for row in data.get(name) or []:
                if isinstance(row, dict):
                    redact_directory_record(row)
    if isinstance(analysis, dict):
        for risk in analysis.get('shared_file_risks') or []:
            risk.update(redact_nested_secrets(risk))
        for result in (analysis.get('engagement') or {}).get('shared_files') or []:
            for risk in result.get('risks') or []:
                risk.update(redact_nested_secrets(risk))
    diff = (analysis or {}).get("incremental_diff") or {}
    collections = diff.get("collections") if isinstance(diff, dict) else None
    if not isinstance(collections, dict):
        return
    for collection in collections.values():
        if not isinstance(collection, dict):
            continue
        for bucket in ("new", "deleted"):
            for row in collection.get(bucket) or []:
                if isinstance(row, dict):
                    redact_directory_record(row)
        for row in collection.get("changed") or []:
            if not isinstance(row, dict):
                continue
            for side in ("previous", "current"):
                item = row.get(side)
                if isinstance(item, dict):
                    redact_directory_record(item)


def _redact_field_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_credential_text(value)
    if isinstance(value, (list, tuple)):
        redacted = [_redact_field_value(item) for item in value]
        return type(value)(redacted) if isinstance(value, tuple) else redacted
    return value

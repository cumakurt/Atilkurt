"""Validate target-bound, fresh evidence without treating missing data as safe."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from core.exceptions import ValidationError
from core.validators import validate_server_address


def evidence_status(row, domain=None, *, now=None, max_age_days=30, targets=None):
    """Return a reason for unusable provenance, or None for usable evidence."""
    if not isinstance(row, dict):
        return 'Evidence must be an object'
    if domain and str(row.get('domain') or '').casefold().strip('.') != domain.casefold().strip('.'):
        return 'Evidence domain does not match the assessment'
    target = row.get('target')
    try:
        if not isinstance(target, str):
            raise ValidationError('Missing target')
        validate_server_address(target)
    except ValidationError:
        return 'Evidence target is missing or invalid'
    if targets is not None and target.casefold().strip('.') not in {str(t).casefold().strip('.') for t in targets}:
        return 'Evidence target is outside the assessed inventory'
    if not isinstance(row.get('source'), str) or not row['source'].strip():
        return 'Evidence source is missing'
    if len(row['source']) > 4096:
        return 'Evidence source exceeds the size limit'
    try:
        stamp = datetime.fromisoformat(str(row.get('collected_at')).replace('Z', '+00:00'))
        now = now or datetime.now(timezone.utc)
        if stamp.tzinfo is None or not now - timedelta(days=max_age_days) <= stamp <= now + timedelta(minutes=5):
            return 'Evidence is stale, future-dated or lacks a timezone'
    except (ValueError, TypeError):
        return 'Evidence collection time is invalid'
    if row.get('status') not in (None, 'available', 'observed'):
        return 'Evidence was not successfully collected'
    return None


def observation_document(document, domain, *, now=None, max_age_days=30, targets=None):
    """Preserve invalid rows as explicit gaps; validate the document contract."""
    if not isinstance(document, dict) or document.get('schema_version') != 1:
        raise ValidationError('Control evidence requires schema_version 1')
    if str(document.get('domain') or '').casefold().strip('.') != domain.casefold().strip('.'):
        raise ValidationError('Control evidence belongs to a different domain')
    rows = document.get('observations', [])
    if not isinstance(rows, list) or len(rows) > 10000 or any(not isinstance(row, dict) for row in rows):
        raise ValidationError('Control evidence requires at most 10000 observation objects')
    result = []
    for row in rows:
        if not isinstance(row.get('name'), str) or not row['name'].strip() or len(row['name']) > 1024:
            raise ValidationError('Control observations require a nonempty name of at most 1024 characters')
        merged = {**row, 'domain': row.get('domain', document['domain'])}
        reason = evidence_status(merged, domain, now=now, max_age_days=max_age_days, targets=targets)
        result.append({**merged, 'status': 'unknown' if reason else 'available', 'reason': reason})
    return result

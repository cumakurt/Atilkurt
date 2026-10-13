"""Validated engagement scope and a shared, thread-safe network request budget."""

from __future__ import annotations

from datetime import datetime, timezone
import fnmatch
import threading
import time

from ldap3.utils.dn import parse_dn
from ldap3.utils.conv import escape_filter_chars

from core.exceptions import LDAPSearchError, ValidationError


class ScopeLimitError(LDAPSearchError):
    """A request was prevented by engagement boundaries or execution limits."""


def dn_parts(value):
    try:
        return tuple((kind.casefold(), text.casefold()) for kind, text, _ in parse_dn(str(value)))
    except Exception as exc:
        raise ValidationError("Scope contains an invalid distinguished name") from exc


def under_dn(value, root):
    parts, suffix = dn_parts(value), dn_parts(root)
    return bool(suffix) and len(parts) >= len(suffix) and parts[-len(suffix):] == suffix


class AssessmentScope:
    """Count logical network requests, including binds and each LDAP page."""

    def __init__(self, domain, document=None, *, max_queries=None, max_seconds=None, clock=None, utcnow=None):
        document = document or {"schema_version": 1}
        if document.get("schema_version") != 1:
            raise ValidationError("Scope requires schema_version 1")
        known_fields = {'schema_version', 'domains', 'ous', 'metadata_roots', 'hosts', 'computer_hosts',
                        'excluded_hosts', 'excluded_dns', 'services', 'max_queries', 'max_seconds', 'utc_windows'}
        if set(document) - known_fields:
            raise ValidationError('Unknown scope fields; check names before authorizing collection')
        self.domain = str(domain).casefold().strip(".")
        self.document = dict(document)
        self.clock = clock or time.monotonic
        self.utcnow = utcnow or (lambda: datetime.now(timezone.utc))
        self.started = self.clock()
        self.lock = threading.Lock()
        self.requests = 0
        self.prevented = 0
        self.max_queries = max_queries if max_queries is not None else document.get("max_queries", 100000)
        self.max_seconds = max_seconds if max_seconds is not None else document.get("max_seconds", 3600)
        for key, value, upper in (("max_queries", self.max_queries, 10000000), ("max_seconds", self.max_seconds, 86400)):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= upper:
                raise ValidationError(f"Scope {key} must be an integer between 1 and {upper}")
        for name in ("domains", "ous", "metadata_roots", "hosts", "computer_hosts", "excluded_hosts", "excluded_dns", "services"):
            values = document.get(name, [])
            if not isinstance(values, list) or len(values) > 1000 or any(not isinstance(v, str) or not v.strip() for v in values):
                raise ValidationError(f"Scope {name} must be a bounded list of nonempty strings")
            setattr(self, name, list(dict.fromkeys(values)))
        if set(self.services) - {'ldap', 'ldaps', 'smb', 'drs', 'adcs_http'}:
            raise ValidationError('Scope contains an unsupported service name')
        if self.domains and self.domain not in {v.casefold().strip(".") for v in self.domains}:
            raise ValidationError("Assessment domain is outside engagement scope")
        self.base_dn = ",".join("DC=" + part for part in self.domain.split("."))
        for root in self.ous:
            if not under_dn(root, self.base_dn):
                raise ValidationError("Scope OU belongs to another domain")
        for root in self.metadata_roots + self.excluded_dns:
            dn_parts(root)
        self.windows = document.get("utc_windows", [])
        if not isinstance(self.windows, list) or len(self.windows) > 100:
            raise ValidationError("Scope UTC windows must be a bounded list")
        parsed = []
        for window in self.windows:
            try:
                start, end = (datetime.fromisoformat(window[key].replace("Z", "+00:00")) for key in ("start", "end"))
                if start.tzinfo is None or end.tzinfo is None or start >= end:
                    raise ValueError("Invalid interval")
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                raise ValidationError("Scope windows require ordered timezone-aware start/end timestamps") from exc
            parsed.append((start, end))
        self._windows = parsed

    def check_host(self, host, service):
        host = str(host).casefold().strip(".")
        if self.services and service not in self.services:
            raise ScopeLimitError(f"Service is outside scope: {service}")
        if any(fnmatch.fnmatchcase(host, pattern.casefold()) for pattern in self.excluded_hosts):
            raise ScopeLimitError(f"Host is excluded from scope: {host}")
        # Host allowlists use exact names/IPs; exclusions may use shell patterns.
        if self.hosts and host not in {v.casefold().strip(".") for v in self.hosts}:
            raise ScopeLimitError(f"Host is outside scope: {host}")

    def consume(self, host, service):
        with self.lock:
            try:
                self.check_host(host, service)
                now = self.utcnow()
                if self._windows and not any(start <= now < end for start, end in self._windows):
                    raise ScopeLimitError("Current time is outside engagement UTC windows")
                if self.requests >= self.max_queries or self.clock() - self.started >= self.max_seconds:
                    raise ScopeLimitError("Engagement network request/time budget exhausted")
                self.requests += 1
            except ScopeLimitError:
                self.prevented += 1
                raise

    def allows_dn(self, dn):
        if any(dn_parts(dn) == dn_parts(excluded) for excluded in self.excluded_dns):
            return False
        return any(under_dn(dn, root) for root in (self.ous or [self.base_dn]) + self.metadata_roots)

    def query_plan(self, base, ldap_filter):
        """Restrict SUBTREE inventory before dispatch; metadata roots are explicit."""
        if self.ous and dn_parts(base) == dn_parts(self.base_dn):
            roots = list(self.ous)
            if '(objectclass=grouppolicycontainer)' in ldap_filter.casefold():
                roots += [root for root in self.metadata_roots if under_dn(root, self.base_dn)]
        elif self.allows_dn(base):
            roots = [base]
        else:
            raise ScopeLimitError("LDAP search base is outside directory scope")
        exclusions = [f"(!(distinguishedName={escape_filter_chars(dn)}))" for dn in self.excluded_dns]
        exclusions += [f"(!(dNSHostName={escape_filter_chars(host).replace(chr(92) + '2a', '*').replace('?', '*')}))" for host in self.excluded_hosts]
        if self.computer_hosts:
            hosts = ''.join(f'(dNSHostName={escape_filter_chars(host)})' for host in self.computer_hosts)
            exclusions.append('(|(!(objectClass=computer))(|' + hosts + '))')
        if exclusions:
            ldap_filter = "(&" + ldap_filter + "".join(exclusions) + ")"
        return [(root, ldap_filter) for root in roots]

    def snapshot(self):
        with self.lock:
            return {"schema_version": 1, "domain": self.domain, "definition": self.document,
                    "requests": self.requests, "prevented": self.prevented, "max_queries": self.max_queries,
                    "max_seconds": self.max_seconds, "elapsed_seconds": round(self.clock() - self.started, 3),
                    "restricted": bool(self.ous or self.computer_hosts or self.excluded_hosts or self.excluded_dns or self.services),
                    "coverage": "partial" if self.ous or self.computer_hosts or self.excluded_hosts or self.excluded_dns or self.prevented else "domain"}

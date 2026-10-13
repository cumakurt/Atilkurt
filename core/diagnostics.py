"""Local/connection diagnostics and conservative LDAP collection health."""

from __future__ import annotations

from importlib import metadata
import json
import socket
import ssl
import subprocess
import sys
from typing import Any

from core.ad_identity import root_dse_attributes
from core.ad_security import as_list, as_text

SCHEMA_ATTRIBUTES = (
    "objectSid",
    "nTSecurityDescriptor",
    "tokenGroups",
    "msDS-KeyCredentialLink",
    "msLAPS-PasswordExpirationTime",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
)


def collection_health(ldap=None, data: dict[str, Any] | None = None) -> dict[str, Any]:
    records = list(getattr(ldap, "query_audit", []) or [])
    overflow = bool(getattr(ldap, "query_audit_overflow", False))
    failures = sum(record["status"] == "failed" for record in records)
    incomplete = any(record.get("status") == "incomplete" for record in records)
    total_failures = getattr(ldap, 'query_failure_count', None)
    if isinstance(total_failures, int):
        failures = max(failures, total_failures)
    failed_collections = []
    seen_collections = set()
    for name in list(getattr(ldap, "failed_collections", []) or []):
        if name and name not in seen_collections:
            seen_collections.add(name)
            failed_collections.append(name)
    for record in records:
        name = record.get("collection")
        if record.get("status") == "failed" and name and name not in seen_collections:
            seen_collections.add(name)
            failed_collections.append(name)
    unhealthy = bool(failures or overflow or incomplete or failed_collections)
    return {
        "status": "unknown" if not records and not failed_collections else "partial" if unhealthy else "completed",
        "query_count": len(records),
        "failed_queries": failures,
        "failed_collections": failed_collections,
        "record_limit_exceeded": overflow,
        "queries": records,
        "collections": {name: len((data or {}).get(name) or []) for name in ("users", "computers", "groups", "gpos")},
        "limitation": "An unobserved attribute may be unset, unsupported, or unreadable. It does not prove absence or denied access.",
    }


def run_doctor(
    domain: str | None = None, host: str | None = None, *, use_ssl: bool = True, timeout: int = 10, ldap=None
) -> dict[str, Any]:
    checks = [
        {"name": "python", "status": "pass" if sys.version_info >= (3, 9) else "fail", "detail": sys.version.split()[0]}
    ]
    for package in ("ldap3", "pycryptodome", "impacket", "reportlab"):
        try:
            version = metadata.version(package)
            checks.append({"name": package, "status": "pass", "detail": version})
        except metadata.PackageNotFoundError:
            checks.append({"name": package, "status": "fail", "detail": "Required package is missing"})
    try:
        checks.append(
            {
                "name": "ca_store",
                "status": "pass" if ssl.create_default_context().get_ca_certs() else "unknown",
                "detail": "System certificate trust store",
            }
        )
    except (OSError, ssl.SSLError):
        checks.append({"name": "ca_store", "status": "fail", "detail": "Cannot load certificate trust store"})
    target = host or domain
    if target:
        # DNS runs in a disposable process so an OS resolver cannot exceed the
        # caller's deadline while holding the doctor process open.
        try:
            command = [
                sys.executable,
                "-c",
                "import socket,sys,json; print(json.dumps(sorted({r[4][0] for r in socket.getaddrinfo(sys.argv[1],None)})))",
                target,
            ]
            resolved = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=True)
            addresses = json.loads(resolved.stdout)
            checks.append({"name": "dns", "status": "pass", "detail": ", ".join(addresses)})
            with socket.create_connection((addresses[0], 636 if use_ssl else 389), timeout=timeout) as connection:
                if use_ssl:
                    with ssl.create_default_context().wrap_socket(connection, server_hostname=target) as secured:
                        checks.append({"name": "tls", "status": "pass", "detail": secured.version()})
                else:
                    checks.append(
                        {"name": "transport", "status": "pass", "detail": "LDAP TCP reachable; TLS was not requested"}
                    )
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            checks.append({"name": "connection", "status": "fail", "detail": type(exc).__name__})
    if ldap:
        root = root_dse_attributes(ldap, ["defaultNamingContext", "schemaNamingContext", "supportedControl"])
        checks.append(
            {
                "name": "ldap_bind",
                "status": "pass" if getattr(getattr(ldap, "connection", None), "bound", False) else "fail",
                "detail": "Authenticated read-only LDAP connection",
            }
        )
        checks.append(
            {
                "name": "naming_context",
                "status": "pass" if root.get("defaultNamingContext") else "unknown",
                "detail": as_text(root.get("defaultNamingContext")),
            }
        )
        schema = getattr(getattr(getattr(ldap, "connection", None), "server", None), "schema", None)
        types = getattr(schema, "attribute_types", {}) or {}
        known = {str(name).casefold() for name in types}
        for name in SCHEMA_ATTRIBUTES:
            checks.append(
                {
                    "name": "schema:" + name,
                    "status": "pass" if name.casefold() in known else "unknown",
                    "detail": "Schema presence; attribute read permission remains separate",
                }
            )
        try:
            rows = ldap.base_search(ldap.base_dn, ["objectClass", "nTSecurityDescriptor", "minPwdLength"])
            observed = {
                str(key).casefold()
                for row in rows
                for key, value in row.items()
                if value is not None and value != "" and value != [] and value != b""
            }
            for name in ("nTSecurityDescriptor", "minPwdLength"):
                checks.append(
                    {
                        "name": "visibility:" + name,
                        "status": "pass" if name.casefold() in observed else "unknown",
                        "detail": "Visible on the domain root"
                        if name.casefold() in observed
                        else "Value not observed; reason cannot be inferred",
                    }
                )
        except Exception as exc:
            checks.append({"name": "domain_root_read", "status": "fail", "detail": type(exc).__name__})
        checks.append(
            {
                "name": "supported_controls",
                "status": "pass" if root.get("supportedControl") else "unknown",
                "detail": ", ".join(str(value) for value in as_list(root.get("supportedControl"))),
            }
        )
    return {
        "schema_version": 1,
        "checks": checks,
        "summary": {
            status: sum(check["status"] == status for check in checks) for status in ("pass", "fail", "unknown")
        },
    }

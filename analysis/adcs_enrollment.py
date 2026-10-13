"""Classify AD CS enrollment rights and CA publication from LDAP evidence."""

from __future__ import annotations

from typing import Any

from core.ad_identity import (
    PRIVILEGED_GROUP_RIDS,
    account_has_current_privileged_membership,
    is_privileged_group_record,
    ldap_scalar_text,
    sid_is_builtin_privileged,
    sid_is_domain_well_known,
)
from core.ad_security import (
    BROAD_PRINCIPAL_SIDS,
    ace_permission_names,
    as_list,
    parsed_security_descriptor,
    sid_text,
)
from core.security_descriptor_parser import effective_allow_aces

CERTIFICATE_ENROLLMENT_GUID = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
CERTIFICATE_AUTOENROLLMENT_GUID = "a05b8cc2-17bc-4802-a210-e9df1b2d80c8"

ENROLLMENT_PERMISSIONS = frozenset({
    "Certificate-Enrollment",
    "Certificate-AutoEnrollment",
    "AllExtendedRights",
    "GenericAll",
    "WriteDACL",
    "WriteOwner",
})

IGNORE_ENROLLMENT_SIDS = frozenset({
    "S-1-3-0",   # Creator Owner
    "S-1-3-1",   # Creator Group
    "S-1-5-10",  # Principal Self
    "S-1-5-18",  # Local System
})

PRE_WINDOWS_2000_COMPATIBLE_ACCESS = "S-1-5-32-554"
PKI_ADMIN_RIDS = frozenset({526, 527})  # Key Admins, Enterprise Key Admins
LOW_PRIVILEGE_DOMAIN_RIDS = frozenset({513, 515})  # Domain Users, Domain Computers
_PRIVILEGED_DOMAIN_ENROLLMENT_RIDS = frozenset(
    rid for rid in PRIVILEGED_GROUP_RIDS if rid < 544
) | PKI_ADMIN_RIDS

WELL_KNOWN_ENROLLMENT_LABELS = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    PRE_WINDOWS_2000_COMPATIBLE_ACCESS: "Pre-Windows 2000 Compatible Access",
}


def index_enrollment_principals(
    users: list[dict[str, Any]] | None,
    groups: list[dict[str, Any]] | None,
) -> dict[str, dict[str, Any]]:
    """Index collected accounts and groups by SID for trustee classification."""
    principals: dict[str, dict[str, Any]] = {}
    for obj in [*(users or []), *(groups or [])]:
        sid = sid_text(obj.get("objectSid"))
        if sid:
            principals[sid] = obj
    return principals


def template_name_keys(template: dict[str, Any]) -> set[str]:
    """Return casefolded names a CA may list in certificateTemplates."""
    keys: set[str] = set()
    for attribute in ("name", "cn", "displayName"):
        text = ldap_scalar_text(template.get(attribute))
        if text:
            keys.add(text.casefold())
    return keys


def publishing_cas(template: dict[str, Any], cas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return enrollment services that publish the template."""
    keys = template_name_keys(template)
    published: list[dict[str, Any]] = []
    if not keys:
        return published
    for ca in cas:
        names = {ldap_scalar_text(value).casefold() for value in as_list(ca.get("certificateTemplates"))}
        names.discard("")
        if keys & names:
            published.append(ca)
    return published


def enrollment_grants(
    descriptor: Any,
    principals: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Classify Enroll/AutoEnroll-equivalent trustees on a template or CA."""
    parsed = parsed_security_descriptor(descriptor)
    if parsed is None:
        return {"status": "unobserved", "low_privilege": [], "privileged": [], "unknown": []}

    low_privilege: list[dict[str, Any]] = []
    privileged: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ace in effective_allow_aces(parsed):
        permissions = ace_permission_names(ace).intersection(ENROLLMENT_PERMISSIONS)
        if not permissions:
            continue
        sid = str(ace.get("sid") or "")
        if not sid or sid in IGNORE_ENROLLMENT_SIDS or sid in seen:
            continue
        seen.add(sid)
        record = {
            "sid": sid,
            "name": _trustee_label(sid, principals.get(sid)),
            "permissions": sorted(permissions),
        }
        kind = _trustee_class(sid, principals.get(sid))
        if kind == "low":
            low_privilege.append(record)
        elif kind == "privileged":
            privileged.append(record)
        else:
            unknown.append(record)
    return {
        "status": "observed",
        "low_privilege": low_privilege,
        "privileged": privileged,
        "unknown": unknown,
    }


def bind_esc_enrollment_evidence(
    risk: dict[str, Any],
    template: dict[str, Any],
    *,
    cas: list[dict[str, Any]],
    cas_observed: bool,
    principals: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """Attach enrollment/publication evidence, or drop a path LDAP proves unusable.

    Confirmed findings require a low-privilege Enroll-equivalent grant on the
    template and publication on at least one CA. Privileged-only enrollment or
    an unpublished template is not an ESC enrollment path. Unreadable ACLs keep
    the existing needs-validation finding.
    """
    template_enroll = enrollment_grants(template.get("nTSecurityDescriptor"), principals)
    publishers = publishing_cas(template, cas) if cas_observed else []
    missing: list[str] = []

    if template_enroll["status"] == "unobserved":
        missing.append("template enrollment ACL")
    elif not template_enroll["low_privilege"] and not template_enroll["unknown"]:
        return None
    elif not template_enroll["low_privilege"]:
        missing.append("template enrollment ACL")

    if not cas_observed:
        missing.append("CA publication")
    elif not publishers:
        return None

    ca_low: list[dict[str, Any]] = []
    if cas_observed and publishers:
        observed = 0
        ca_unknown_only = False
        for ca in publishers:
            grant = enrollment_grants(ca.get("nTSecurityDescriptor"), principals)
            if grant["status"] == "unobserved":
                continue
            observed += 1
            ca_low.extend(grant["low_privilege"])
            if grant["unknown"] and not grant["low_privilege"]:
                ca_unknown_only = True
        # Every issuing CA was readable and none grant enroll to a low-privilege
        # or unresolved trustee: the template ACE cannot be exercised.
        if observed == len(publishers) and not ca_low and not ca_unknown_only:
            return None

    prior = risk.get("evidence") or {}
    if prior.get("enrollment_flag_observed") is False and "msPKI-Enrollment-Flag" not in missing:
        missing.append("msPKI-Enrollment-Flag")

    evidence = dict(prior)
    evidence["enrollment_trustees"] = template_enroll["low_privilege"] or template_enroll["unknown"]
    evidence["privileged_enrollment_trustees"] = template_enroll["privileged"]
    evidence["published_cas"] = [
        ldap_scalar_text(ca.get("cn") or ca.get("displayName") or ca.get("dNSHostName")) or "Unknown CA"
        for ca in publishers
    ]
    evidence["ca_enrollment_trustees"] = ca_low
    if missing:
        evidence["missing_prerequisites"] = missing
        evidence["requires_runtime_validation"] = True
        evidence.pop("vulnerability_confirmed", None)
        risk["evidence"] = evidence
        return risk

    evidence["missing_prerequisites"] = []
    evidence["requires_runtime_validation"] = False
    evidence["vulnerability_confirmed"] = True
    risk["evidence"] = evidence
    _annotate_confirmed_path(risk, evidence)
    return risk


def is_broad_enrollment_sid(sid: str) -> bool:
    """Return True for Everyone, Authenticated Users, Domain Users/Computers, and similar."""
    if sid in BROAD_PRINCIPAL_SIDS or sid == PRE_WINDOWS_2000_COMPATIBLE_ACCESS:
        return True
    return sid_is_domain_well_known(sid, LOW_PRIVILEGE_DOMAIN_RIDS)


def is_privileged_enrollment_sid(sid: str) -> bool:
    """Return True for well-known administrative SIDs that are expected to enroll."""
    if sid_is_domain_well_known(sid, _PRIVILEGED_DOMAIN_ENROLLMENT_RIDS) or sid_is_builtin_privileged(sid):
        return True
    return sid in {"S-1-5-9", "S-1-5-32-544"}


def _trustee_class(sid: str, principal: dict[str, Any] | None) -> str:
    if is_privileged_enrollment_sid(sid):
        return "privileged"
    if is_broad_enrollment_sid(sid):
        return "low"
    if principal is not None:
        if account_has_current_privileged_membership(principal) or is_privileged_group_record(principal):
            return "privileged"
        return "low"
    return "unknown"


def _trustee_label(sid: str, principal: dict[str, Any] | None) -> str:
    if principal:
        return (
            ldap_scalar_text(principal.get("sAMAccountName"))
            or ldap_scalar_text(principal.get("name"))
            or ldap_scalar_text(principal.get("cn"))
            or sid
        )
    return WELL_KNOWN_ENROLLMENT_LABELS.get(sid, sid)


def _annotate_confirmed_path(risk: dict[str, Any], evidence: dict[str, Any]) -> None:
    trustees = ", ".join(item["name"] for item in evidence.get("enrollment_trustees") or []) or "a low-privilege principal"
    cas = ", ".join(evidence.get("published_cas") or []) or "a published CA"
    description = str(risk.get("description") or "").replace(
        "Enrollment rights still need to be confirmed from the template ACL.",
        "",
    ).strip()
    risk["description"] = (
        f"{description} Low-privilege enrollment is granted to {trustees}. "
        f"The template is published on {cas}."
    )
    risk["impact"] = (
        "A low-privilege principal can request an authentication certificate and impersonate "
        "another identity, including Domain Admin, without further ACL review."
    )

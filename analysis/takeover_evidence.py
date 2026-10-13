"""Finding-specific, read-only proof dossiers for the takeover map."""

from __future__ import annotations

import shlex
from typing import Any

from ldap3.utils.conv import escape_filter_chars

from core.finding_evidence import requires_takeover_validation
from core.finding_review import required_checks


def evidence_dossier(risk: dict[str, Any], *, domain_dn: str, dc_ip: str) -> dict[str, Any]:
    """Separate a directory observation from proof of a completed takeover.

    Commands deliberately request configuration and ACLs only. No credential
    value, ticket, account mutation, or replication operation is generated.
    """
    evidence = risk.get("evidence") if isinstance(risk.get("evidence"), dict) else {}
    kind = str(risk.get("type") or "")
    obj = str(risk.get("affected_object") or risk.get("sAMAccountName") or "")
    dn = str(evidence.get("target_dn") or risk.get("distinguishedName") or "")
    trustee = str(evidence.get("trustee_sid") or risk.get("trustee") or "")
    attributes = ["distinguishedName", "objectSid", "objectClass"]
    checks = list(evidence.get("missing_prerequisites") or required_checks(risk))
    expected = "Resolve the exact object and compare the collected attributes with this finding."
    falsifier = "A changed object, unresolved trustee, or missing attribute leaves the claim unverified."
    base, scope = domain_dn, "sub"
    if dn:
        base, scope, query = dn, "base", "(objectClass=*)"
    elif obj:
        escaped = escape_filter_chars(obj)
        query = f"(|(sAMAccountName={escaped})(name={escaped})(distinguishedName={escaped}))"
    else:
        query = "(objectClass=domainDNS)"

    if "dcsync" in kind or "replication" in kind or kind == "shadow_admin":
        base, scope, query = domain_dn, "base", "(objectClass=domainDNS)"
        attributes += ["nTSecurityDescriptor"]
        checks = [
            "Both Get-Changes and Get-Changes-All on the domain root",
            "Effective allow/deny evaluation for the complete trustee token",
            "Trustee is outside the approved DC/synchronization service inventory",
        ]
        expected = "The same effective token holds GUIDs 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 AND 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 at the domain root."
        falsifier = "One replication right alone, a grant on a child OU, an applicable deny, or an approved service account does not establish unauthorized DCSync."
    elif "adcs" in kind or "certificate" in kind:
        attributes += ["nTSecurityDescriptor"]
        expected = "Resolve the exact PKI object, trustee, effective writable property, active CA publication, enrollment policy and authentication trust."
        falsifier = "A certificate container ACL or a template object alone does not prove an active certificate-authentication takeover chain."
    elif any(word in kind for word in ("acl", "gpo", "adminsdholder")):
        attributes += ["nTSecurityDescriptor"]
        checks += [
            "Property/ObjectType GUID and inheritance scope",
            "Applicable deny ACEs and trustee nested security groups",
            "A concrete privileged target reachable after this control step",
        ]
        expected = "The effective right applies to the exact target and property, not merely to an unrelated object with the same label."
        falsifier = "An inherit-only ACE, wrong property GUID, filtered GPO, or non-applicable deny/allow combination breaks the proposed chain."
    else:
        attributes += [
            "userAccountControl",
            "memberOf",
            "primaryGroupID",
            "servicePrincipalName",
            "msDS-AllowedToDelegateTo",
        ]
        checks += [
            "Current enabled account and effective nested security-group membership",
            "Separate evidence of any required credential recovery or privileged session",
        ]
        expected = "Configuration flags and membership reproduce the condition. Existing admin membership is recorded as current access."
        falsifier = "A stale adminCount, distribution-group membership, account-age indicator or SPN alone does not prove Domain Admin takeover."

    arguments = ["ldapsearch", "-LLL", "-x", "-H", f"ldaps://{dc_ip}", "-D", "<BIND_DN>", "-W", "-b", base, "-s", scope]
    if "nTSecurityDescriptor" in attributes:
        # BER sequence INTEGER 4 requests DACL only, avoiding SACL privileges.
        arguments += ["-E", "!1.2.840.113556.1.4.801=::MAMCAQQ="]
    arguments += [query, *attributes]
    return {
        "finding_id": risk.get("finding_id") or "",
        "type": kind,
        "object": obj,
        "target_dn": dn,
        "trustee": trustee,
        "permissions": evidence.get("permissions") or evidence.get("rights") or risk.get("permission") or "",
        "observation": str(risk.get("description") or risk.get("title") or kind),
        "evidence_state": "needs_validation" if requires_takeover_validation(risk) else "observed_condition",
        "takeover_tested": False,
        "checks": list(dict.fromkeys(checks)),
        "expected": expected,
        "falsifier": falsifier,
        "read_only_poc": shlex.join(arguments),
        "poc_note": "Example only; not executed by this report. Requires ldapsearch, a reachable LDAPS service, trusted CA and replacement of <BIND_DN>. The password is prompted with -W. Missing/hidden attributes remain unknown. Decode returned DACL bytes before interpreting rights.",
        "retest": "Repeat the same object-scoped query and a fresh scan after remediation; retain both timestamps and compare the finding ID and effective rights.",
    }

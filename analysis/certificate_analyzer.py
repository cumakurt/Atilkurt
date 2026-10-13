"""
Certificate-Based Attack Analyzer Module
Detects LDAP-visible AD CS template indicators for ESC1 and ESC2.
"""

from __future__ import annotations

import logging
from typing import Any

from analysis.adcs_enrollment import bind_esc_enrollment_evidence, index_enrollment_principals
from core.ad_identity import forest_configuration_dn, ldap_scalar_text
from core.constants import MITRETechniques, RiskTypes, Severity
from core.exceptions import LDAPSearchError

logger = logging.getLogger(__name__)

ENROLLEE_SUPPLIES_SUBJECT = 0x1
PEND_ALL_REQUESTS = 0x2
CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2"
SMART_CARD_LOGON_OID = "1.3.6.1.4.1.311.20.2.2"
ANY_PURPOSE_OID = "2.5.29.37.0"
TEMPLATE_ATTRIBUTES = [
    "name",
    "displayName",
    "cn",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag",
    "pKIExtendedKeyUsage",
    "msPKI-RA-Signature",
    "nTSecurityDescriptor",
    "distinguishedName",
]
CA_ATTRIBUTES = [
    "cn",
    "displayName",
    "dNSHostName",
    "certificateTemplates",
    "nTSecurityDescriptor",
    "distinguishedName",
]


class CertificateAnalyzer:
    """Analyzes Active Directory Certificate Services for vulnerabilities."""

    def __init__(self, ldap_connection, users: list[dict[str, Any]] | None = None,
                 groups: list[dict[str, Any]] | None = None):
        """Initialize certificate analyzer."""
        self.ldap = ldap_connection
        self.users = users or []
        self.groups = groups or []

    def analyze_certificate_services(self) -> list[dict[str, Any]]:
        """Analyze AD Certificate Services templates using the forest config NC."""
        config_dn = forest_configuration_dn(self.ldap)
        if not config_dn:
            logger.warning("Could not determine forest configuration naming context")
            return []

        pki_base = f"CN=Public Key Services,CN=Services,{config_dn}"
        try:
            templates = self.ldap.search(
                search_base=f"CN=Certificate Templates,{pki_base}",
                search_filter="(objectClass=pKICertificateTemplate)",
                attributes=TEMPLATE_ATTRIBUTES,
            ) or []
        except LDAPSearchError as exc:
            logger.debug("Certificate template search failed: %s", exc)
            return []

        cas, cas_observed = self._enrollment_services(pki_base)
        principals = index_enrollment_principals(self.users, self.groups)
        risks: list[dict[str, Any]] = []
        for template in templates:
            template_name = (
                ldap_scalar_text(template.get("name"))
                or ldap_scalar_text(template.get("displayName"))
                or ldap_scalar_text(template.get("cn"))
                or "Unknown"
            )
            for risk in self._analyze_template_vulnerabilities(template, str(template_name)):
                bound = bind_esc_enrollment_evidence(
                    risk,
                    template,
                    cas=cas,
                    cas_observed=cas_observed,
                    principals=principals,
                )
                if bound:
                    risks.append(bound)

        logger.info("Found %d certificate service risks", len(risks))
        return risks

    def _enrollment_services(self, pki_base: str) -> tuple[list[dict[str, Any]], bool]:
        """Return CA objects and whether the enrollment-service search completed."""
        try:
            rows = self.ldap.search(
                search_base=f"CN=Enrollment Services,{pki_base}",
                search_filter="(objectClass=pKIEnrollmentService)",
                attributes=CA_ATTRIBUTES,
            ) or []
            return rows, True
        except LDAPSearchError as exc:
            logger.debug("Enrollment service search failed: %s", exc)
            return [], False

    def _analyze_template_vulnerabilities(self, template: dict, template_name: str) -> list[dict[str, Any]]:
        """Analyze a certificate template for ESC1- and ESC2-like attribute exposure."""
        risks: list[dict[str, Any]] = []
        enrollment_flags = self._as_int(template.get("msPKI-Enrollment-Flag"))
        signatures = self._as_int(template.get('msPKI-RA-Signature'))
        name_flags = self._as_int(template.get("msPKI-Certificate-Name-Flag")) or 0
        ekus_present = "pKIExtendedKeyUsage" in template
        ekus = self._as_list(template.get("pKIExtendedKeyUsage"))
        eku_set = {str(eku).strip() for eku in ekus}
        has_client_auth = bool({CLIENT_AUTH_OID, SMART_CARD_LOGON_OID}.intersection(eku_set))
        has_any_purpose = ANY_PURPOSE_OID in eku_set
        manager_approval = enrollment_flags is not None and bool(enrollment_flags & PEND_ALL_REQUESTS)
        if manager_approval or (signatures is not None and signatures > 0):
            return risks

        if (
            name_flags & ENROLLEE_SUPPLIES_SUBJECT
            and not manager_approval
            and (has_client_auth or has_any_purpose)
        ):
            risks.append({
                "type": RiskTypes.CERTIFICATE_ESC1,
                "severity": Severity.CRITICAL,
                "title": f"ESC1-like template flags: {template_name}",
                "description": (
                    f"Certificate template '{template_name}' allows the enrollee to supply the subject "
                    "and advertises client authentication (or Any Purpose) without manager approval. "
                    "Enrollment rights still need to be confirmed from the template ACL."
                ),
                "affected_object": template_name,
                "object_type": "certificate_template",
                "vulnerability": "ESC1",
                "impact": (
                    "If a low-privilege principal can enroll, they can request a certificate for another "
                    "identity and authenticate as that account."
                ),
                "attack_scenario": (
                    f"Enroll against '{template_name}', supply a Domain Admin SAN, and authenticate with "
                    "the issued certificate."
                ),
                "mitigation": (
                    "Clear ENROLLEE_SUPPLIES_SUBJECT, require manager approval, and restrict enrollment."
                ),
                "mitre_attack": MITRETechniques.STEAL_FORGE_KERBEROS_SILVER,
            })

        empty_eku_confirmed = (
            ekus_present
            and not ekus
            and (
                "msPKI-Certificate-Name-Flag" in template
                or "msPKI-Enrollment-Flag" in template
            )
        )
        if has_any_purpose or empty_eku_confirmed:
            risks.append({
                "type": RiskTypes.CERTIFICATE_ESC2,
                "severity": Severity.CRITICAL,
                "title": f"ESC2-like template flags: {template_name}",
                "description": (
                    f"Certificate template '{template_name}' has Any Purpose EKU or an empty EKU list "
                    "on a fully retrieved template object."
                ),
                "affected_object": template_name,
                "object_type": "certificate_template",
                "vulnerability": "ESC2",
                "impact": (
                    "Unrestricted EKUs can be used for client authentication and other certificate uses."
                ),
                "attack_scenario": (
                    f"Request a certificate from '{template_name}' and use it for authentication."
                ),
                "mitigation": "Replace Any Purpose / empty EKU with explicit application policies.",
                "mitre_attack": MITRETechniques.STEAL_FORGE_KERBEROS_SILVER,
            })

        for risk in risks:
            missing = ['template enrollment ACL', 'CA publication', 'CA enrollment policy']
            if risk.get('type') == RiskTypes.CERTIFICATE_ESC1 and enrollment_flags is None:
                missing.insert(0, 'msPKI-Enrollment-Flag')
            risk['evidence'] = {
                'requires_runtime_validation': True,
                'name_flags': name_flags,
                'enrollment_flags': enrollment_flags,
                'enrollment_flag_observed': enrollment_flags is not None,
                'authorized_signatures': signatures,
                'ekus': sorted(eku_set),
                'missing_prerequisites': missing,
            }
        return risks

    @staticmethod
    def _as_int(value: Any) -> int | None:
        if isinstance(value, (list, tuple)):
            value = value[0] if value else None
        if value in (None, ""):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _as_list(value: Any) -> list[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, tuple):
            return list(value)
        return [value]

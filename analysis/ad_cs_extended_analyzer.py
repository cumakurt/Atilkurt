"""
AD CS Extended Analyzer Module
Extends the existing certificate_analyzer.py with additional ESC vectors:
  ESC5  — CA ACL abuse (ManageCA permission)
  ESC7  — CA Officer approval abuse
  ESC9  — CT_FLAG_NO_SECURITY_EXTENSION
  ESC10 — Weak certificate mapping (altSecurityIdentities)
  ESC11 — ICertPassage RPC relay
  ESC13 — OID Group Link abuse
  ESC14 — Explicit altSecurityIdentities write
  Certifried — CVE-2022-26923 (machine account SPN takeover)
"""

import logging
from typing import List, Dict, Any, Optional
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)

# Certificate template enrollment flags
CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001


class ADCSExtendedAnalyzer:
    """Extended AD CS vulnerability analysis (ESC5-14 + Certifried)."""

    def __init__(self, ldap_connection):
        self.ldap = ldap_connection

    def analyze(self) -> List[Dict[str, Any]]:
        risks: List[Dict[str, Any]] = []
        try:
            config_dn = self._get_config_dn()
            if not config_dn:
                logger.warning("Could not determine Configuration DN")
                return risks

            pki_dn = f"CN=Public Key Services,CN=Services,{config_dn}"

            # ── Enrollment Services (CAs) ──
            cas = self._get_enrollment_services(pki_dn)
            if cas:
                risks.extend(self._check_esc5(cas))
                risks.extend(self._check_esc7(cas))
                risks.extend(self._check_esc11(cas))

            # ── Certificate Templates ──
            templates = self._get_certificate_templates(pki_dn)
            if templates:
                risks.extend(self._check_esc9(templates))
                risks.extend(self._check_esc13(templates))

            # ── Certifried (CVE-2022-26923) ──
            risks.extend(self._check_certifried())

            # ── ESC10/ESC14 — altSecurityIdentities ──
            risks.extend(self._check_esc10_esc14())

            logger.info(f"Found {len(risks)} extended AD CS risks")
            return risks

        except Exception as e:
            logger.error(f"Error in AD CS extended analysis: {e}")
            return []

    # ── Data retrieval ──────────────────────────────────────────────────────

    def _get_config_dn(self) -> Optional[str]:
        try:
            results = self.ldap.search(
                search_base='', search_filter='(objectClass=*)',
                attributes=['configurationNamingContext'], size_limit=1,
            )
            if results:
                return results[0].get('configurationNamingContext')
        except Exception:
            pass
        base_dn = self.ldap.base_dn
        dc_parts = [p for p in base_dn.split(',') if p.upper().startswith('DC=')]
        return 'CN=Configuration,' + ','.join(dc_parts) if dc_parts else None

    def _get_enrollment_services(self, pki_dn: str) -> List[Dict[str, Any]]:
        try:
            results = self.ldap.search(
                search_base=f"CN=Enrollment Services,{pki_dn}",
                search_filter='(objectClass=pKIEnrollmentService)',
                attributes=[
                    'cn', 'dNSHostName', 'certificateTemplates',
                    'nTSecurityDescriptor', 'cACertificate',
                    'msPKI-Enrollment-Flag',
                ],
            )
            return results if results else []
        except Exception as e:
            logger.debug(f"Could not get enrollment services: {e}")
            return []

    def _get_certificate_templates(self, pki_dn: str) -> List[Dict[str, Any]]:
        try:
            results = self.ldap.search(
                search_base=f"CN=Certificate Templates,{pki_dn}",
                search_filter='(objectClass=pKICertificateTemplate)',
                attributes=[
                    'cn', 'displayName', 'msPKI-Certificate-Name-Flag',
                    'msPKI-Enrollment-Flag', 'msPKI-RA-Signature',
                    'pKIExtendedKeyUsage', 'msPKI-Certificate-Application-Policy',
                    'nTSecurityDescriptor', 'msPKI-Template-Schema-Version',
                    'flags',
                ],
            )
            return results if results else []
        except Exception as e:
            logger.debug(f"Could not get certificate templates: {e}")
            return []

    # ── ESC5 — CA ACL abuse ─────────────────────────────────────────────────

    def _check_esc5(self, cas: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        risks: List[Dict[str, Any]] = []
        for ca in cas:
            ca_name = ca.get('cn', '?')
            # We flag the existence of CAs and recommend ACL review
            risks.append({
                'type': RiskTypes.CERTIFICATE_ESC5,
                'severity': Severity.MEDIUM,
                'title': f'CA "{ca_name}" — review ManageCA ACL (ESC5)',
                'description': (
                    f'The CA "{ca_name}" should be audited for ManageCA and '
                    'ManageCertificates permissions. Users with ManageCA can '
                    'modify CA configuration, enable SAN for any template, '
                    'and effectively achieve ESC1.'
                ),
                'affected_object': ca_name,
                'object_type': 'configuration',
                'mitigation': (
                    'Review CA ACL: certutil -getreg CA\\Security\n'
                    'Remove ManageCA permissions from non-admin accounts.\n'
                    'Only PKI Admins should have ManageCA.'
                ),
                'mitre_attack': MITRETechniques.PRIVILEGE_ESCALATION,
            })
        return risks

    # ── ESC7 — CA Officer abuse ─────────────────────────────────────────────

    def _check_esc7(self, cas: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        risks: List[Dict[str, Any]] = []
        for ca in cas:
            ca_name = ca.get('cn', '?')
            risks.append({
                'type': RiskTypes.CERTIFICATE_ESC7,
                'severity': Severity.MEDIUM,
                'title': f'CA "{ca_name}" — check Officer approval config (ESC7)',
                'description': (
                    f'If "{ca_name}" has Certificate Manager Approval enabled '
                    'but a non-admin has ManageCertificates rights, they can '
                    'approve their own certificate requests (ESC7).'
                ),
                'affected_object': ca_name,
                'object_type': 'configuration',
                'mitigation': (
                    'Ensure ManageCertificates permission is restricted to '
                    'PKI officers only. Enable role separation on the CA.'
                ),
                'mitre_attack': MITRETechniques.PRIVILEGE_ESCALATION,
            })
        return risks

    # ── ESC9 — CT_FLAG_NO_SECURITY_EXTENSION ────────────────────────────────

    def _check_esc9(self, templates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        risks: List[Dict[str, Any]] = []
        for tmpl in templates:
            name = tmpl.get('cn') or tmpl.get('displayName', '?')
            enroll_flag = tmpl.get('msPKI-Enrollment-Flag')
            if enroll_flag is None:
                continue
            try:
                if int(enroll_flag) & CT_FLAG_NO_SECURITY_EXTENSION:
                    risks.append({
                        'type': RiskTypes.CERTIFICATE_ESC9,
                        'severity': Severity.HIGH,
                        'title': f'Template "{name}" has NO_SECURITY_EXTENSION (ESC9)',
                        'description': (
                            f'Certificate template "{name}" has '
                            'CT_FLAG_NO_SECURITY_EXTENSION set. Certificates '
                            'issued from this template will not include the '
                            'szOID_NTDS_CA_SECURITY_EXT SID extension, enabling '
                            'name impersonation attacks.'
                        ),
                        'affected_object': name,
                        'object_type': 'configuration',
                        'mitigation': (
                            'Remove CT_FLAG_NO_SECURITY_EXTENSION from the '
                            'template enrollment flags. Enable strong certificate '
                            'mapping (KB5014754).'
                        ),
                        'mitre_attack': MITRETechniques.PRIVILEGE_ESCALATION,
                    })
            except (ValueError, TypeError):
                continue
        return risks

    # ── ESC11 — ICertPassage RPC relay ──────────────────────────────────────

    def _check_esc11(self, cas: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        risks: List[Dict[str, Any]] = []
        for ca in cas:
            ca_name = ca.get('cn', '?')
            host = ca.get('dNSHostName', '?')
            risks.append({
                'type': RiskTypes.CERTIFICATE_ESC11,
                'severity': Severity.MEDIUM,
                'title': f'CA "{ca_name}" — check RPC interface protection (ESC11)',
                'description': (
                    f'The CA "{ca_name}" ({host}) may be vulnerable to ESC11 '
                    'if the ICertPassage RPC interface does not require '
                    'authentication. An attacker can relay NTLM authentication '
                    'to the RPC interface to request certificates.'
                ),
                'affected_object': ca_name,
                'object_type': 'configuration',
                'mitigation': (
                    'Set IF_ENFORCEENCRYPTICERTREQUEST on the CA:\n'
                    '  certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST\n'
                    '  Restart-Service CertSvc'
                ),
                'mitre_attack': MITRETechniques.PRIVILEGE_ESCALATION,
            })
        return risks

    # ── ESC13 — OID Group Link ──────────────────────────────────────────────

    def _check_esc13(self, templates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        risks: List[Dict[str, Any]] = []
        for tmpl in templates:
            name = tmpl.get('cn') or tmpl.get('displayName', '?')
            app_policies = tmpl.get('msPKI-Certificate-Application-Policy', [])
            if isinstance(app_policies, str):
                app_policies = [app_policies]
            # ESC13: template has issuance policy OIDs linked to groups
            eku = tmpl.get('pKIExtendedKeyUsage', [])
            if isinstance(eku, str):
                eku = [eku]
            # Flag templates with custom OIDs that may link to groups
            custom_oids = [
                oid for oid in (list(app_policies) + list(eku))
                if oid and not oid.startswith('1.3.6.1.') and not oid.startswith('2.5.')
            ]
            if custom_oids:
                risks.append({
                    'type': RiskTypes.CERTIFICATE_ESC13,
                    'severity': Severity.MEDIUM,
                    'title': f'Template "{name}" has custom OIDs — check for ESC13',
                    'description': (
                        f'Certificate template "{name}" references custom '
                        f'OID(s): {", ".join(custom_oids[:5])}. If these OIDs '
                        'are linked to AD groups via msDS-OIDToGroupLink, '
                        'obtaining a certificate grants group membership (ESC13).'
                    ),
                    'affected_object': name,
                    'object_type': 'configuration',
                    'mitigation': (
                        'Audit OID-to-group links:\n'
                        '  Get-ADObject -SearchBase "CN=OID,CN=Public Key Services,'
                        'CN=Services,<ConfigDN>" -Filter {msDS-OIDToGroupLink -like "*"}\n'
                        'Remove unnecessary OID group links.'
                    ),
                    'mitre_attack': MITRETechniques.PRIVILEGE_ESCALATION,
                })
        return risks

    # ── Certifried (CVE-2022-26923) ─────────────────────────────────────────

    def _check_certifried(self) -> List[Dict[str, Any]]:
        """Check for Certifried vulnerability (machine account SPN abuse)."""
        risks: List[Dict[str, Any]] = []
        try:
            base_dn = self.ldap.base_dn
            # Check ms-DS-MachineAccountQuota (needed for Certifried)
            results = self.ldap.search(
                search_base=base_dn,
                search_filter='(objectClass=domainDNS)',
                attributes=['ms-DS-MachineAccountQuota'],
                size_limit=1,
            )
            if results:
                quota = results[0].get('ms-DS-MachineAccountQuota')
                if quota is not None and int(quota) > 0:
                    risks.append({
                        'type': RiskTypes.CERTIFICATE_CERTIFRIED,
                        'severity': Severity.HIGH,
                        'title': 'Certifried (CVE-2022-26923) may be exploitable',
                        'description': (
                            'ms-DS-MachineAccountQuota is > 0, allowing any '
                            'user to create machine accounts. Combined with '
                            'a Machine template that uses dNSHostName for the'
                            ' subject, an attacker can impersonate a DC.'
                        ),
                        'affected_object': 'Domain',
                        'object_type': 'configuration',
                        'mitigation': (
                            '1. Install KB5014754 (strong certificate mapping)\n'
                            '2. Set ms-DS-MachineAccountQuota to 0\n'
                            '3. Ensure Machine template validates dNSHostName '
                            'against existing accounts'
                        ),
                        'mitre_attack': MITRETechniques.PRIVILEGE_ESCALATION,
                    })
        except Exception as e:
            logger.debug(f"Certifried check failed: {e}")
        return risks

    # ── ESC10 / ESC14 — altSecurityIdentities ───────────────────────────────

    def _check_esc10_esc14(self) -> List[Dict[str, Any]]:
        """Check for weak certificate mapping and writable altSecurityIdentities."""
        risks: List[Dict[str, Any]] = []
        try:
            base_dn = self.ldap.base_dn
            results = self.ldap.search(
                search_base=base_dn,
                search_filter='(altSecurityIdentities=*)',
                attributes=['sAMAccountName', 'altSecurityIdentities'],
            )
            if results:
                accounts_with_alt = [
                    r.get('sAMAccountName', '?') for r in results
                ]
                if len(accounts_with_alt) > 0:
                    risks.append({
                        'type': RiskTypes.CERTIFICATE_ESC14,
                        'severity': Severity.MEDIUM,
                        'title': f'{len(accounts_with_alt)} accounts have altSecurityIdentities',
                        'description': (
                            f'{len(accounts_with_alt)} account(s) have explicit '
                            'altSecurityIdentities set. If writable by non-admins, '
                            'an attacker can map their own certificate to a '
                            'privileged account (ESC14).'
                        ),
                        'affected_object': ', '.join(accounts_with_alt[:10]),
                        'object_type': 'user',
                        'mitigation': (
                            'Audit altSecurityIdentities ACLs. Ensure only '
                            'admins can write this attribute. Enable strong '
                            'certificate mapping (KB5014754).'
                        ),
                        'mitre_attack': MITRETechniques.PRIVILEGE_ESCALATION,
                        'accounts': accounts_with_alt,
                    })
        except Exception as e:
            logger.debug(f"ESC10/ESC14 check failed: {e}")
        return risks

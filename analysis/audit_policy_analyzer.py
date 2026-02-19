"""
Audit Policy Analyzer Module
Evaluates the sufficiency of AD audit/logging configuration by examining
GPO-defined audit policies and SACL coverage on sensitive objects.
"""

import logging
from typing import List, Dict, Any
from core.constants import RiskTypes, Severity

logger = logging.getLogger(__name__)

# Minimum recommended audit event IDs to monitor
CRITICAL_EVENT_IDS = {
    '4624': 'Successful Logon',
    '4625': 'Failed Logon',
    '4648': 'Explicit Credential Logon',
    '4662': 'Directory Service Access',
    '4672': 'Special Privileges Assigned',
    '4720': 'User Account Created',
    '4728': 'Member Added to Security Group',
    '4732': 'Member Added to Local Group',
    '4756': 'Member Added to Universal Group',
    '4768': 'Kerberos TGT Requested',
    '4769': 'Kerberos Service Ticket Requested',
    '4771': 'Kerberos Pre-Auth Failed',
    '4776': 'NTLM Authentication',
    '5136': 'Directory Object Modified',
    '5141': 'Directory Object Deleted',
    '1102': 'Audit Log Cleared',
}


class AuditPolicyAnalyzer:
    """Evaluates audit policy configuration and SACL coverage."""

    def __init__(self, ldap_connection):
        self.ldap = ldap_connection

    def analyze(
        self,
        groups: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Analyze audit policy configuration.

        Args:
            groups: List of group dictionaries (used for cross-reference)

        Returns:
            List of risk dictionaries
        """
        risks: List[Dict[str, Any]] = []

        try:
            base_dn = self.ldap.base_dn

            # ── 1. Check if audit policies are retrievable via GPO objects ──
            risks.extend(self._check_audit_gpos(base_dn))

            # ── 2. Check SACL on AdminSDHolder ──
            risks.extend(self._check_adminsdholder_sacl(base_dn))

            # ── 3. Check SACL on domain root ──
            risks.extend(self._check_domain_root_sacl(base_dn))

            # ── 4. Provide monitoring recommendations ──
            risks.extend(self._recommend_monitoring())

            logger.info(f"Found {len(risks)} audit policy findings")
            return risks

        except Exception as e:
            logger.error(f"Error analyzing audit policy: {e}")
            return []

    # ── Audit GPO Analysis ──────────────────────────────────────────────────

    def _check_audit_gpos(
        self, base_dn: str
    ) -> List[Dict[str, Any]]:
        """Check for GPOs that configure audit policies."""
        risks: List[Dict[str, Any]] = []

        try:
            results = self.ldap.search(
                search_base=base_dn,
                search_filter=(
                    '(&(objectClass=groupPolicyContainer)'
                    '(|(displayName=*audit*)(displayName=*Audit*)'
                    '(displayName=*logging*)(displayName=*Logging*)))'
                ),
                attributes=['displayName', 'gPCFileSysPath', 'cn'],
            )

            if not results:
                risks.append({
                    'type': RiskTypes.AUDIT_POLICY_INSUFFICIENT,
                    'severity': Severity.HIGH,
                    'title': 'No audit-specific GPO found',
                    'description': (
                        'No GPO with "audit" or "logging" in its name '
                        'was found. This suggests that advanced audit policies '
                        'may not be centrally configured. Without proper audit '
                        'configuration, security events will not be logged.'
                    ),
                    'affected_object': 'Domain',
                    'object_type': 'configuration',
                    'impact': (
                        'Without audit logging, you cannot detect attacks '
                        'such as DCSync, Golden Ticket usage, lateral movement, '
                        'or privilege escalation. Incident response becomes '
                        'nearly impossible.'
                    ),
                    'mitigation': (
                        'Create a GPO to configure Advanced Audit Policy:\n'
                        '  - Account Logon: Audit Kerberos Auth (Success+Failure)\n'
                        '  - Logon/Logoff: Audit Logon (Success+Failure)\n'
                        '  - Object Access: Audit SAM, DS Access\n'
                        '  - Privilege Use: Audit Sensitive Privilege Use\n'
                        '  - Account Management: Audit User/Group Management\n'
                        '  - DS Access: Audit Directory Service Changes'
                    ),
                    'cis_reference': 'CIS Benchmark §17 — Advanced Audit Policy',
                })
            else:
                gpo_names = [r.get('displayName', '?') for r in results]
                risks.append({
                    'type': RiskTypes.AUDIT_POLICY_INSUFFICIENT,
                    'severity': Severity.LOW,
                    'title': f'{len(results)} audit GPO(s) found — verify coverage',
                    'description': (
                        f'Found {len(results)} GPO(s) related to auditing: '
                        f'{", ".join(gpo_names[:5])}. Verify these GPOs configure '
                        'all required advanced audit subcategories.'
                    ),
                    'affected_object': ', '.join(gpo_names[:5]),
                    'object_type': 'configuration',
                    'mitigation': (
                        'Review audit GPO settings with:\n'
                        '  auditpol /get /category:*\n'
                        'Ensure all CIS §17 subcategories are enabled.'
                    ),
                    'cis_reference': 'CIS Benchmark §17',
                    'audit_gpos': gpo_names,
                })

        except Exception as e:
            logger.debug(f"Could not check audit GPOs: {e}")

        return risks

    # ── AdminSDHolder SACL ──────────────────────────────────────────────────

    def _check_adminsdholder_sacl(
        self, base_dn: str
    ) -> List[Dict[str, Any]]:
        """Check if AdminSDHolder has SACL auditing configured."""
        risks: List[Dict[str, Any]] = []

        try:
            admin_dn = f"CN=AdminSDHolder,CN=System,{base_dn}"
            results = self.ldap.search(
                search_base=admin_dn,
                search_filter='(objectClass=*)',
                attributes=['nTSecurityDescriptor', 'cn'],
                size_limit=1,
            )

            if results:
                # We can't easily parse SACL from LDAP, but we flag it
                # for manual verification
                risks.append({
                    'type': RiskTypes.AUDIT_SACL_MISSING,
                    'severity': Severity.MEDIUM,
                    'title': 'Verify SACL on AdminSDHolder container',
                    'description': (
                        'AdminSDHolder controls ACLs for all protected accounts. '
                        'Any modification to AdminSDHolder should be audited. '
                        'Verify that a SACL is configured to log all write '
                        'operations.'
                    ),
                    'affected_object': 'AdminSDHolder',
                    'object_type': 'configuration',
                    'mitigation': (
                        'Set SACL on AdminSDHolder:\n'
                        '  dsacls "CN=AdminSDHolder,CN=System,<DomainDN>" '
                        '/G "Everyone:RPWP;nTSecurityDescriptor" /A\n\n'
                        'Monitor Event ID 5136 for changes to this object.'
                    ),
                })

        except Exception as e:
            logger.debug(f"AdminSDHolder check failed: {e}")

        return risks

    # ── Domain Root SACL ────────────────────────────────────────────────────

    def _check_domain_root_sacl(
        self, base_dn: str
    ) -> List[Dict[str, Any]]:
        """Recommend SACL on domain root for replication rights monitoring."""
        return [{
            'type': RiskTypes.AUDIT_SACL_MISSING,
            'severity': Severity.MEDIUM,
            'title': 'Verify SACL on domain root for DCSync detection',
            'description': (
                'SACL auditing on the domain root object can detect '
                'DCSync attacks by logging DS-Replication-Get-Changes '
                'operations (Event ID 4662).'
            ),
            'affected_object': base_dn,
            'object_type': 'configuration',
            'mitigation': (
                'Configure SACL on domain root to audit:\n'
                '  - DS-Replication-Get-Changes (Success)\n'
                '  - DS-Replication-Get-Changes-All (Success)\n'
                'Monitor Event ID 4662 with Operation Type "Object Access".'
            ),
        }]

    # ── Monitoring Recommendations ──────────────────────────────────────────

    def _recommend_monitoring(self) -> List[Dict[str, Any]]:
        """Provide minimum SIEM monitoring event ID list."""
        event_list = '\n'.join(
            f'  • {eid}: {desc}'
            for eid, desc in sorted(CRITICAL_EVENT_IDS.items())
        )
        return [{
            'type': RiskTypes.AUDIT_POLICY_INSUFFICIENT,
            'severity': Severity.LOW,
            'title': 'Recommended minimum Event IDs for SIEM monitoring',
            'description': (
                'The following Event IDs should be forwarded to your SIEM '
                'for security monitoring coverage:'
            ),
            'affected_object': 'Domain',
            'object_type': 'configuration',
            'mitigation': f'Forward these Event IDs to SIEM:\n{event_list}',
            'critical_event_ids': list(CRITICAL_EVENT_IDS.keys()),
        }]

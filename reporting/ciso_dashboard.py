"""
CISO Dashboard Generator
Enterprise-grade CISO dashboard for AD security metrics
"""

import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

# Human-readable labels for each analysis category (Executive Summary - All Analyses Overview)
ANALYSIS_DISPLAY_LABELS = {
    "user_risks": "User risk analysis",
    "computer_risks": "Computer risk analysis",
    "group_risks": "Group risk analysis",
    "kerberos_risks": "Kerberos & delegation",
    "escalation_paths": "Privilege escalation paths",
    "acl_risks": "ACL risks (legacy)",
    "comprehensive_acl_risks": "ACL security (comprehensive)",
    "legacy_os_risks": "Legacy / EOL operating systems",
    "kerberoasting_targets": "Kerberoasting targets",
    "asrep_targets": "AS-REP roasting targets",
    "service_risks": "Service account risks",
    "gpo_abuse_risks": "GPO abuse risks",
    "dcsync_risks": "DCSync rights",
    "password_policy_risks": "Password policy issues",
    "trust_risks": "Trust relationship risks",
    "certificate_risks": "AD CS certificate risks",
    "gpp_risks": "GPP stored passwords",
    "laps_risks": "LAPS configuration",
    "zerologon_risks": "ZeroLogon (CVE-2020-1472)",
    "printnightmare_risks": "PrintNightmare",
    "petitpotam_risks": "PetitPotam",
    "shadow_cred_risks": "Shadow credentials",
    "nopac_risks": "NoPac",
    "domain_security_risks": "Domain security (LDAP/NTLM/SMB)",
    "extended_ldap_risks": "Extended LDAP (RBCD, PSO, etc.)",
    "password_spray_risks": "Password spray risk accounts",
    "golden_gmsa_risks": "Golden gMSA",
    "honeypot_risks": "Honeypot / deception",
    "stale_objects_risks": "Stale objects",
    "adcs_extended_risks": "AD CS extended (ESC5–14)",
    "audit_policy_risks": "Audit policy",
    "backup_operator_risks": "Backup Operators / sensitive groups",
    "coercion_risks": "Coercion attack surface",
    "gmsa_risks": "gMSA configuration",
    "krbtgt_risks": "KRBTGT health",
    "lateral_movement_risks": "Lateral movement",
    "machine_quota_risks": "Machine account quota",
    "replication_risks": "Replication metadata",
    "shadow_admins": "Shadow admins",
    "acl_escalation_paths": "ACL privilege escalation paths",
    "misconfig_findings": "Misconfiguration findings",
}


class CISODashboardGenerator:
    """Generates CISO-focused executive dashboard."""
    
    def __init__(self):
        """Initialize CISO dashboard generator."""
        pass
    
    def generate_dashboard_data(self, risks, users, computers, groups, domain_score, executive_summary,
                                 analysis_summary_counts=None):
        """
        Generate CISO dashboard data structure.

        Args:
            risks: List of scored risk dictionaries
            users: List of user dictionaries
            computers: List of computer dictionaries
            groups: List of group dictionaries
            domain_score: Domain security score (0-100)
            executive_summary: Executive summary dictionary
            analysis_summary_counts: Optional dict of analysis key -> count for Executive Summary

        Returns:
            dict: CISO dashboard data
        """
        # Calculate top KPIs
        kpis = self._calculate_top_kpis(risks, users, computers, groups)

        # Calculate risk distribution
        risk_distribution = self._calculate_risk_distribution(risks)

        # Calculate risk by category
        risk_by_category = self._calculate_risk_by_category(risks)

        # Get top 10 riskiest objects
        top_risky_objects = self._get_top_risky_objects(risks)

        # Build all-analyses summary for Executive Summary (label, count, status)
        all_analyses_summary = self._build_all_analyses_summary(
            analysis_summary_counts or {}
        )

        # Generate enhanced CISO / Executive summary text (paragraph + key metrics)
        ciso_summary = self._generate_ciso_summary(
            risks, risk_by_category, analysis_summary_counts=analysis_summary_counts
        )

        # Generate action priorities
        action_priorities = self._generate_action_priorities(risks, executive_summary)

        # Password statistics
        password_stats = self._calculate_password_statistics(users)

        # Account activity statistics
        account_activity_stats = self._calculate_account_activity_statistics(users)

        # Admin group membership statistics
        admin_group_stats = self._calculate_admin_group_statistics(users)

        # Account status statistics
        account_status_stats = self._calculate_account_status_statistics(users)

        return {
            'kpis': kpis,
            'risk_distribution': risk_distribution,
            'risk_by_category': risk_by_category,
            'top_risky_objects': top_risky_objects,
            'ciso_summary': ciso_summary,
            'all_analyses_summary': all_analyses_summary,
            'action_priorities': action_priorities,
            'domain_score': domain_score,
            'password_stats': password_stats,
            'account_activity_stats': account_activity_stats,
            'admin_group_stats': admin_group_stats,
            'account_status_stats': account_status_stats
        }
    
    def _calculate_top_kpis(self, risks, users, computers, groups):
        """Calculate top KPIs for CISO dashboard."""
        # Get severity from 'severity' or 'severity_level' field
        critical_risks = [r for r in risks if (r.get('severity_level', '').lower() == 'critical' or 
                                               r.get('severity', '').lower() == 'critical')]
        high_risks = [r for r in risks if (r.get('severity_level', '').lower() == 'high' or 
                                          r.get('severity', '').lower() == 'high')]
        
        # Count privileged accounts
        privileged_accounts = 0
        for user in users:
            if user.get('adminCount') == 1 or user.get('adminCount') == '1':
                privileged_accounts += 1
            else:
                member_of = user.get('memberOf', []) or []
                if not isinstance(member_of, list):
                    member_of = [member_of] if member_of else []
                for group_dn in member_of:
                    group_name = self._extract_group_name(group_dn)
                    if group_name and any(priv in group_name.upper() for priv in 
                        ['DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'SCHEMA ADMINS']):
                        privileged_accounts += 1
                        break
        
        # Count delegation risks
        delegation_risks = len([r for r in risks if 'delegation' in r.get('type', '').lower()])
        
        return {
            'overall_score': {
                'value': 0,  # Will be set from domain_score
                'label': 'Overall AD Security Score',
                'color': 'green',  # Will be calculated
                'trend': 'stable'  # Placeholder
            },
            'critical_risks': {
                'value': len(critical_risks),
                'label': 'Critical Risks',
                'color': 'red' if len(critical_risks) > 0 else 'green',
                'trend': 'stable'
            },
            'high_risks': {
                'value': len(high_risks),
                'label': 'High Risks',
                'color': 'yellow' if len(high_risks) > 0 else 'green',
                'trend': 'stable'
            },
            'privileged_accounts': {
                'value': privileged_accounts,
                'label': 'Privileged Accounts',
                'color': 'yellow' if privileged_accounts > 10 else 'green',
                'trend': 'stable'
            },
            'delegation_risks': {
                'value': delegation_risks,
                'label': 'Delegation Risks',
                'color': 'red' if delegation_risks > 0 else 'green',
                'trend': 'stable'
            }
        }
    
    def _calculate_risk_distribution(self, risks):
        """Calculate risk distribution by severity."""
        distribution = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        for risk in risks:
            # Try both 'severity_level' and 'severity' fields
            severity = risk.get('severity_level') or risk.get('severity', 'Medium')
            if isinstance(severity, str):
                severity = severity.capitalize()
            if severity in distribution:
                distribution[severity] += 1
            else:
                # Default to Medium if unknown
                distribution['Medium'] += 1
        
        return distribution
    
    def _calculate_risk_by_category(self, risks):
        """Calculate risks by category."""
        categories = {
            'Identity': 0,
            'Privilege': 0,
            'Kerberos': 0,
            'Delegation': 0,
            'ACL': 0,
            'Legacy Systems': 0,
            'DCSync': 0,
            'Password Policy': 0,
            'Trust': 0,
            'Certificate': 0,
            'GPP': 0,
            'LAPS': 0,
            'Vulnerabilities': 0
        }
        
        for risk in risks:
            risk_type = risk.get('type', '').lower()
            
            # Categorize risks
            if 'dcsync' in risk_type:
                categories['DCSync'] += 1
            elif 'password_policy' in risk_type or (risk.get('object_type') == 'policy' and 'password' in risk_type):
                categories['Password Policy'] += 1
            elif 'trust' in risk_type or risk.get('object_type') == 'trust':
                categories['Trust'] += 1
            elif 'certificate' in risk_type or 'esc' in risk_type:
                categories['Certificate'] += 1
            elif 'gpp' in risk_type:
                categories['GPP'] += 1
            elif 'laps' in risk_type:
                categories['LAPS'] += 1
            elif 'zerologon' in risk_type or 'printnightmare' in risk_type or 'petitpotam' in risk_type or 'shadow' in risk_type:
                categories['Vulnerabilities'] += 1
            elif 'password' in risk_type or 'preauth' in risk_type or 'spn' in risk_type:
                categories['Identity'] += 1
            elif 'admin' in risk_type or 'privilege' in risk_type or 'escalation' in risk_type:
                categories['Privilege'] += 1
            elif 'kerberos' in risk_type:
                categories['Kerberos'] += 1
            elif 'delegation' in risk_type:
                categories['Delegation'] += 1
            elif 'acl' in risk_type:
                categories['ACL'] += 1
            elif 'eol' in risk_type or 'operating_system' in risk_type:
                categories['Legacy Systems'] += 1
        
        return categories
    
    def _calculate_password_statistics(self, users):
        """Calculate password-related statistics."""
        from datetime import datetime
        
        stats = {
            'never_changed': 0,
            'over_90_days': 0,
            'over_180_days': 0,
            'over_365_days': 0,
            'same_as_creation': 0,
            'total_users': len(users),
            'details': []
        }
        
        now = datetime.now()
        
        for user in users:
            pwd_last_set = user.get('pwdLastSet')
            when_created = user.get('whenCreated')
            username = user.get('sAMAccountName', 'Unknown')
            
            if not pwd_last_set:
                stats['never_changed'] += 1
                stats['details'].append({
                    'username': username,
                    'issue': 'Password never changed',
                    'days': None
                })
                continue
            
            # Convert timestamp to datetime if needed
            pwd_date = None
            if isinstance(pwd_last_set, datetime):
                pwd_date = pwd_last_set
            elif isinstance(pwd_last_set, str):
                try:
                    # Try ISO format first
                    pwd_date = datetime.fromisoformat(pwd_last_set.replace('Z', '+00:00'))
                except (ValueError, TypeError):
                    try:
                        # Try common datetime formats
                        pwd_date = datetime.strptime(pwd_last_set, '%Y-%m-%d %H:%M:%S')
                    except (ValueError, TypeError):
                        try:
                            pwd_date = datetime.strptime(pwd_last_set, '%Y-%m-%d %H:%M:%S.%f')
                        except (ValueError, TypeError):
                            continue
            else:
                continue
            
            if not pwd_date:
                continue
            
            # Remove timezone for calculation
            if pwd_date.tzinfo:
                pwd_date = pwd_date.replace(tzinfo=None)
            
            # Calculate age
            age_days = (now - pwd_date).days
            
            # Check if same as creation date
            created_date = None
            if when_created:
                if isinstance(when_created, datetime):
                    created_date = when_created
                elif isinstance(when_created, str):
                    try:
                        created_date = datetime.fromisoformat(when_created.replace('Z', '+00:00'))
                    except (ValueError, TypeError):
                        try:
                            created_date = datetime.strptime(when_created, '%Y-%m-%d %H:%M:%S')
                        except (ValueError, TypeError):
                            try:
                                created_date = datetime.strptime(when_created, '%Y-%m-%d %H:%M:%S.%f')
                            except (ValueError, TypeError):
                                created_date = None
                
                if created_date:
                    if created_date.tzinfo:
                        created_date = created_date.replace(tzinfo=None)
                    # If password set date is within 1 day of creation, consider it same
                    if abs((pwd_date - created_date).days) <= 1:
                        stats['same_as_creation'] += 1
                        stats['details'].append({
                            'username': username,
                            'issue': 'Password never changed since account creation',
                            'days': age_days
                        })
                        continue
            
            # Count by age
            if age_days > 365:
                stats['over_365_days'] += 1
                stats['details'].append({
                    'username': username,
                    'issue': f'Password not changed for {age_days} days',
                    'days': age_days
                })
            elif age_days > 180:
                stats['over_180_days'] += 1
                stats['details'].append({
                    'username': username,
                    'issue': f'Password not changed for {age_days} days',
                    'days': age_days
                })
            elif age_days > 90:
                stats['over_90_days'] += 1
                stats['details'].append({
                    'username': username,
                    'issue': f'Password not changed for {age_days} days',
                    'days': age_days
                })
        
        return stats
    
    def _get_top_risky_objects(self, risks):
        """Get top 10 riskiest objects."""
        object_scores = defaultdict(lambda: {'score': 0, 'count': 0, 'type': 'unknown'})
        
        for risk in risks:
            affected_object = risk.get('affected_object')
            if affected_object:
                object_scores[affected_object]['score'] += risk.get('final_score', risk.get('score', 0))
                object_scores[affected_object]['count'] += 1
                object_scores[affected_object]['type'] = risk.get('object_type', 'unknown')
        
        # Sort by score
        sorted_objects = sorted(
            object_scores.items(),
            key=lambda x: x[1]['score'],
            reverse=True
        )[:10]
        
        return [
            {
                'name': obj[0],
                'type': obj[1]['type'],
                'total_score': round(obj[1]['score'], 1),
                'risk_count': obj[1]['count']
            }
            for obj in sorted_objects
        ]
    
    def _build_all_analyses_summary(self, analysis_summary_counts):
        """Build list of {label, count, status} for every analysis category."""
        result = []
        critical_keys = {
            'dcsync_risks', 'kerberoasting_targets', 'asrep_targets', 'gpp_risks',
            'zerologon_risks', 'shadow_cred_risks', 'nopac_risks', 'shadow_admins',
            'acl_escalation_paths',
        }
        high_keys = {
            'user_risks', 'computer_risks', 'group_risks', 'kerberos_risks',
            'escalation_paths', 'comprehensive_acl_risks', 'certificate_risks',
            'printnightmare_risks', 'petitpotam_risks', 'password_policy_risks',
            'trust_risks', 'adcs_extended_risks', 'golden_gmsa_risks'
        }
        for key, label in ANALYSIS_DISPLAY_LABELS.items():
            count = analysis_summary_counts.get(key, 0)
            if key in critical_keys and count > 0:
                status = 'critical'
            elif key in high_keys and count > 0:
                status = 'warning'
            elif count > 0:
                status = 'warning'
            else:
                status = 'ok'
            result.append({'key': key, 'label': label, 'count': count, 'status': status})
        return result

    def _generate_ciso_summary(self, risks, risk_by_category, analysis_summary_counts=None):
        """Generate enhanced CISO / Executive summary: one paragraph + key metrics."""
        critical_count = len([r for r in risks if (r.get('severity_level', '').lower() == 'critical' or
                                                     r.get('severity', '').lower() == 'critical')])
        high_count = len([r for r in risks if (r.get('severity_level', '').lower() == 'high' or
                                               r.get('severity', '').lower() == 'high')])
        total_risks = len(risks)
        identity_risks = risk_by_category.get('Identity', 0)
        privilege_risks = risk_by_category.get('Privilege', 0)
        delegation_count = risk_by_category.get('Delegation', 0)

        # Total findings from all analyses (if available)
        total_findings = 0
        categories_with_findings = 0
        if analysis_summary_counts:
            for k, v in analysis_summary_counts.items():
                if v and isinstance(v, (int, float)):
                    total_findings += int(v)
                    categories_with_findings += 1

        summary_parts = []

        # Opening: overall assessment
        if total_risks == 0:
            summary_parts.append(
                "This Active Directory security assessment did not identify any scored risks. "
                "The environment appears to be in good standing from the perspective of this analysis."
            )
        else:
            summary_parts.append(
                f"This report summarizes a comprehensive Active Directory security health check. "
                f"Across all analyses, {total_risks} risk(s) were identified and scored."
            )
            if total_findings > 0 and total_findings != total_risks:
                summary_parts.append(
                    f"Findings span {categories_with_findings} analysis categories "
                    f"({total_findings} total finding items before consolidation)."
                )

        # Severity focus
        if critical_count > 0:
            summary_parts.append(
                f"Critical: {critical_count}. These require immediate remediation."
            )
        if high_count > 0:
            summary_parts.append(
                f"High: {high_count}. These should be addressed as a priority."
            )
        if (critical_count + high_count) == 0 and total_risks > 0:
            summary_parts.append(
                "No critical or high severity risks were found; remaining items are medium or low."
            )

        # Identity and privilege
        if identity_risks > 0 or privilege_risks > 0:
            total_ip = identity_risks + privilege_risks
            summary_parts.append(
                f"Identity and privilege-related findings: {total_ip}."
            )
        if delegation_count > 0:
            summary_parts.append(
                f"Delegation-related risks: {delegation_count}."
            )

        # Closing
        if total_risks == 0:
            summary_parts.append(
                "Recommend maintaining current controls and re-running the assessment periodically."
            )
        else:
            summary_parts.append(
                "Details per category are in the \"Complete Analysis Summary\" table below and in the risk tabs."
            )

        return " ".join(summary_parts)
    
    def _generate_action_priorities(self, risks, executive_summary):
        """Generate action priorities with timelines."""
        priorities = {
            'quick_wins': [],  # 0-30 days
            'medium_term': [],  # 30-90 days
            'long_term': []  # 90+ days
        }
        
        # Quick wins from executive summary
        quick_wins = executive_summary.get('quick_wins', []) if executive_summary else []
        for win in quick_wins[:5]:
            priorities['quick_wins'].append({
                'action': win.get('action', 'Unknown'),
                'impact': win.get('impact', 'Medium'),
                'effort': win.get('effort', 'Low'),
                'affected_count': win.get('affected_count', 0),
                'description': win.get('description', ''),
                'estimated_risk_reduction': self._estimate_risk_reduction(win, risks)
            })
        
        # Medium-term from executive summary
        long_term = executive_summary.get('long_term_improvements', []) if executive_summary else []
        for improvement in long_term:
            timeline = improvement.get('timeline', '')
            if '3-6' in timeline or '30-90' in timeline or '30' in timeline:
                priorities['medium_term'].append({
                    'action': improvement.get('action', 'Unknown'),
                    'timeline': improvement.get('timeline', '30-90 days'),
                    'impact': improvement.get('impact', 'High'),
                    'description': improvement.get('description', ''),
                    'estimated_risk_reduction': self._estimate_risk_reduction(improvement, risks)
                })
            elif '6-12' in timeline or '12-18' in timeline or '90' in timeline:
                priorities['long_term'].append({
                    'action': improvement.get('action', 'Unknown'),
                    'timeline': improvement.get('timeline', '90+ days'),
                    'impact': improvement.get('impact', 'High'),
                    'description': improvement.get('description', ''),
                    'estimated_risk_reduction': self._estimate_risk_reduction(improvement, risks)
                })
        
        return priorities
    
    def _estimate_risk_reduction(self, action_item, risks):
        """Estimate risk reduction percentage for an action."""
        # Simplified estimation based on action type
        action = action_item.get('action', '').lower()
        
        if 'password' in action:
            # Password-related fixes typically reduce 15-25% of risks
            return "15-25%"
        elif 'delegation' in action:
            # Delegation fixes are high impact
            return "20-30%"
        elif 'admin' in action or 'privilege' in action:
            # Privilege-related fixes
            return "10-20%"
        elif 'upgrade' in action or 'eol' in action:
            # System upgrades
            return "5-15%"
        else:
            return "10-20%"
    
    def _extract_group_name(self, group_dn):
        """Extract group name from DN."""
        if not group_dn:
            return None
        if 'CN=' in group_dn:
            try:
                cn_part = group_dn.split('CN=')[1].split(',')[0]
                return cn_part
            except Exception:
                return None
        return group_dn
    
    def _calculate_account_activity_statistics(self, users):
        """Calculate account activity statistics (recently created, group changes)."""
        from datetime import datetime
        
        stats = {
            'recently_created': {
                'last_10_days': 0,
                'last_30_days': 0,
                'last_60_days': 0,
                'last_90_days': 0,
                'details': []
            },
            'recently_group_changed': {
                'last_10_days': 0,
                'last_30_days': 0,
                'last_60_days': 0,
                'last_90_days': 0,
                'details': []
            }
        }
        
        for user in users:
            username = user.get('sAMAccountName', 'Unknown')
            
            # Check recently created accounts
            if user.get('createdInLast10Days'):
                stats['recently_created']['last_10_days'] += 1
                stats['recently_created']['details'].append({
                    'username': username,
                    'days_ago': user.get('accountAgeDays', 0),
                    'period': '10 days'
                })
            elif user.get('createdInLast30Days'):
                stats['recently_created']['last_30_days'] += 1
                stats['recently_created']['details'].append({
                    'username': username,
                    'days_ago': user.get('accountAgeDays', 0),
                    'period': '30 days'
                })
            elif user.get('createdInLast60Days'):
                stats['recently_created']['last_60_days'] += 1
                stats['recently_created']['details'].append({
                    'username': username,
                    'days_ago': user.get('accountAgeDays', 0),
                    'period': '60 days'
                })
            elif user.get('createdInLast90Days'):
                stats['recently_created']['last_90_days'] += 1
                stats['recently_created']['details'].append({
                    'username': username,
                    'days_ago': user.get('accountAgeDays', 0),
                    'period': '90 days'
                })
            
            # Check recently modified group membership
            if user.get('groupChangedInLast10Days'):
                stats['recently_group_changed']['last_10_days'] += 1
                stats['recently_group_changed']['details'].append({
                    'username': username,
                    'period': '10 days'
                })
            elif user.get('groupChangedInLast30Days'):
                stats['recently_group_changed']['last_30_days'] += 1
                stats['recently_group_changed']['details'].append({
                    'username': username,
                    'period': '30 days'
                })
            elif user.get('groupChangedInLast60Days'):
                stats['recently_group_changed']['last_60_days'] += 1
                stats['recently_group_changed']['details'].append({
                    'username': username,
                    'period': '60 days'
                })
            elif user.get('groupChangedInLast90Days'):
                stats['recently_group_changed']['last_90_days'] += 1
                stats['recently_group_changed']['details'].append({
                    'username': username,
                    'period': '90 days'
                })
        
        return stats
    
    def _calculate_admin_group_statistics(self, users):
        """Calculate admin group membership statistics."""
        from datetime import datetime
        
        stats = {
            'domain_admins': {
                'count': 0,
                'members': []
            },
            'enterprise_admins': {
                'count': 0,
                'members': []
            },
            'schema_admins': {
                'count': 0,
                'members': []
            },
            'total_privileged': 0
        }
        
        for user in users:
            username = user.get('sAMAccountName', 'Unknown')
            is_privileged = False
            
            # Format account creation time
            account_created_time = None
            account_created_display = 'N/A'
            when_created = user.get('whenCreated')
            if when_created:
                try:
                    if isinstance(when_created, str):
                        account_created_time = datetime.fromisoformat(when_created.replace('Z', '+00:00'))
                    elif isinstance(when_created, datetime):
                        account_created_time = when_created
                    if account_created_time:
                        if account_created_time.tzinfo:
                            account_created_time = account_created_time.replace(tzinfo=None)
                        account_created_display = account_created_time.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    pass
            
            # Format group membership change time (proxy using whenChanged)
            group_added_time = None
            group_added_display = 'N/A'
            when_changed = user.get('whenChanged')
            if when_changed:
                try:
                    if isinstance(when_changed, str):
                        group_added_time = datetime.fromisoformat(when_changed.replace('Z', '+00:00'))
                    elif isinstance(when_changed, datetime):
                        group_added_time = when_changed
                    if group_added_time:
                        if group_added_time.tzinfo:
                            group_added_time = group_added_time.replace(tzinfo=None)
                        group_added_display = group_added_time.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    pass
            
            # Check Domain Admin groups
            domain_admin_groups = user.get('domainAdminGroups', [])
            if domain_admin_groups:
                stats['domain_admins']['count'] += 1
                stats['domain_admins']['members'].append({
                    'username': username,
                    'groups': domain_admin_groups,
                    'accountCreated': account_created_display,
                    'accountCreatedRaw': account_created_time.isoformat() if account_created_time else None,
                    'groupAdded': group_added_display,
                    'groupAddedRaw': group_added_time.isoformat() if group_added_time else None
                })
                is_privileged = True
            
            # Check Enterprise Admin groups
            enterprise_admin_groups = user.get('enterpriseAdminGroups', [])
            if enterprise_admin_groups:
                stats['enterprise_admins']['count'] += 1
                stats['enterprise_admins']['members'].append({
                    'username': username,
                    'groups': enterprise_admin_groups,
                    'accountCreated': account_created_display,
                    'accountCreatedRaw': account_created_time.isoformat() if account_created_time else None,
                    'groupAdded': group_added_display,
                    'groupAddedRaw': group_added_time.isoformat() if group_added_time else None
                })
                is_privileged = True
            
            # Check Schema Admin groups
            schema_admin_groups = user.get('schemaAdminGroups', [])
            if schema_admin_groups:
                stats['schema_admins']['count'] += 1
                stats['schema_admins']['members'].append({
                    'username': username,
                    'groups': schema_admin_groups,
                    'accountCreated': account_created_display,
                    'accountCreatedRaw': account_created_time.isoformat() if account_created_time else None,
                    'groupAdded': group_added_display,
                    'groupAddedRaw': group_added_time.isoformat() if group_added_time else None
                })
                is_privileged = True
            
            if is_privileged:
                stats['total_privileged'] += 1
        
        return stats
    
    def _calculate_account_status_statistics(self, users):
        """Calculate account status statistics (disabled, locked)."""
        stats = {
            'disabled': {
                'count': 0,
                'accounts': []
            },
            'locked': {
                'count': 0,
                'accounts': []
            },
            'disabled_and_locked': {
                'count': 0,
                'accounts': []
            }
        }
        
        from datetime import datetime
        
        for user in users:
            username = user.get('sAMAccountName', 'Unknown')
            is_disabled = user.get('isDisabled', False)
            is_locked = user.get('isLocked', False)
            
            # Format disabled time (use whenChanged as proxy for when disabled)
            disabled_time = None
            disabled_time_display = 'N/A'
            if is_disabled:
                when_changed = user.get('whenChanged')
                if when_changed:
                    try:
                        if isinstance(when_changed, str):
                            disabled_time = datetime.fromisoformat(when_changed.replace('Z', '+00:00'))
                        elif isinstance(when_changed, datetime):
                            disabled_time = when_changed
                        if disabled_time:
                            if disabled_time.tzinfo:
                                disabled_time = disabled_time.replace(tzinfo=None)
                            disabled_time_display = disabled_time.strftime('%Y-%m-%d %H:%M:%S')
                    except Exception:
                        pass
            
            # Format locked time (use lockoutTime)
            locked_time = None
            locked_time_display = 'N/A'
            if is_locked:
                lockout_time = user.get('lockoutTime')
                if lockout_time:
                    try:
                        if isinstance(lockout_time, str):
                            locked_time = datetime.fromisoformat(lockout_time.replace('Z', '+00:00'))
                        elif isinstance(lockout_time, datetime):
                            locked_time = lockout_time
                        if locked_time:
                            if locked_time.tzinfo:
                                locked_time = locked_time.replace(tzinfo=None)
                            locked_time_display = locked_time.strftime('%Y-%m-%d %H:%M:%S')
                    except Exception:
                        pass
            
            if is_disabled:
                stats['disabled']['count'] += 1
                stats['disabled']['accounts'].append({
                    'username': username,
                    'displayName': user.get('displayName', username),
                    'disabledTime': disabled_time_display,
                    'disabledTimeRaw': disabled_time.isoformat() if disabled_time else None
                })
            
            if is_locked:
                stats['locked']['count'] += 1
                stats['locked']['accounts'].append({
                    'username': username,
                    'displayName': user.get('displayName', username),
                    'lockedTime': locked_time_display,
                    'lockedTimeRaw': locked_time.isoformat() if locked_time else None
                })
            
            if is_disabled and is_locked:
                stats['disabled_and_locked']['count'] += 1
                stats['disabled_and_locked']['accounts'].append({
                    'username': username,
                    'displayName': user.get('displayName', username),
                    'disabledTime': disabled_time_display,
                    'lockedTime': locked_time_display
                })
        
        return stats

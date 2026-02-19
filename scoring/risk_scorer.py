"""
Enterprise-Grade Risk Scoring Engine
Based on CIS Benchmark, Microsoft Security Baseline, and real-world AD audit practices
"""

import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


class RiskScorer:
    """
    Enterprise-grade risk scoring engine.
    Risk = Impact × Likelihood × Prevalence
    """
    
    # Base risk scores (0-100 scale)
    BASE_RISK_SCORES = {
        'user_password_never_expires': 30,
        'password_not_required': 95,  # Critical - even higher than specified
        'kerberos_preauth_disabled': 85,
        'user_with_spn': 40,
        'admin_count_set': 60,
        'inactive_privileged_account': 50,
        'unconstrained_delegation': 90,
        'unconstrained_delegation_user': 90,
        'constrained_delegation': 45,
        'computer_unconstrained_delegation': 90,
        'computer_broad_constrained_delegation': 55,
        'eol_operating_system': 70,
        'too_many_domain_admins': 75,
        'nested_admin_group': 65,
        'operators_group_members': 60,
        'duplicate_spn': 50,
        'privilege_escalation_path': 55,
        'delegation_privilege_escalation': 95,
        'spn_privilege_escalation': 70,
        'computer_delegation_privilege_path': 95,
        'acl_generic_all': 80,
        'acl_write_dacl': 85,
        'acl_write_owner': 85,
        'acl_generic_write': 60,
        'rbcd_delegation': 85,
        'sid_history_present': 70,
        'foreign_security_principal': 35,
        'empty_group': 15,
        'deeply_nested_group': 25,
        'computer_account_expired': 40,
        'bitlocker_recovery_in_ad': 30,
        'ou_delegation_risk': 60,
        'ou_gpo_inheritance_blocked': 35,
        'printer_object_risk': 45,
        'exchange_objects_found': 20,
        'dns_zone_found': 15,
        'ad_recycle_bin_deleted_objects': 40,
        'ad_recycle_bin_enabled': 5,
        'adminsdholder_analysis': 25,
        'fine_grained_password_policy': 20,
        'key_credential_link_present': 65,
    }
    
    # Object type multipliers
    OBJECT_TYPE_MULTIPLIERS = {
        'normal_user': 1.0,
        'privileged_user': 1.5,
        'domain_controller': 2.0,
        'computer': 1.2,
        'group': 1.3,
        'gpo': 1.4
    }
    
    # Prevalence multipliers
    PREVALENCE_MULTIPLIERS = {
        1: 1.0,
        2: 1.2,
        3: 1.2,
        4: 1.2,
        5: 1.2,
    }
    # 6+ objects → 1.4
    
    def __init__(self):
        """Initialize risk scorer."""
        self.risk_counts = defaultdict(int)
        self.object_risk_map = defaultdict(list)
    
    def score_risks(self, risks, users=None, groups=None, computers=None):
        """
        Score all risks with enterprise-grade calculation.
        
        Args:
            risks: List of risk dictionaries
            users: List of user dictionaries (for context)
            groups: List of group dictionaries (for context)
            computers: List of computer dictionaries (for context)
        
        Returns:
            list: List of scored risk dictionaries with additional fields
        """
        if not risks:
            return []
        
        # Build context maps
        user_map = {u.get('sAMAccountName'): u for u in (users or [])}
        group_map = {g.get('name') or g.get('sAMAccountName'): g for g in (groups or [])}
        computer_map = {c.get('name'): c for c in (computers or [])}
        
        # Count risk types for prevalence calculation
        self._count_risk_types(risks)
        
        # Score each risk
        scored_risks = []
        for risk in risks:
            scored_risk = self._score_single_risk(risk, user_map, group_map, computer_map)
            scored_risks.append(scored_risk)
        
        # Apply combination bonuses
        scored_risks = self._apply_combination_bonuses(scored_risks, user_map, group_map, computer_map)
        
        # Sort by final score (highest first)
        scored_risks.sort(key=lambda x: x.get('final_score', 0), reverse=True)
        
        # Add severity level
        for risk in scored_risks:
            risk['severity_level'] = self._calculate_severity_level(risk.get('final_score', 0))
            risk['severity'] = risk['severity_level'].lower()
        
        logger.info(f"Scored {len(scored_risks)} risks")
        return scored_risks
    
    def _count_risk_types(self, risks):
        """Count occurrences of each risk type for prevalence calculation."""
        self.risk_counts.clear()
        for risk in risks:
            risk_type = risk.get('type', 'unknown')
            self.risk_counts[risk_type] += 1
    
    def _score_single_risk(self, risk, user_map, group_map, computer_map):
        """
        Score a single risk.
        
        Formula: Base Score × Object Type Multiplier × Prevalence Multiplier
        """
        risk_type = risk.get('type', 'unknown')
        base_score = self.BASE_RISK_SCORES.get(risk_type, 50)  # Default 50 if unknown
        
        # Determine object type and multiplier
        object_type_multiplier = self._get_object_type_multiplier(risk, user_map, group_map, computer_map)
        
        # Get prevalence multiplier
        prevalence_count = self.risk_counts.get(risk_type, 1)
        prevalence_multiplier = self._get_prevalence_multiplier(prevalence_count)
        
        # Calculate intermediate score
        intermediate_score = base_score * object_type_multiplier * prevalence_multiplier
        
        # Cap at 100
        final_score = min(intermediate_score, 100.0)
        
        # Add scoring details to risk
        risk['base_score'] = base_score
        risk['object_type_multiplier'] = object_type_multiplier
        risk['prevalence_multiplier'] = prevalence_multiplier
        risk['intermediate_score'] = round(intermediate_score, 2)
        risk['final_score'] = round(final_score, 2)
        risk['prevalence_count'] = prevalence_count
        
        # Add executive description
        if 'executive_description' not in risk:
            risk['executive_description'] = self._generate_executive_description(risk)
        
        # Track object risks for combination bonuses
        affected_object = risk.get('affected_object')
        if affected_object:
            self.object_risk_map[affected_object].append(risk)
        
        return risk
    
    def _get_object_type_multiplier(self, risk, user_map, group_map, computer_map):
        """Determine object type multiplier based on risk context."""
        object_type = risk.get('object_type', '').lower()
        affected_object = risk.get('affected_object')
        
        if object_type == 'user' and affected_object:
            user = user_map.get(affected_object)
            if user:
                # Check if privileged user
                if user.get('adminCount') == 1 or user.get('adminCount') == '1':
                    return self.OBJECT_TYPE_MULTIPLIERS['privileged_user']
                # Check if member of privileged groups
                member_of = user.get('memberOf', []) or []
                if not isinstance(member_of, list):
                    member_of = [member_of] if member_of else []
                for group_dn in member_of:
                    group_name = self._extract_group_name(group_dn)
                    if any(priv in (group_name or '').upper() for priv in 
                           ['DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'SCHEMA ADMINS']):
                        return self.OBJECT_TYPE_MULTIPLIERS['privileged_user']
            return self.OBJECT_TYPE_MULTIPLIERS['normal_user']
        
        elif object_type == 'computer' and affected_object:
            computer = computer_map.get(affected_object)
            if computer:
                name = (computer.get('name') or '').upper()
                if 'DC' in name or 'CONTROLLER' in name:
                    return self.OBJECT_TYPE_MULTIPLIERS['domain_controller']
            return self.OBJECT_TYPE_MULTIPLIERS['computer']
        
        elif object_type == 'group':
            return self.OBJECT_TYPE_MULTIPLIERS['group']
        
        elif object_type == 'gpo':
            return self.OBJECT_TYPE_MULTIPLIERS['gpo']
        
        # Default multiplier
        return 1.0
    
    def _get_prevalence_multiplier(self, count):
        """Get prevalence multiplier based on count."""
        if count >= 6:
            return 1.4
        return self.PREVALENCE_MULTIPLIERS.get(count, 1.0)
    
    def _apply_combination_bonuses(self, scored_risks, user_map, group_map, computer_map):
        """
        Apply combination bonuses:
        - Same object with 2+ risks: +20%
        - Same path with 2+ risks: +30%
        """
        # Group risks by affected object
        object_risks = defaultdict(list)
        for risk in scored_risks:
            affected_object = risk.get('affected_object')
            if affected_object:
                object_risks[affected_object].append(risk)
        
        # Apply same-object bonus
        for obj, risks_list in object_risks.items():
            if len(risks_list) >= 2:
                bonus_percentage = 0.20  # 20% bonus
                for risk in risks_list:
                    current_score = risk.get('final_score', 0)
                    bonus = current_score * bonus_percentage
                    risk['final_score'] = min(current_score + bonus, 100.0)
                    risk['combination_bonus'] = f"+{bonus_percentage*100:.0f}% (multiple risks on same object)"
        
        # Apply path-based bonus (for escalation paths)
        path_risks = defaultdict(list)
        for risk in scored_risks:
            escalation_path = risk.get('escalation_path', {})
            if escalation_path:
                # Create path identifier
                user = escalation_path.get('user', '')
                path_key = f"{user}_{risk.get('type', '')}"
                path_risks[path_key].append(risk)
        
        for path_key, risks_list in path_risks.items():
            if len(risks_list) >= 2:
                bonus_percentage = 0.30  # 30% bonus
                for risk in risks_list:
                    current_score = risk.get('final_score', 0)
                    bonus = current_score * bonus_percentage
                    risk['final_score'] = min(current_score + bonus, 100.0)
                    if 'combination_bonus' not in risk:
                        risk['combination_bonus'] = f"+{bonus_percentage*100:.0f}% (multiple risks on same path)"
                    else:
                        risk['combination_bonus'] += f", +{bonus_percentage*100:.0f}% (path)"
        
        return scored_risks
    
    def _calculate_severity_level(self, score):
        """
        Calculate severity level based on score.
        
        0-20   : Low
        21-40  : Medium
        41-70  : High
        71-100 : Critical
        """
        if score <= 20:
            return 'Low'
        elif score <= 40:
            return 'Medium'
        elif score <= 70:
            return 'High'
        else:
            return 'Critical'
    
    def calculate_domain_score(self, scored_risks):
        """
        Calculate overall domain security score (0-100, higher is better).
        
        Formula: Weighted score based on risk severity distribution and total risk impact
        Uses logarithmic scaling to prevent score from dropping to 0 too quickly
        """
        if not scored_risks:
            return 100.0
        
        # Count risks by severity
        critical_count = len([r for r in scored_risks if (r.get('severity_level', '').lower() == 'critical' or 
                                                          r.get('severity', '').lower() == 'critical')])
        high_count = len([r for r in scored_risks if (r.get('severity_level', '').lower() == 'high' or 
                                                     r.get('severity', '').lower() == 'high')])
        medium_count = len([r for r in scored_risks if (r.get('severity_level', '').lower() == 'medium' or 
                                                       r.get('severity', '').lower() == 'medium')])
        low_count = len([r for r in scored_risks if (r.get('severity_level', '').lower() == 'low' or 
                                                    r.get('severity', '').lower() == 'low')])
        
        total_risks = len(scored_risks)
        
        # Calculate average risk score
        total_risk_points = sum(risk.get('final_score', 0) for risk in scored_risks)
        avg_risk_score = total_risk_points / total_risks if total_risks > 0 else 0
        
        # Weighted penalty calculation using logarithmic scaling
        # Critical risks: heavier penalty but with diminishing returns
        import math
        critical_penalty = min(critical_count * 3.5, 35)  # Max 35 points for 10+ critical
        high_penalty = min(high_count * 2.0, 20)  # Max 20 points for 10+ high
        medium_penalty = min(medium_count * 0.8, 15)  # Max 15 points for 18+ medium
        low_penalty = min(low_count * 0.3, 10)  # Max 10 points for 33+ low
        
        # Average risk score penalty: if avg > 60, additional penalty
        avg_penalty = 0
        if avg_risk_score > 60:
            avg_penalty = (avg_risk_score - 60) * 0.2  # Max ~8 points for avg 100
        
        # Risk density penalty: too many risks relative to objects
        affected_objects = set()
        for risk in scored_risks:
            affected_object = risk.get('affected_object')
            if affected_object:
                affected_objects.add(affected_object)
        
        object_count = len(affected_objects) if affected_objects else 1
        risks_per_object = total_risks / object_count if object_count > 0 else total_risks
        
        # If more than 2 risks per object on average, apply density penalty
        density_penalty = 0
        if risks_per_object > 2:
            density_penalty = min((risks_per_object - 2) * 2, 10)  # Max 10 points
        
        # Calculate final score
        security_score = 100.0 - critical_penalty - high_penalty - medium_penalty - low_penalty - avg_penalty - density_penalty
        
        # Apply bounds: minimum 0, maximum 100
        security_score = max(0.0, min(100.0, security_score))
        
        return round(security_score, 1)
    
    def generate_executive_summary(self, scored_risks, users, computers, groups):
        """
        Generate executive summary with:
        - Top 5 critical risks
        - Most risky object
        - Quick wins
        - Long-term improvements
        """
        summary = {
            'top_critical_risks': [],
            'most_risky_object': None,
            'quick_wins': [],
            'long_term_improvements': []
        }
        
        if not scored_risks:
            return summary
        
        # Top 5 critical risks
        critical_risks = [r for r in scored_risks if r.get('severity_level') == 'Critical']
        high_risks = [r for r in scored_risks if r.get('severity_level') == 'High']
        
        top_risks = (critical_risks + high_risks)[:5]
        summary['top_critical_risks'] = [
            {
                'title': r.get('title', 'Unknown Risk'),
                'score': r.get('final_score', 0),
                'affected_object': r.get('affected_object', 'Unknown'),
                'executive_description': self._generate_executive_description(r)
            }
            for r in top_risks
        ]
        
        # Most risky object
        object_scores = defaultdict(float)
        for risk in scored_risks:
            affected_object = risk.get('affected_object')
            if affected_object:
                object_scores[affected_object] += risk.get('final_score', 0)
        
        if object_scores:
            most_risky = max(object_scores.items(), key=lambda x: x[1])
            summary['most_risky_object'] = {
                'object': most_risky[0],
                'total_risk_score': round(most_risky[1], 2),
                'risk_count': len([r for r in scored_risks if r.get('affected_object') == most_risky[0]])
            }
        
        # Quick wins (high impact, low effort)
        quick_wins = self._identify_quick_wins(scored_risks)
        summary['quick_wins'] = quick_wins
        
        # Long-term improvements
        long_term = self._identify_long_term_improvements(scored_risks)
        summary['long_term_improvements'] = long_term
        
        return summary
    
    def _generate_executive_description(self, risk):
        """Generate executive-friendly description of risk."""
        risk_type = risk.get('type', '')
        score = risk.get('final_score', 0)
        affected = risk.get('affected_object', 'Unknown')
        
        descriptions = {
            'password_not_required': f"Account '{affected}' can be accessed without a password. This is an extreme security vulnerability that must be fixed immediately.",
            'unconstrained_delegation': f"Computer '{affected}' has unconstrained delegation enabled, allowing it to impersonate any user in the domain. This creates a critical privilege escalation risk.",
            'kerberos_preauth_disabled': f"Account '{affected}' has Kerberos preauthentication disabled, allowing attackers to attempt password cracking without triggering account lockouts.",
            'eol_operating_system': f"Computer '{affected}' is running an end-of-life operating system that no longer receives security updates, making it vulnerable to known exploits.",
            'too_many_domain_admins': f"Domain Admins group has excessive members, increasing the attack surface and making it harder to secure privileged access.",
            'delegation_privilege_escalation': f"User '{affected}' has both delegation rights and privileged group membership, creating a critical escalation path.",
        }
        
        return descriptions.get(risk_type, 
            f"Security risk detected on '{affected}' with a risk score of {score:.1f}/100. Immediate review and remediation recommended.")
    
    def _identify_quick_wins(self, scored_risks):
        """Identify quick wins - high impact, low effort fixes."""
        quick_wins = []
        
        # Password not required - easy fix
        pwd_not_req = [r for r in scored_risks if r.get('type') == 'password_not_required']
        if pwd_not_req:
            quick_wins.append({
                'action': 'Remove password not required flag',
                'impact': 'Critical',
                'effort': 'Low',
                'affected_count': len(pwd_not_req),
                'description': f"Remove the password not required flag from {len(pwd_not_req)} account(s). This can be done immediately and significantly improves security."
            })
        
        # Password never expires - easy fix
        pwd_never_exp = [r for r in scored_risks if r.get('type') == 'user_password_never_expires']
        if pwd_never_exp:
            quick_wins.append({
                'action': 'Enable password expiration',
                'impact': 'High',
                'effort': 'Low',
                'affected_count': len(pwd_never_exp),
                'description': f"Enable password expiration for {len(pwd_never_exp)} account(s). Review and set appropriate expiration policies."
            })
        
        # Excessive Domain Admins - medium effort
        too_many_admins = [r for r in scored_risks if r.get('type') == 'too_many_domain_admins']
        if too_many_admins:
            quick_wins.append({
                'action': 'Reduce Domain Admins membership',
                'impact': 'High',
                'effort': 'Medium',
                'affected_count': 1,
                'description': "Reduce Domain Admins group membership to 2-3 accounts. Use role-based access for other administrative functions."
            })
        
        return quick_wins[:5]  # Top 5 quick wins
    
    def _identify_long_term_improvements(self, scored_risks):
        """Identify long-term improvement recommendations."""
        improvements = []
        
        # Unconstrained delegation - requires planning
        unconstrained = [r for r in scored_risks if 'unconstrained_delegation' in r.get('type', '')]
        if unconstrained:
            improvements.append({
                'action': 'Migrate from unconstrained to constrained delegation',
                'timeline': '3-6 months',
                'impact': 'Critical',
                'description': f"Replace unconstrained delegation on {len(unconstrained)} object(s) with constrained or resource-based constrained delegation. This requires application compatibility testing."
            })
        
        # EOL operating systems - requires upgrade
        eol_os = [r for r in scored_risks if r.get('type') == 'eol_operating_system']
        if eol_os:
            improvements.append({
                'action': 'Upgrade end-of-life operating systems',
                'timeline': '6-12 months',
                'impact': 'Critical',
                'description': f"Upgrade {len(eol_os)} computer(s) running end-of-life operating systems to supported versions. Plan for application compatibility and migration."
            })
        
        # ACL review - requires audit
        acl_risks = [r for r in scored_risks if 'acl' in r.get('type', '').lower()]
        if acl_risks:
            improvements.append({
                'action': 'Comprehensive ACL audit and remediation',
                'timeline': '6-12 months',
                'impact': 'High',
                'description': "Conduct comprehensive ACL review on all privileged objects. Implement principle of least privilege and regular ACL audits."
            })
        
        # Tiering model - requires architecture
        tiering_issues = [r for r in scored_risks if 'tiering' in r.get('type', '').lower() or 
                         (r.get('type') == 'spn_privilege_escalation' and r.get('object_type') == 'user')]
        if tiering_issues:
            improvements.append({
                'action': 'Implement tiering model',
                'timeline': '12-18 months',
                'impact': 'High',
                'description': "Implement Microsoft's tiering model to separate administrative accounts from service accounts. Use managed service accounts (MSAs/gMSAs) for services."
            })
        
        return improvements
    
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

"""
Risk Management Module
Risk heat map, business impact assessment, remediation cost estimation, ROI calculation
"""

import logging
from typing import Dict, Any, List, Optional
from collections import defaultdict
import math

logger = logging.getLogger(__name__)


class RiskManager:
    """
    Advanced risk management with business impact and ROI calculations.
    """
    
    # Default business impact multipliers
    BUSINESS_IMPACT_MULTIPLIERS = {
        'critical': {'financial': 1.0, 'reputation': 1.0, 'operational': 1.0, 'compliance': 1.0},
        'high': {'financial': 0.7, 'reputation': 0.7, 'operational': 0.7, 'compliance': 0.7},
        'medium': {'financial': 0.4, 'reputation': 0.4, 'operational': 0.4, 'compliance': 0.4},
        'low': {'financial': 0.1, 'reputation': 0.1, 'operational': 0.1, 'compliance': 0.1}
    }
    
    # Default remediation cost estimates (in hours)
    REMEDIATION_COST_ESTIMATES = {
        'user_password_never_expires': 0.5,
        'password_not_required': 0.5,
        'kerberos_preauth_disabled': 1.0,
        'unconstrained_delegation': 2.0,
        'too_many_domain_admins': 4.0,
        'weak_password_policy': 2.0,
        'password_policy_weak': 2.0,
        'account_lockout_disabled': 1.0,
        'eol_operating_system': 8.0,
        'legacy_operating_system': 6.0,
        'inactive_computer': 1.0,
        'never_used_computer': 1.0,
        'laps_not_configured': 4.0,
        'laps_access_analysis': 3.0,
        'gpp_passwords': 2.0,
        'gpp_password_found': 2.0,
        'dcsync_rights': 1.0,
        'trust_sid_filtering_disabled': 2.0,
        'trust_relationship_risk': 3.0,
        'privilege_escalation_path': 4.0,
        'shadow_admin': 2.0,
        'kerberoasting_target': 1.0,
        'asrep_roasting_target': 1.0,
        'service_account_high_privilege': 2.0,
        'service_account_without_msa': 4.0,
        'service_account_password_never_expires': 0.5,
        'gpo_modification_rights': 3.0,
        'gpo_linked_to_privileged_ou': 3.0,
        'ldap_signing_disabled': 4.0,
        'ntlm_restriction_weak': 3.0,
        'smb_signing_disabled': 3.0,
        'krbtgt_password_age': 2.0,
        'krbtgt_weak_encryption': 2.0,
        'machine_account_quota_high': 1.0,
        'password_spray_risk': 2.0,
        'password_spray_no_lockout': 2.0,
        'backup_operator_risk': 2.0,
        'sensitive_operator_risk': 2.0,
        'audit_policy_insufficient': 4.0,
        'audit_sacl_missing': 4.0,
    }
    
    # Default hourly rate (can be customized)
    DEFAULT_HOURLY_RATE = 100.0
    
    def __init__(self, hourly_rate: float = DEFAULT_HOURLY_RATE):
        """
        Initialize risk manager.
        
        Args:
            hourly_rate: Hourly rate for cost calculations
        """
        self.hourly_rate = hourly_rate
    
    def calculate_business_impact(self, risk: Dict[str, Any], 
                                 business_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Calculate business impact of a risk.
        
        Args:
            risk: Risk dictionary
            business_context: Optional business context (revenue, employees, etc.)
            
        Returns:
            Dict with business impact assessment
        """
        severity = risk.get('severity', 'medium').lower()
        multipliers = self.BUSINESS_IMPACT_MULTIPLIERS.get(severity, self.BUSINESS_IMPACT_MULTIPLIERS['medium'])
        
        # Base impact scores (0-100)
        base_financial = 50.0
        base_reputation = 50.0
        base_operational = 50.0
        base_compliance = 50.0
        
        # Apply multipliers
        financial_impact = base_financial * multipliers['financial']
        reputation_impact = base_reputation * multipliers['reputation']
        operational_impact = base_operational * multipliers['operational']
        compliance_impact = base_compliance * multipliers['compliance']
        
        # Adjust based on business context if provided
        if business_context:
            revenue = business_context.get('annual_revenue', 0)
            employees = business_context.get('employees', 0)
            
            # Scale financial impact based on revenue
            if revenue > 0:
                financial_impact *= min(2.0, math.log10(revenue / 1000000) + 1)
            
            # Scale operational impact based on employees
            if employees > 0:
                operational_impact *= min(2.0, math.log10(employees / 100) + 1)
        
        # Calculate overall business impact score
        overall_impact = (financial_impact + reputation_impact + operational_impact + compliance_impact) / 4
        
        return {
            'financial_impact': round(financial_impact, 2),
            'reputation_impact': round(reputation_impact, 2),
            'operational_impact': round(operational_impact, 2),
            'compliance_impact': round(compliance_impact, 2),
            'overall_impact': round(overall_impact, 2),
            'severity': severity
        }
    
    def estimate_remediation_cost(self, risk: Dict[str, Any], 
                                 custom_costs: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
        """
        Estimate remediation cost for a risk.
        
        Args:
            risk: Risk dictionary
            custom_costs: Optional custom cost estimates
            
        Returns:
            Dict with cost estimation
        """
        risk_type = risk.get('type', '')
        cost_estimates = custom_costs or self.REMEDIATION_COST_ESTIMATES

        # Get base hours for this risk type
        base_hours = self._get_base_remediation_hours(risk_type, cost_estimates)
        
        # Adjust based on severity
        severity = risk.get('severity', 'medium').lower()
        severity_multipliers = {
            'critical': 1.5,
            'high': 1.2,
            'medium': 1.0,
            'low': 0.8
        }
        multiplier = severity_multipliers.get(severity, 1.0)
        
        # Calculate hours
        estimated_hours = base_hours * multiplier
        
        # Calculate costs
        labor_cost = estimated_hours * self.hourly_rate
        
        # Estimate additional costs (tools, licenses, etc.)
        additional_cost_multiplier = 0.2  # 20% of labor cost
        additional_costs = labor_cost * additional_cost_multiplier
        
        total_cost = labor_cost + additional_costs
        
        return {
            'estimated_hours': round(estimated_hours, 2),
            'labor_cost': round(labor_cost, 2),
            'additional_costs': round(additional_costs, 2),
            'total_cost': round(total_cost, 2),
            'currency': 'USD'
        }

    def _get_base_remediation_hours(self, risk_type: str, cost_estimates: Dict[str, float]) -> float:
        """Return exact or category-based remediation effort in hours."""
        if risk_type in cost_estimates:
            return cost_estimates[risk_type]

        category_defaults = (
            ('acl_', 3.0),
            ('certificate_esc', 6.0),
            ('certificate_certifried', 6.0),
            ('certificate_services', 1.0),
            ('coercion_', 4.0),
            ('golden_gmsa_', 6.0),
            ('gmsa_', 4.0),
            ('lateral_movement_', 6.0),
            ('replication_', 3.0),
            ('stale_', 1.0),
            ('zerologon_', 8.0),
            ('printnightmare_', 6.0),
            ('petitpotam_', 4.0),
            ('nopac_', 6.0),
        )
        for prefix, hours in category_defaults:
            if risk_type.startswith(prefix):
                return hours

        return 2.0
    
    def calculate_roi(self, risk: Dict[str, Any], business_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Calculate ROI of remediating a risk.
        
        Args:
            risk: Risk dictionary
            business_context: Optional business context
            
        Returns:
            Dict with ROI calculation
        """
        # Calculate business impact
        impact = self.calculate_business_impact(risk, business_context)
        
        # Estimate remediation cost
        cost = self.estimate_remediation_cost(risk)
        
        # Calculate potential loss (if risk is exploited)
        # Assume potential loss is proportional to business impact
        potential_loss_multiplier = impact['overall_impact'] / 100.0
        
        # Base potential loss (can be customized)
        base_potential_loss = 100000.0  # $100k base
        if business_context:
            revenue = business_context.get('annual_revenue', 0)
            if revenue > 0:
                base_potential_loss = revenue * 0.01  # 1% of revenue
        
        potential_loss = base_potential_loss * potential_loss_multiplier
        
        # Calculate ROI
        # ROI = (Benefit - Cost) / Cost * 100
        # Benefit = Potential Loss Avoided
        benefit = potential_loss
        roi = ((benefit - cost['total_cost']) / cost['total_cost'] * 100) if cost['total_cost'] > 0 else 0
        
        # Calculate payback period (in months)
        # Assuming monthly benefit is 1/12 of annual benefit
        monthly_benefit = benefit / 12
        payback_period = (cost['total_cost'] / monthly_benefit) if monthly_benefit > 0 else 0
        
        return {
            'potential_loss': round(potential_loss, 2),
            'remediation_cost': cost['total_cost'],
            'benefit': round(benefit, 2),
            'roi_percentage': round(roi, 2),
            'payback_period_months': round(payback_period, 2),
            'net_benefit': round(benefit - cost['total_cost'], 2),
            'currency': 'USD'
        }
    
    def generate_risk_heat_map(self, risks: List[Dict[str, Any]], 
                               business_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate risk heat map based on impact and likelihood.
        
        Args:
            risks: List of risk dictionaries
            business_context: Optional business context
            
        Returns:
            Dict with heat map data
        """
        heat_map = {
            'critical_high': [],
            'critical_medium': [],
            'critical_low': [],
            'high_high': [],
            'high_medium': [],
            'high_low': [],
            'medium_high': [],
            'medium_medium': [],
            'medium_low': [],
            'low_high': [],
            'low_medium': [],
            'low_low': []
        }
        
        for risk in risks:
            severity = risk.get('severity', 'medium').lower()
            exploitability = risk.get('exploitability', {})
            likelihood = exploitability.get('score', 50) if isinstance(exploitability, dict) else 50
            
            # Categorize likelihood
            if likelihood >= 75:
                likelihood_category = 'high'
            elif likelihood >= 50:
                likelihood_category = 'medium'
            else:
                likelihood_category = 'low'
            
            # Create key
            key = f"{severity}_{likelihood_category}"
            
            if key in heat_map:
                impact = self.calculate_business_impact(risk, business_context)
                cost = self.estimate_remediation_cost(risk)
                roi = self.calculate_roi(risk, business_context)
                
                heat_map[key].append({
                    'risk': risk,
                    'impact': impact,
                    'cost': cost,
                    'roi': roi
                })
        
        # Calculate statistics
        stats = {}
        for category, items in heat_map.items():
            if items:
                stats[category] = {
                    'count': len(items),
                    'total_cost': sum(item['cost']['total_cost'] for item in items),
                    'total_potential_loss': sum(item['roi']['potential_loss'] for item in items),
                    'average_roi': sum(item['roi']['roi_percentage'] for item in items) / len(items)
                }
        
        return {
            'heat_map': heat_map,
            'statistics': stats,
            'total_risks': len(risks)
        }
    
    def prioritize_risks(self, risks: List[Dict[str, Any]], 
                        business_context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Prioritize risks based on ROI and impact.
        
        Args:
            risks: List of risk dictionaries
            business_context: Optional business context
            
        Returns:
            List of prioritized risks with ROI data
        """
        prioritized = []
        
        for risk in risks:
            impact = self.calculate_business_impact(risk, business_context)
            cost = self.estimate_remediation_cost(risk)
            roi = self.calculate_roi(risk, business_context)
            
            # Calculate priority score (higher is better)
            # Priority = (Impact * ROI) / Cost
            priority_score = (impact['overall_impact'] * roi['roi_percentage']) / max(cost['total_cost'], 1)
            
            prioritized.append({
                'risk': risk,
                'impact': impact,
                'cost': cost,
                'roi': roi,
                'priority_score': round(priority_score, 2)
            })
        
        # Sort by priority score (descending)
        prioritized.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return prioritized

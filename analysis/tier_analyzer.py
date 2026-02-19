"""
TIER Model Analyzer Module
Assesses Tier 0 (DCs), Tier 1 (Admin Infrastructure), Tier 2 (Workstations/Servers)
Based on Microsoft's privileged access tier model
"""

import logging
from typing import List, Dict, Any, Optional
from core.constants import PRIVILEGED_GROUPS

logger = logging.getLogger(__name__)

TIER_0_GROUPS = ['Domain Controllers', 'Enterprise Admins', 'Schema Admins']
TIER_1_GROUPS = ['Domain Admins', 'Administrators', 'Backup Operators', 'Account Operators',
                 'Server Operators', 'Print Operators', 'DnsAdmins', 'Group Policy Creator Owners']


class TierAnalyzer:
    """Assesses AD objects against the Microsoft TIER model (0/1/2)."""

    def analyze_tiers(
        self,
        users: List[Dict[str, Any]],
        computers: List[Dict[str, Any]],
        groups: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Categorize users and computers into Tier 0, 1, 2.
        Returns tier breakdown and risk assessment.
        """
        result = {
            'tier_0': {'users': [], 'computers': [], 'count': 0, 'risks': []},
            'tier_1': {'users': [], 'computers': [], 'count': 0, 'risks': []},
            'tier_2': {'users': [], 'computers': [], 'count': 0, 'risks': []},
            'summary': {},
            'tier_risks': []
        }

        def _user_tier(user: Dict[str, Any]) -> int:
            member_of = user.get('memberOf', []) or []
            if not isinstance(member_of, list):
                member_of = [member_of]
            for dn in member_of:
                group_upper = str(dn).upper()
                if any(t in group_upper for t in [g.upper() for g in TIER_0_GROUPS]):
                    return 0
                if any(t in group_upper for t in [g.upper() for g in TIER_1_GROUPS]):
                    return 1
            return 2

        def _computer_tier(computer: Dict[str, Any]) -> int:
            name = computer.get('name', '')
            os_name = computer.get('operatingSystem', '') or ''
            if 'DC' in name.upper() or 'DOMAIN CONTROLLER' in os_name.upper():
                return 0
            # Servers typically Tier 1, workstations Tier 2
            if 'SERVER' in os_name.upper():
                return 1
            return 2

        tier0_users = [u for u in users if _user_tier(u) == 0]
        tier1_users = [u for u in users if _user_tier(u) == 1]
        tier2_users = [u for u in users if _user_tier(u) == 2]

        tier0_computers = [c for c in computers if _computer_tier(c) == 0]
        tier1_computers = [c for c in computers if _computer_tier(c) == 1]
        tier2_computers = [c for c in computers if _computer_tier(c) == 2]

        result['tier_0']['users'] = [u.get('sAMAccountName') for u in tier0_users]
        result['tier_0']['computers'] = [c.get('name') for c in tier0_computers]
        result['tier_0']['count'] = len(tier0_users) + len(tier0_computers)

        result['tier_1']['users'] = [u.get('sAMAccountName') for u in tier1_users]
        result['tier_1']['computers'] = [c.get('name') for c in tier1_computers]
        result['tier_1']['count'] = len(tier1_users) + len(tier1_computers)

        result['tier_2']['users'] = [u.get('sAMAccountName') for u in tier2_users]
        result['tier_2']['computers'] = [c.get('name') for c in tier2_computers]
        result['tier_2']['count'] = len(tier2_users) + len(tier2_computers)

        result['summary'] = {
            'tier_0_users': len(tier0_users),
            'tier_0_computers': len(tier0_computers),
            'tier_1_users': len(tier1_users),
            'tier_1_computers': len(tier1_computers),
            'tier_2_users': len(tier2_users),
            'tier_2_computers': len(tier2_computers),
        }

        # Tier risks: too many Tier 0/1, Tier 2 in admin groups, etc.
        if len(tier0_users) > 5:
            result['tier_risks'].append({
                'severity': 'high',
                'title': 'Excessive Tier 0 User Count',
                'description': f'{len(tier0_users)} users have Tier 0 access. Limit Tier 0 to minimal break-glass accounts.'
            })
        if len(tier1_users) > 15:
            result['tier_risks'].append({
                'severity': 'medium',
                'title': 'Excessive Tier 1 User Count',
                'description': f'{len(tier1_users)} users have Tier 1 (admin) access. Consider reducing.'
            })

        logger.info(f"TIER analysis: T0={result['tier_0']['count']}, T1={result['tier_1']['count']}, T2={result['tier_2']['count']}")
        return result

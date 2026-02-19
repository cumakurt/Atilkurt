"""
Type Definitions Module
TypedDict definitions for better type safety
"""

from typing import TypedDict, List, Optional, Dict, Any
from datetime import datetime


class UserDict(TypedDict, total=False):
    """User dictionary type definition."""
    sAMAccountName: str
    displayName: Optional[str]
    memberOf: List[str]
    lastLogonTimestamp: Optional[datetime]
    pwdLastSet: Optional[datetime]
    userAccountControl: int
    adminCount: Optional[int]
    servicePrincipalName: List[str]
    mail: Optional[str]
    whenCreated: Optional[datetime]
    whenChanged: Optional[datetime]
    description: Optional[str]
    distinguishedName: str
    lockoutTime: Optional[datetime]
    accountExpires: Optional[datetime]
    isDisabled: Optional[bool]
    isLocked: Optional[bool]
    # Enriched fields
    accountAgeDays: Optional[int]
    domainAdminGroups: List[str]
    enterpriseAdminGroups: List[str]
    schemaAdminGroups: List[str]
    adminGroups: List[str]
    adminPrivilegeAgeDays: Optional[int]
    isServiceAccount: bool
    daysSinceLastLogon: Optional[int]
    createdInLast10Days: Optional[bool]
    createdInLast30Days: Optional[bool]
    createdInLast60Days: Optional[bool]
    createdInLast90Days: Optional[bool]
    groupChangedInLast10Days: Optional[bool]
    groupChangedInLast30Days: Optional[bool]
    groupChangedInLast60Days: Optional[bool]
    groupChangedInLast90Days: Optional[bool]


class ComputerDict(TypedDict, total=False):
    """Computer dictionary type definition."""
    name: str
    distinguishedName: str
    operatingSystem: Optional[str]
    operatingSystemVersion: Optional[str]
    lastLogonTimestamp: Optional[datetime]
    whenCreated: Optional[datetime]
    whenChanged: Optional[datetime]
    userAccountControl: int
    unconstrainedDelegation: Optional[bool]
    trustedToAuthForDelegation: Optional[bool]
    msDS_AllowedToDelegateTo: Optional[List[str]]  # LDAP attribute: msDS-AllowedToDelegateTo
    # Enriched fields
    daysSinceLastLogon: Optional[int]
    inactiveFor10Days: Optional[bool]
    inactiveFor30Days: Optional[bool]
    inactiveFor60Days: Optional[bool]
    inactiveFor90Days: Optional[bool]
    neverUsed: Optional[bool]
    isEOL: Optional[bool]
    eolDate: Optional[datetime]


class GroupDict(TypedDict, total=False):
    """Group dictionary type definition."""
    name: str
    sAMAccountName: Optional[str]
    distinguishedName: str
    member: List[str]
    memberOf: Optional[List[str]]
    whenCreated: Optional[datetime]
    whenChanged: Optional[datetime]
    description: Optional[str]
    # Enriched fields
    memberCount: Optional[int]
    isPrivileged: Optional[bool]
    isNested: Optional[bool]


class GPODict(TypedDict, total=False):
    """GPO dictionary type definition."""
    name: str
    distinguishedName: str
    displayName: Optional[str]
    whenCreated: Optional[datetime]
    whenChanged: Optional[datetime]
    gPCFileSysPath: Optional[str]


class RiskDict(TypedDict, total=False):
    """Risk dictionary type definition."""
    type: str
    severity: str
    title: str
    description: str
    affected_object: str
    object_type: str
    impact: Optional[str]
    attack_scenario: Optional[str]
    mitigation: Optional[str]
    cis_reference: Optional[str]
    mitre_attack: Optional[str]
    # Scoring fields
    base_score: Optional[float]
    object_type_multiplier: Optional[float]
    prevalence_multiplier: Optional[float]
    intermediate_score: Optional[float]
    final_score: Optional[float]
    prevalence_count: Optional[int]
    severity_level: Optional[str]
    executive_description: Optional[str]
    combination_bonus: Optional[str]
    # Additional fields
    spns: Optional[List[str]]
    member_of: Optional[List[str]]
    privileged_groups: Optional[List[str]]
    days_inactive: Optional[int]
    escalation_path: Optional[Dict[str, Any]]
    exploitability: Optional[Dict[str, Any]]


class EscalationPathDict(TypedDict, total=False):
    """Privilege escalation path dictionary."""
    user: str
    target_group: str
    path: List[str]
    depth: int
    probability: float
    path_type: str

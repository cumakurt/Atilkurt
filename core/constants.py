"""
Constants Module
Centralized constants for UAC flags, risk types, and other configuration values
"""

# User Account Control (UAC) Flags
class UACFlags:
    """User Account Control flag constants."""
    SCRIPT = 0x1
    ACCOUNTDISABLE = 0x2
    HOMEDIR_REQUIRED = 0x8
    LOCKOUT = 0x10
    PASSWD_NOTREQD = 0x20
    PASSWD_CANT_CHANGE = 0x40
    ENCRYPTED_TEXT_PWD_ALLOWED = 0x80
    TEMP_DUPLICATE_ACCOUNT = 0x100
    NORMAL_ACCOUNT = 0x200
    INTERDOMAIN_TRUST_ACCOUNT = 0x800
    WORKSTATION_TRUST_ACCOUNT = 0x1000
    SERVER_TRUST_ACCOUNT = 0x2000
    DONT_EXPIRE_PASSWORD = 0x10000
    MNS_LOGON_ACCOUNT = 0x20000
    SMARTCARD_REQUIRED = 0x40000
    TRUSTED_FOR_DELEGATION = 0x80000
    NOT_DELEGATED = 0x100000
    USE_DES_KEY_ONLY = 0x200000
    DONT_REQUIRE_PREAUTH = 0x400000
    PASSWORD_EXPIRED = 0x800000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
    PARTIAL_SECRETS_ACCOUNT = 0x4000000


# Risk Type Constants
class RiskTypes:
    """Risk type identifiers."""
    # User risks
    USER_PASSWORD_NEVER_EXPIRES = 'user_password_never_expires'
    PASSWORD_NOT_REQUIRED = 'password_not_required'
    KERBEROS_PREAUTH_DISABLED = 'kerberos_preauth_disabled'
    USER_WITH_SPN = 'user_with_spn'
    ADMIN_COUNT_SET = 'admin_count_set'
    INACTIVE_PRIVILEGED_ACCOUNT = 'inactive_privileged_account'
    DISABLED_USER_ACCOUNT = 'disabled_user_account'
    LOCKED_USER_ACCOUNT = 'locked_user_account'
    SERVICE_ACCOUNT_PASSWORD_NEVER_EXPIRES = 'service_account_password_never_expires'
    RECENTLY_CREATED_ACCOUNT = 'recently_created_account'
    RECENTLY_MODIFIED_GROUP_MEMBERSHIP = 'recently_modified_group_membership'
    
    # Kerberos & Delegation risks
    UNCONSTRAINED_DELEGATION = 'unconstrained_delegation'
    UNCONSTRAINED_DELEGATION_USER = 'unconstrained_delegation_user'
    CONSTRAINED_DELEGATION = 'constrained_delegation'
    COMPUTER_UNCONSTRAINED_DELEGATION = 'computer_unconstrained_delegation'
    COMPUTER_BROAD_CONSTRAINED_DELEGATION = 'computer_broad_constrained_delegation'
    DUPLICATE_SPN = 'duplicate_spn'
    
    # Computer risks
    EOL_OPERATING_SYSTEM = 'eol_operating_system'
    LEGACY_OPERATING_SYSTEM = 'legacy_operating_system'
    INACTIVE_COMPUTER = 'inactive_computer'
    NEVER_USED_COMPUTER = 'never_used_computer'
    COMPUTER_ACCOUNT_EXPIRED = 'computer_account_expired'
    
    # Group risks
    TOO_MANY_DOMAIN_ADMINS = 'too_many_domain_admins'
    NESTED_ADMIN_GROUP = 'nested_admin_group'
    OPERATORS_GROUP_MEMBERS = 'operators_group_members'
    EMPTY_GROUP = 'empty_group'
    DEEPLY_NESTED_GROUP = 'deeply_nested_group'
    
    # Privilege escalation
    PRIVILEGE_ESCALATION_PATH = 'privilege_escalation_path'
    DELEGATION_PRIVILEGE_ESCALATION = 'delegation_privilege_escalation'
    SPN_PRIVILEGE_ESCALATION = 'spn_privilege_escalation'
    COMPUTER_DELEGATION_PRIVILEGE_PATH = 'computer_delegation_privilege_path'
    
    # ACL risks
    ACL_GENERIC_ALL = 'acl_generic_all'
    ACL_WRITE_DACL = 'acl_write_dacl'
    ACL_WRITE_OWNER = 'acl_write_owner'
    ACL_GENERIC_WRITE = 'acl_generic_write'
    ACL_WRITE_PROPERTY = 'acl_write_property'
    ACL_DCSYNC = 'acl_dcsync'
    ACL_FORCE_CHANGE_PASSWORD = 'acl_force_change_password'
    ACL_WRITE_SERVICE_PRINCIPAL_NAME = 'acl_write_service_principal_name'
    ACL_WRITE_USER_ACCOUNT_CONTROL = 'acl_write_user_account_control'
    ACL_WRITE_MEMBER = 'acl_write_member'
    ACL_DS_REPLICATION_GET_CHANGES = 'acl_ds_replication_get_changes'
    ACL_DS_REPLICATION_GET_CHANGES_ALL = 'acl_ds_replication_get_changes_all'
    ACL_DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET = 'acl_ds_replication_get_changes_in_filtered_set'
    ACL_ALL_EXTENDED_RIGHTS = 'acl_all_extended_rights'
    DCSYNC_RIGHTS = 'dcsync_rights'
    SHADOW_ADMIN = 'shadow_admin'
    ACL_INHERITANCE_RISK = 'acl_inheritance_risk'
    ACL_PRIVILEGE_ESCALATION_PATH = 'acl_privilege_escalation_path'
    
    # Kerberoasting/AS-REP Roasting
    KERBEROASTING_TARGET = 'kerberoasting_target'
    ASREP_ROASTING_TARGET = 'asrep_roasting_target'
    
    # Service account risks
    SERVICE_ACCOUNT_HIGH_PRIVILEGE = 'service_account_high_privilege'
    SERVICE_ACCOUNT_WITHOUT_MSA = 'service_account_without_msa'
    
    # GPO risks
    GPO_MODIFICATION_RIGHTS = 'gpo_modification_rights'
    GPO_LINKED_TO_PRIVILEGED_OU = 'gpo_linked_to_privileged_ou'
    
    # Policy risks
    PASSWORD_POLICY_WEAK = 'password_policy_weak'
    
    # Trust risks
    TRUST_RELATIONSHIP_RISK = 'trust_relationship_risk'
    
    # GPP risks
    GPP_PASSWORD_FOUND = 'gpp_password_found'
    
    # LAPS risks
    LAPS_NOT_CONFIGURED = 'laps_not_configured'
    LAPS_ACCESS_ANALYSIS = 'laps_access_analysis'
    
    # Vulnerability risks
    ZEROLOGON_VULNERABLE = 'zerologon_vulnerable'
    PRINTNIGHTMARE_VULNERABLE = 'printnightmare_vulnerable'
    PETITPOTAM_VULNERABLE = 'petitpotam_vulnerable'
    SHADOW_CREDENTIALS = 'shadow_credentials'
    KEY_CREDENTIAL_LINK_PRESENT = 'key_credential_link_present'
    NOPAC_VULNERABLE = 'nopac_vulnerable'
    LDAP_SIGNING_DISABLED = 'ldap_signing_disabled'
    NTLM_RESTRICTION_WEAK = 'ntlm_restriction_weak'
    SMB_SIGNING_DISABLED = 'smb_signing_disabled'
    
    # Certificate risks
    CERTIFICATE_SERVICES_DETECTED = 'certificate_services_detected'
    CERTIFICATE_ESC1 = 'certificate_esc1'
    CERTIFICATE_ESC2 = 'certificate_esc2'
    CERTIFICATE_ESC3 = 'certificate_esc3'
    CERTIFICATE_ESC4 = 'certificate_esc4'
    CERTIFICATE_ESC6 = 'certificate_esc6'
    CERTIFICATE_ESC8 = 'certificate_esc8'

    # Extended LDAP security risks
    RBCD_DELEGATION = 'rbcd_delegation'
    SID_HISTORY_PRESENT = 'sid_history_present'
    FOREIGN_SECURITY_PRINCIPAL = 'foreign_security_principal'
    FINE_GRAINED_PASSWORD_POLICY = 'fine_grained_password_policy'
    BITLOCKER_RECOVERY_IN_AD = 'bitlocker_recovery_in_ad'
    ADMINSDHOLDER_ANALYSIS = 'adminsdholder_analysis'
    OU_DELEGATION_RISK = 'ou_delegation_risk'
    OU_GPO_INHERITANCE_BLOCKED = 'ou_gpo_inheritance_blocked'
    AD_RECYCLE_BIN_ENABLED = 'ad_recycle_bin_enabled'
    AD_RECYCLE_BIN_DELETED_OBJECTS = 'ad_recycle_bin_deleted_objects'
    PRINTER_OBJECT_RISK = 'printer_object_risk'
    EXCHANGE_OBJECTS_FOUND = 'exchange_objects_found'
    DNS_ZONE_FOUND = 'dns_zone_found'

    # Machine Account Quota risks
    MACHINE_ACCOUNT_QUOTA_HIGH = 'machine_account_quota_high'

    # KRBTGT health risks
    KRBTGT_PASSWORD_AGE = 'krbtgt_password_age'
    KRBTGT_WEAK_ENCRYPTION = 'krbtgt_weak_encryption'

    # Stale objects risks
    STALE_INACTIVE_ACCOUNT = 'stale_inactive_account'
    STALE_ANCIENT_PASSWORD = 'stale_ancient_password'
    STALE_DESCRIPTION_CREDENTIAL = 'stale_description_credential'
    STALE_COMPUTER_ACCOUNT = 'stale_computer_account'
    STALE_ORPHAN_SID = 'stale_orphan_sid'

    # Golden gMSA risks
    GOLDEN_GMSA_ROOT_KEY = 'golden_gmsa_root_key'
    GOLDEN_GMSA_EXCESSIVE_READERS = 'golden_gmsa_excessive_readers'

    # gMSA analyzer risks
    GMSA_MISCONFIGURATION = 'gmsa_misconfiguration'
    GMSA_LEGACY_SERVICE_ACCOUNT = 'gmsa_legacy_service_account'

    # Password spray risk
    PASSWORD_SPRAY_RISK = 'password_spray_risk'
    PASSWORD_SPRAY_NO_LOCKOUT = 'password_spray_no_lockout'

    # Backup / sensitive operator risks
    BACKUP_OPERATOR_RISK = 'backup_operator_risk'
    SENSITIVE_OPERATOR_RISK = 'sensitive_operator_risk'

    # Coercion attack risks
    COERCION_SPOOLSAMPLE = 'coercion_spoolsample'
    COERCION_DFSCOERCE = 'coercion_dfscoerce'
    COERCION_WEBCLIENT = 'coercion_webclient'

    # Extended AD CS risks (ESC5-14)
    CERTIFICATE_ESC5 = 'certificate_esc5'
    CERTIFICATE_ESC7 = 'certificate_esc7'
    CERTIFICATE_ESC9 = 'certificate_esc9'
    CERTIFICATE_ESC10 = 'certificate_esc10'
    CERTIFICATE_ESC11 = 'certificate_esc11'
    CERTIFICATE_ESC13 = 'certificate_esc13'
    CERTIFICATE_ESC14 = 'certificate_esc14'
    CERTIFICATE_CERTIFRIED = 'certificate_certifried'

    # Lateral movement risks
    LATERAL_MOVEMENT_UNRESTRICTED = 'lateral_movement_unrestricted'
    LATERAL_MOVEMENT_TIER_VIOLATION = 'lateral_movement_tier_violation'
    LATERAL_MOVEMENT_RDP_EXPOSURE = 'lateral_movement_rdp_exposure'

    # Honeypot / deception risks
    HONEYPOT_CANDIDATE = 'honeypot_candidate'
    HONEYPOT_RECOMMENDATION = 'honeypot_recommendation'

    # Audit policy risks
    AUDIT_POLICY_INSUFFICIENT = 'audit_policy_insufficient'
    AUDIT_SACL_MISSING = 'audit_sacl_missing'

    # Replication metadata risks
    REPLICATION_SUSPICIOUS_CHANGE = 'replication_suspicious_change'
    REPLICATION_TOMBSTONE_RISK = 'replication_tombstone_risk'


# Privileged Groups
PRIVILEGED_GROUPS = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Account Operators',
    'Backup Operators',
    'Server Operators',
    'Print Operators',
    'Administrators',
    'Domain Controllers',
    'Replicator',
    'DnsAdmins',
    'Group Policy Creator Owners'
]


# Severity Levels
class Severity:
    """Risk severity levels."""
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


# MITRE ATT&CK Techniques (commonly used)
class MITRETechniques:
    """MITRE ATT&CK technique IDs."""
    VALID_ACCOUNTS = 'T1078'
    VALID_ACCOUNTS_DOMAIN = 'T1078.002'
    STEAL_FORGE_KERBEROS_GOLDEN = 'T1558.001'
    STEAL_FORGE_KERBEROS_SILVER = 'T1558.002'
    STEAL_FORGE_KERBEROS_KERBEROASTING = 'T1558.003'
    STEAL_FORGE_KERBEROS_DCSYNC = 'T1003.006'
    EXPLOITATION_PRIVILEGE_ESCALATION = 'T1068'
    DCSYNC = 'T1003.006'
    PASS_THE_HASH = 'T1550.002'
    PASS_THE_TICKET = 'T1550.003'
    LATERAL_MOVEMENT = 'TA0008'
    PRIVILEGE_ESCALATION = 'TA0004'
    UNSECURED_CREDENTIALS = 'T1552'
    EXPLOIT_PUBLIC_FACING_APPLICATION = 'T1190'


# Time Thresholds (in days)
class TimeThresholds:
    """Time-based thresholds for analysis."""
    INACTIVE_ACCOUNT_THRESHOLD = 90
    RECENTLY_CREATED_THRESHOLD = 30
    RECENTLY_MODIFIED_THRESHOLD = 30
    RECENTLY_CREATED_10_DAYS = 10
    RECENTLY_CREATED_60_DAYS = 60
    RECENTLY_CREATED_90_DAYS = 90
    INACTIVE_COMPUTER_THRESHOLD = 90
    NEVER_USED_THRESHOLD = 365


# Service Account Patterns
class ServiceAccountPatterns:
    """Patterns to identify service accounts."""
    PREFIXES = ['SVC_', 'SRV_', 'SERVICE_']
    KEYWORDS = ['SERVICE']


# Domain Admin Thresholds
class DomainAdminThresholds:
    """Thresholds for domain admin analysis."""
    MAX_DOMAIN_ADMINS = 3
    WARNING_DOMAIN_ADMINS = 5


# Risk Score Thresholds
class RiskScoreThresholds:
    """Thresholds for risk scoring."""
    LOW_MAX = 20
    MEDIUM_MAX = 40
    HIGH_MAX = 70
    CRITICAL_MIN = 71


# LDAP Configuration Constants
class LDAPConstants:
    """LDAP-related constants."""
    MAX_PAGE_SIZE = 100000  # Increased from 1000 to allow larger page sizes
    DEFAULT_TIMEOUT = 30
    MAX_TIMEOUT = 300
    DEFAULT_RETRY_DELAY = 2.0
    DEFAULT_MAX_RETRIES = 3
    DEFAULT_PORT = 389
    DEFAULT_SSL_PORT = 636


# Developer information (used in HTML report footer)
# Keys: name, email, linkedin, github
DEVELOPER_INFO = {
    "name": "Cuma KURT",
    "email": "cumakurt@gmail.com",
    "linkedin": "https://www.linkedin.com/in/cuma-kurt-34414917/",
    "github": "https://github.com/cumakurt/AtilKurt",
}

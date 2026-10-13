"""Domain Admin takeover map.

Synthesizes every registered finding into pentest-oriented Domain Admin
(and Domain Admin-equivalent) paths: why the path works, which scan evidence
supports it, the logical stages, a detailed PoC roadmap, usable commands,
and how to break it.
"""

from __future__ import annotations

import logging
from typing import Any
from core.finding_evidence import is_disproved, requires_takeover_validation as requires_validation

from analysis.assessment_da_paths import (
    build_assessment_account_view,
    build_nonadmin_starter_view,
    evidence_options,
)
from analysis.domain_admin_takeover_playbooks import domain_to_dn, fill_playbook_fields, playbook_for
from analysis.takeover_evidence import evidence_dossier
from core.constants import MITRETechniques, Severity

logger = logging.getLogger(__name__)

SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

# Catalog of Domain Admin (or DA-equivalent) techniques a penetration tester
# reviews. Each entry is matched against scan findings.
DA_PATH_CATALOG: list[dict[str, Any]] = [
    {
        "id": "dcsync",
        "name": "DCSync / directory replication rights",
        "category": "credential_access",
        "starting_access": "A principal that already has, or can obtain, DS-Replication-Get-Changes / Get-Changes-All.",
        "da_equivalent": True,
        "severity_if_open": Severity.CRITICAL,
        "mitre": MITRETechniques.DCSYNC,
        "why_da": (
            "Replication rights let a principal request password hashes for any account, "
            "including KRBTGT and Domain Admins. That is Domain Admin equivalent without "
            "ever joining the Domain Admins group."
        ),
        "match": {"prefixes": ("dcsync", "acl_dcsync", "acl_ds_replication")},
        "stages": [
            {
                "title": "Confirm replication trustees",
                "why": "Only a small set of default security principals should hold these extended rights.",
                "action": "Review every non-DC, non-built-in trustee with Get-Changes / Get-Changes-All on the domain naming context.",
            },
            {
                "title": "Treat the trustee as DA-equivalent",
                "why": "A stolen or coerced session of that trustee can request KRBTGT and privileged hashes.",
                "action": "Assume compromise of that account equals domain takeover until the right is removed.",
            },
            {
                "title": "Remove and monitor",
                "why": "Lingering replication ACEs are the most common ‘shadow DA’ condition.",
                "action": "Strip the ACE, rotate KRBTGT twice, and alert on 4662 replication from unexpected sources.",
            },
        ],
        "break_path": [
            "Remove DS-Replication-Get-Changes-All from every account that is not a DC computer account or a documented Entra Connect gMSA.",
            "Rotate KRBTGT twice after any unauthorized replication right is found.",
        ],
        "detection": "Windows 4662 with replication control access, 4661, and unusual LDAP/DRSUAPI from non-DC hosts.",
    },
    {
        "id": "kerberoasting",
        "name": "Kerberoasting of privileged or weak service accounts",
        "category": "kerberos",
        "starting_access": "Any authenticated domain user (TGS-REQ is a normal Kerberos operation).",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.STEAL_FORGE_KERBEROS_KERBEROASTING,
        "why_da": (
            "Service tickets are encrypted with the service account secret. If that account is a Domain Admin, "
            "is nested into a privileged group, or can log on to a DC/admin workstation, recovering the secret "
            "is a Domain Admin path."
        ),
        "match": {"types": ("kerberoasting_target", "user_with_spn"), "prefixes": ("kerberoast",)},
        "stages": [
            {
                "title": "Inventory SPNs on user accounts",
                "why": "User accounts with SPNs are the Kerberoasting target set; computer accounts are much harder to crack.",
                "action": "Prioritize enabled user SPNs with old passwords, RC4, and privileged group membership.",
            },
            {
                "title": "Recover the account secret",
                "why": "Offline cracking does not lock the account and is invisible to simple logon monitoring.",
                "action": "Treat any crackable privileged SPN as an active DA path until the password is rotated and the SPN is removed or moved to a gMSA.",
            },
            {
                "title": "Use the identity toward DA",
                "why": "The recovered account may already be DA, or it may have logon rights, GPO, or ACL edges to DA.",
                "action": "Map the recovered account’s groups, constrained delegation, and object ACLs before declaring the path closed.",
            },
        ],
        "break_path": [
            "Move services to gMSA/dMSA with AES-only encryption.",
            "Remove SPNs from privileged users; enforce long, random passwords where a user SPN must remain.",
        ],
        "detection": "Unusual TGS-REQ volume (4769) for high-value SPNs, especially RC4 etype 0x17.",
    },
    {
        "id": "asrep",
        "name": "AS-REP roasting of pre-authentication-disabled accounts",
        "category": "kerberos",
        "starting_access": "Network access to a KDC; no valid domain credentials required for the AS-REQ.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.STEAL_FORGE_KERBEROS_KERBEROASTING,
        "why_da": (
            "DONT_REQUIRE_PREAUTH lets anyone request an encrypted TGT for that account. If the account is "
            "privileged, or its password is reused on a privileged identity, this becomes a Domain Admin path "
            "from an unauthenticated starting position."
        ),
        "match": {"types": ("asrep_roasting_target", "kerberos_preauth_disabled"), "prefixes": ("asrep",)},
        "stages": [
            {
                "title": "Find DONT_REQUIRE_PREAUTH accounts",
                "why": "This flag is rarely required on modern systems and is a classic high-signal finding.",
                "action": "Enumerate enabled users with the pre-auth flag cleared, especially adminCount=1.",
            },
            {
                "title": "Recover the secret offline",
                "why": "The AS-REP is encrypted to the account password and can be attacked without triggering lockout.",
                "action": "Treat a recovered privileged AS-REP account as DA-equivalent until the flag is cleared and the password rotated.",
            },
        ],
        "break_path": [
            "Clear DONT_REQUIRE_PREAUTH on every account.",
            "Rotate affected passwords and place privileged users in Protected Users.",
        ],
        "detection": "4768 with Pre-Authentication Type 0 from unexpected sources.",
    },
    {
        "id": "unconstrained_delegation",
        "name": "Unconstrained Kerberos delegation",
        "category": "delegation",
        "starting_access": "Compromise of a host or account trusted for unconstrained delegation, plus a way to coerce or wait for a privileged TGT.",
        "da_equivalent": True,
        "severity_if_open": Severity.CRITICAL,
        "mitre": MITRETechniques.STEAL_FORGE_KERBEROS_SILVER,
        "why_da": (
            "Unconstrained delegation stores the user’s TGT in memory when they authenticate to the delegate. "
            "If a Domain Admin (or KRBTGT via a DC) can be made to authenticate, that TGT is Domain Admin."
        ),
        "match": {
            "types": (
                "unconstrained_delegation",
                "unconstrained_delegation_user",
                "computer_unconstrained_delegation",
            ),
            "contains": ("unconstrained_delegation",),
        },
        "stages": [
            {
                "title": "Identify non-DC unconstrained delegates",
                "why": "Domain Controllers have the flag by design; any other host is an extra TGT cache.",
                "action": "List TRUSTED_FOR_DELEGATION computers/users that are not domain controllers.",
            },
            {
                "title": "Obtain a privileged TGT on that host",
                "why": "Print spooler, other coercion, or an admin browsing a share can drop a DA TGT into memory.",
                "action": "Assume any unconstrained member server that privileged users touch is a DA landing zone.",
            },
        ],
        "break_path": [
            "Disable unconstrained delegation everywhere except DCs.",
            "Move remaining needs to constrained or resource-based constrained delegation.",
            "Add privileged users to Protected Users so their TGTs cannot be delegated.",
        ],
        "detection": "4769 with forwarded TGT options; 4624 on unconstrained hosts from DA accounts.",
    },
    {
        "id": "constrained_delegation",
        "name": "Constrained delegation / S4U to a privileged service",
        "category": "delegation",
        "starting_access": "Compromise of an account trusted for constrained delegation to a DC or other Tier 0 SPN.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.STEAL_FORGE_KERBEROS_SILVER,
        "why_da": (
            "Constrained delegation lets the trusted account request a service ticket as another user to allowed SPNs. "
            "If those SPNs include a domain controller, LDAP, CIFS on a DC, or another Tier 0 service, the result is "
            "Domain Admin equivalent impersonation."
        ),
        "match": {
            "types": (
                "constrained_delegation",
                "computer_broad_constrained_delegation",
                "privileged_account_delegatable",
            ),
            "prefixes": ("constrained_delegation", "computer_broad_constrained"),
        },
        "stages": [
            {
                "title": "Inventory msDS-AllowedToDelegateTo on non-DCs",
                "why": "The allowed-to-delegate list is the blast radius of a stolen constrained-delegation account.",
                "action": "Flag any host whose allowed SPNs include ldap/, cifs/, or krbtgt/ on a domain controller.",
            },
            {
                "title": "Treat the trusted account as a DA stepping stone",
                "why": "S4U2Self plus S4U2Proxy produces a usable service ticket as a privileged user.",
                "action": "Assume compromise of that account equals control of every listed SPN until the grant is removed.",
            },
        ],
        "break_path": [
            "Remove constrained delegation to DC and other Tier 0 SPNs.",
            "Use resource-based constrained delegation with a documented owner instead of unconstrained-style broad grants.",
            "Place privileged users in Protected Users so they cannot be delegated.",
        ],
        "detection": "4769 S4U (Service-for-User) traffic toward DC SPNs from unexpected intermediates.",
    },
    {
        "id": "rbcd",
        "name": "Resource-based constrained delegation (RBCD)",
        "category": "delegation",
        "starting_access": "Write access to msDS-AllowedToActOnBehalfOfOtherIdentity on a high-value computer, or a computer account the attacker already controls.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.STEAL_FORGE_KERBEROS_SILVER,
        "why_da": (
            "RBCD lets a chosen account impersonate users to a target service. Pointed at a DC or a privileged "
            "server, it yields Domain Admin-equivalent service tickets."
        ),
        "match": {"types": ("rbcd_delegation",), "prefixes": ("rbcd",)},
        "stages": [
            {
                "title": "Find writable computer objects or existing RBCD grants",
                "why": "MachineAccountQuota or GenericWrite on a computer is enough to set the RBCD attribute.",
                "action": "Review msDS-AllowedToActOnBehalfOfOtherIdentity on DCs, PKI, ADFS, and admin workstations.",
            },
            {
                "title": "Impersonate a privileged user to that resource",
                "why": "S4U2Self/S4U2Proxy then produces a usable service ticket as that user.",
                "action": "Treat any RBCD grant toward a DC or DA workstation as an open DA path.",
            },
        ],
        "break_path": [
            "Set MachineAccountQuota to 0.",
            "Audit and clear unexpected msDS-AllowedToActOnBehalfOfOtherIdentity values.",
            "Remove GenericWrite/GenericAll on computer objects from Authenticated Users and similar.",
        ],
        "detection": "Changes to msDS-AllowedToActOnBehalfOfOtherIdentity (5136) and unusual S4U activity.",
    },
    {
        "id": "shadow_credentials",
        "name": "Shadow credentials (Key Credential Link)",
        "category": "credential_access",
        "starting_access": "Write access to msDS-KeyCredentialLink on a user or computer, including GenericWrite/GenericAll.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
        "why_da": (
            "A new key credential lets an attacker PKINIT-authenticate as that object without knowing its password. "
            "Written to a Domain Admin, a DC computer account, or KRBTGT-adjacent identities, this is domain takeover."
        ),
        "match": {
            "types": ("shadow_credentials", "key_credential_link_present"),
            "contains": ("shadow_cred", "key_credential"),
        },
        "stages": [
            {
                "title": "Identify who can write msDS-KeyCredentialLink",
                "why": "Many helpdesk or computer-management ACLs accidentally include this attribute.",
                "action": "Check GenericWrite/WriteProperty on privileged users, DCs, and the AdminSDHolder template.",
            },
            {
                "title": "Authenticate as the target via PKINIT",
                "why": "The added device key is a valid credential until it is removed and the account is remediated.",
                "action": "Treat unexplained KeyCredentialLink values on privileged objects as confirmed persistence.",
            },
        ],
        "break_path": [
            "Remove unexpected msDS-KeyCredentialLink values on privileged objects.",
            "Restrict write access to that attribute to Identity/PAM systems only.",
        ],
        "detection": "LDAP 5136 on msDS-KeyCredentialLink for adminCount=1 objects; unexpected PKINIT 4768.",
    },
    {
        "id": "adcs",
        "name": "AD CS template / CA abuse (ESC1–ESC16)",
        "category": "adcs",
        "starting_access": "Enrollment rights on a vulnerable template, or NTLM coercion to a web enrollment endpoint, depending on the ESC.",
        "da_equivalent": True,
        "severity_if_open": Severity.CRITICAL,
        "mitre": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
        "why_da": (
            "A certificate that permits domain authentication as an arbitrary or privileged user is Domain Admin "
            "equivalent. ESC1/ESC6/ESC8/ESC9/ESC15 are the most common DA-class issues."
        ),
        "match": {"prefixes": ("certificate_",), "contains": ("certifried",)},
        "stages": [
            {
                "title": "Identify dangerous templates and CA flags",
                "why": "Enrollee-supplied SAN plus Client Authentication EKU is a classic ESC1 DA path.",
                "action": "Review templates that allow SAN, lack manager approval, and grant enroll to Domain Users/computers.",
            },
            {
                "title": "Obtain a certificate as a privileged identity",
                "why": "Schannel or PKINIT then authenticates that identity to LDAP/CIFS.",
                "action": "Any enrollable template that can name a Domain Admin is an open DA path.",
            },
        ],
        "break_path": [
            "Disable unused templates; require manager approval; remove enrollee-supplied SAN.",
            "Require LDAP channel binding; disable HTTP web enrollment or enforce Kerberos-only.",
            "Upgrade schema v1 templates (ESC15) and disable EDITF_ATTRIBUTESUBJECTALTNAME2.",
        ],
        "detection": "Certificate issuance for privileged UPN/SAN values; CA audit events 4886/4887.",
    },
    {
        "id": "gpo_acl",
        "name": "GPO modification on Domain Controllers or privileged OUs",
        "category": "acl",
        "starting_access": "WriteDACL/WriteOwner/GenericWrite on a GPO linked to Domain Controllers, Domain Admins, or a Tier 0 OU.",
        "da_equivalent": True,
        "severity_if_open": Severity.CRITICAL,
        "mitre": MITRETechniques.PRIVILEGE_ESCALATION,
        "why_da": (
            "Immediate scheduled tasks, logon scripts, or local-admin GPP deployed to DCs execute as SYSTEM "
            "on a Domain Controller — that is Domain Admin."
        ),
        "match": {"prefixes": ("gpo_",), "contains": ("gpo_abuse", "gpo_modification")},
        "stages": [
            {
                "title": "Find GPOs linked to Tier 0",
                "why": "Default Domain Controllers Policy and any GPO on OU=Domain Controllers are the highest value.",
                "action": "List trustees with Edit settings, Delete, or Modify security on those GPOs.",
            },
            {
                "title": "Push a privileged logon or service",
                "why": "The next gpupdate on a DC runs attacker-controlled code as SYSTEM.",
                "action": "Treat any non-admin editor of a DC-linked GPO as an open DA path.",
            },
        ],
        "break_path": [
            "Restrict GPO edit rights to a tiny Tier 0 group.",
            "Enable GPO auditing (5136/5137) and SYSVOL integrity monitoring.",
        ],
        "detection": "5136 on GPC objects; unexpected SYSVOL file writes; 4688 on DCs shortly after GPO version change.",
    },
    {
        "id": "gpp_passwords",
        "name": "GPP / SYSVOL stored passwords",
        "category": "credential_access",
        "starting_access": "Any authenticated user who can read SYSVOL (default).",
        "da_equivalent": True,
        "severity_if_open": Severity.CRITICAL,
        "mitre": MITRETechniques.UNSECURED_CREDENTIALS,
        "why_da": (
            "cpassword in Groups.xml is recoverable with a published AES key. If the stored account is "
            "a domain admin, local admin of a DC, or a widely reused privileged password, this is a DA path "
            "from a standard user."
        ),
        "match": {"prefixes": ("gpp_",), "contains": ("gpp_password",)},
        "stages": [
            {
                "title": "Read SYSVOL GPP files",
                "why": "Authenticated Users can read SYSVOL in almost every domain.",
                "action": "Treat any decrypted GPP credential as live until rotated everywhere it was used.",
            },
            {
                "title": "Reuse the recovered identity",
                "why": "These passwords are often domain-join, local-admin, or service accounts with DC logon.",
                "action": "Map the recovered account to privileged groups and inbound admin rights on DCs.",
            },
        ],
        "break_path": [
            "Delete GPP credential XML from SYSVOL and all GPO backups.",
            "Rotate every recovered password; never store secrets in GPO.",
        ],
        "detection": "Access to Groups.xml/Services.xml from unusual workstations; leftover cpassword strings in SYSVOL.",
    },
    {
        "id": "acl_generic_all",
        "name": "Dangerous ACL on privileged users, groups, or AdminSDHolder",
        "category": "acl",
        "starting_access": "Control of a trustee that has GenericAll, WriteDACL, WriteOwner, or ForceChangePassword on a DA-class object.",
        "da_equivalent": True,
        "severity_if_open": Severity.CRITICAL,
        "mitre": MITRETechniques.PRIVILEGE_ESCALATION,
        "why_da": (
            "GenericAll or WriteDACL on Domain Admins, AdminSDHolder, or a DA user lets an attacker add themselves, "
            "reset a password, or plant a persistent ACE — all Domain Admin outcomes."
        ),
        "match": {
            "types": (
                "acl_generic_all",
                "acl_write_dacl",
                "acl_write_owner",
                "acl_force_change_password",
                "shadow_admin",
                "acl_privilege_escalation_path",
                "adminsdholder_analysis",
            ),
            "prefixes": ("acl_", "shadow_admin"),
            "exclude_prefixes": ("acl_dcsync", "acl_ds_replication"),
        },
        "stages": [
            {
                "title": "Graph the control edges into Tier 0",
                "why": "BloodHound-style ACL edges are how most internal tests reach DA without a single CVE.",
                "action": "Follow GenericAll/WriteDACL/WriteOwner/AllExtendedRights from the current identity to Domain Admins.",
            },
            {
                "title": "Take the object",
                "why": "Password reset, group add, or DACL rewrite is enough.",
                "action": "Any non-admin trustee with those rights on AdminSDHolder or Domain Admins is an open DA path.",
            },
        ],
        "break_path": [
            "Reset AdminSDHolder to the Microsoft default DACL.",
            "Remove GenericAll/WriteDACL granted to users, computers, and broad groups.",
            "Run SDProp and review adminCount=1 orphans.",
        ],
        "detection": "4742/4738 on privileged users from unexpected callers; 5136 on AdminSDHolder.",
    },
    {
        "id": "escalation_graph",
        "name": "Chained privilege-escalation graph into Domain Admins",
        "category": "attack_path",
        "starting_access": "Any identity that sits at the start of a scored escalation path toward Domain Admins.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.PRIVILEGE_ESCALATION,
        "why_da": (
            "Individual ACL, delegation, or SPN findings are often only one hop. A multi-hop graph that ends at "
            "Domain Admins, Enterprise Admins, or a DC is a complete takeover path even when no single hop is DA-equivalent."
        ),
        "match": {
            "types": (
                "privilege_escalation_path",
                "delegation_privilege_escalation",
                "spn_privilege_escalation",
                "computer_delegation_privilege_path",
                "nested_admin_group",
            ),
            "contains": ("privilege_escalation_path", "privilege_escalation"),
            "exclude_prefixes": ("acl_",),
        },
        "stages": [
            {
                "title": "Read the shortest path to Domain Admins",
                "why": "Testers start from the cheapest hop (often GenericWrite or an SPN) rather than from DA membership.",
                "action": "Record every hop: who controls whom, and which right turns the next object into a DA stepping stone.",
            },
            {
                "title": "Break the cheapest hop first",
                "why": "Removing one edge can collapse several DA paths at once.",
                "action": "Prefer fixing the first non-admin hop over adding more Domain Admins monitoring.",
            },
        ],
        "break_path": [
            "Remove the first control edge that a non-admin holds toward a privileged object.",
            "Flatten unnecessary nested admin groups and reduce Domain Admins membership.",
        ],
        "detection": "Correlate 4728/4732 group changes with 5136 ACL writes along the same object chain.",
    },
    {
        "id": "ops_groups",
        "name": "Built-in operator groups (Backup, Server, Account, Print, DnsAdmins)",
        "category": "operations_groups",
        "starting_access": "Membership in Backup Operators, Server Operators, Account Operators, Print Operators, or DnsAdmins.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.PRIVILEGE_ESCALATION,
        "why_da": (
            "These groups have implicit DC-impacting rights: SeBackupPrivilege (NTDS.dit), service/driver load, "
            "account manipulation, or DNS DLL load. Each is a documented Domain Admin technique."
        ),
        "match": {
            "prefixes": ("backup_operator", "sensitive_operator"),
            "contains": ("dnsadmin", "operators_group"),
        },
        "stages": [
            {
                "title": "Enumerate operator group members",
                "why": "These groups should be empty in a hardened domain.",
                "action": "Any enabled member is a DA-class identity even if they are not in Domain Admins.",
            },
            {
                "title": "Abuse the implicit right",
                "why": "Backup of NTDS, loading a print driver, or DNS service DLL execution runs as SYSTEM on a DC.",
                "action": "Treat membership itself as the path; do not wait for a second finding.",
            },
        ],
        "break_path": [
            "Empty Backup/Server/Account/Print Operators.",
            "Replace DnsAdmins with least-privilege DNS roles on Windows Server 2022+ or dedicated admin tiers.",
        ],
        "detection": "4728/4732 into operator groups; SeBackupPrivilege use (4672) on DCs by non-DA accounts.",
    },
    {
        "id": "laps",
        "name": "Readable LAPS / Windows LAPS local-admin secrets",
        "category": "credential_access",
        "starting_access": "LDAP read of ms-Mcs-AdmPwd or msLAPS-Password on a Domain Controller or admin workstation.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.UNSECURED_CREDENTIALS,
        "why_da": (
            "Local administrator of a DC or of a jump host used by Domain Admins yields LSASS/NTDS access. "
            "Broad LAPS read ACLs therefore become Domain Admin paths."
        ),
        "match": {"prefixes": ("laps_", "windows_laps")},
        "stages": [
            {
                "title": "See who can read LAPS attributes",
                "why": "Helpdesk groups are often granted domain-wide LAPS read, including DCs.",
                "action": "Exclude Domain Controllers from LAPS read scopes used by helpdesk.",
            },
            {
                "title": "Use the local admin on a Tier 0 host",
                "why": "Local admin on a DC or DA workstation is DA-equivalent.",
                "action": "Any LAPS grant covering DC objects is an open DA path.",
            },
        ],
        "break_path": [
            "Scope LAPS read to the owning support tier; never to Authenticated Users.",
            "Use encrypted Windows LAPS; rotate and restrict msLAPS-Password.",
        ],
        "detection": "LDAP reads of ms-Mcs-AdmPwd / msLAPS-* from unusual callers.",
    },
    {
        "id": "machine_quota",
        "name": "MachineAccountQuota plus a DC/computer write primitive",
        "category": "delegation",
        "starting_access": "Any authenticated user when ms-DS-MachineAccountQuota is greater than 0.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.PRIVILEGE_ESCALATION,
        "why_da": (
            "Creating a computer account gives the attacker a security principal they fully control. Combined "
            "with RBCD, noPac-class issues, or a writable DC object, that principal becomes a DA path."
        ),
        "match": {"prefixes": ("machine_account_quota",), "contains": ("machine_quota",)},
        "stages": [
            {
                "title": "Create or identify a controlled computer account",
                "why": "Quota > 0 is the default and is enough for several modern DA chains.",
                "action": "Set quota to 0 unless a documented join workflow requires it.",
            },
            {
                "title": "Chain into RBCD, noPac, or shadow credentials",
                "why": "The new computer is the attacker-controlled node those techniques need.",
                "action": "If quota is non-zero and any DC has weak ACLs or RBCD, record a DA path.",
            },
        ],
        "break_path": [
            "Set ms-DS-MachineAccountQuota to 0.",
            "Harden computer-object ACLs; patch DCs for CVE-2021-42278/42287.",
        ],
        "detection": "4741 computer creations by non-join accounts; subsequent RBCD attribute writes.",
    },
    {
        "id": "nopac",
        "name": "noPac (CVE-2021-42278 / CVE-2021-42287) with a machine-quota principal",
        "category": "protocol_abuse",
        "starting_access": "Authenticated domain user who can create a computer account, against unpatched domain controllers.",
        "da_equivalent": True,
        "severity_if_open": Severity.CRITICAL,
        "mitre": MITRETechniques.EXPLOITATION_PRIVILEGE_ESCALATION,
        "why_da": (
            "The noPac class of issues lets a controlled computer account impersonate a domain controller by combining "
            "sAMAccountName spoofing with a Kerberos TGT request. Unpatched DCs plus MachineAccountQuota > 0 is a "
            "Domain Admin path from any authenticated user."
        ),
        "match": {"types": ("nopac_vulnerable",), "contains": ("nopac",)},
        "stages": [
            {
                "title": "Confirm DC patch level and machine quota",
                "why": "The chain needs both a create-computer primitive and an unpatched KDC.",
                "action": "Treat unpatched DCs together with quota > 0 as an open DA path even before exploitation.",
            },
            {
                "title": "Assume any authenticated user can request a DC TGT",
                "why": "That TGT is Domain Admin equivalent until DCs are patched and quota is zero.",
                "action": "Patch DCs, then set ms-DS-MachineAccountQuota to 0.",
            },
        ],
        "break_path": [
            "Patch every domain controller for CVE-2021-42278 and CVE-2021-42287.",
            "Set ms-DS-MachineAccountQuota to 0.",
        ],
        "detection": "4741 followed by 4781 (computer rename) and 4768 for a DC-named account from a workstation.",
    },
    {
        "id": "relay_coerce",
        "name": "Authentication coercion plus missing LDAP/SMB signing",
        "category": "protocol_relay",
        "starting_access": "Network position to coerce a DC or privileged host (PetitPotam, PrinterBug, DFS, WebClient).",
        "da_equivalent": True,
        "severity_if_open": Severity.CRITICAL,
        "mitre": MITRETechniques.PASS_THE_HASH,
        "why_da": (
            "If LDAP signing and EPA/channel binding are not required, a coerced DC machine account can be "
            "relayed to LDAP to grant DCSync, RBCD, or shadow credentials — Domain Admin in a few LDAP writes."
        ),
        "match": {
            "types": ("ldap_signing_disabled", "ntlm_restriction_weak", "smb_signing_disabled"),
            "prefixes": ("coercion_", "petitpotam", "printnightmare", "zerologon"),
        },
        "stages": [
            {
                "title": "Confirm signing / channel binding gaps",
                "why": "Relay dies if LDAP signing and EPA are enforced and SMB signing is required.",
                "action": "Treat ‘signing not required’ on DCs as a domain-wide DA enabler.",
            },
            {
                "title": "Coerce a privileged machine account",
                "why": "The DC computer account can write privileged LDAP attributes when signing is off.",
                "action": "Combine spooler/EFS/DFS exposure with the signing gap; that pair is the DA path.",
            },
        ],
        "break_path": [
            "Require LDAP signing and channel binding on all DCs.",
            "Require SMB signing; disable the print spooler on DCs; restrict EFS RPC.",
        ],
        "detection": "NTLM (4624 type 3) from DCs to unexpected hosts; LDAP writes from DC machine accounts.",
    },
    {
        "id": "krbtgt",
        "name": "Stale KRBTGT secret (Golden Ticket window)",
        "category": "persistence_secrets",
        "starting_access": "A previously stolen KRBTGT hash, or a current DCSync path that can still use the old key.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.STEAL_FORGE_KERBEROS_GOLDEN,
        "why_da": (
            "KRBTGT encrypts every TGT. An old KRBTGT password that has not been rotated twice leaves a "
            "Golden Ticket window: forged TGTs for any user, including Domain Admins."
        ),
        "match": {"prefixes": ("krbtgt_",)},
        "stages": [
            {
                "title": "Measure KRBTGT password age and history",
                "why": "Microsoft guidance is a double rotation after any suspected DC compromise.",
                "action": "If pwdLastSet is years old, assume any past DCSync still works.",
            },
            {
                "title": "Forge TGTs until both keys are dead",
                "why": "Kerberos accepts the previous KRBTGT key. One rotation is not enough.",
                "action": "Plan a two-step rotation with a waiting period so both keys change.",
            },
        ],
        "break_path": [
            "Rotate KRBTGT twice with the Microsoft two-phase procedure.",
            "Reset after every DC compromise or unauthorized replication right.",
        ],
        "detection": "Anomalous TGTs (4768/4769) with unusual lifetimes or encryption vs policy.",
    },
    {
        "id": "gmsa_kds",
        "name": "Golden gMSA / readable KDS root key",
        "category": "persistence_secrets",
        "starting_access": "Read access to the KDS root key object for principals that should not manage gMSA.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.UNSECURED_CREDENTIALS,
        "why_da": (
            "Anyone who can read the KDS root key can compute current and future gMSA passwords. "
            "A gMSA used on DCs, AD FS, or Entra Connect is Domain Admin equivalent."
        ),
        "match": {"prefixes": ("golden_gmsa", "gmsa_")},
        "stages": [
            {
                "title": "See who can read msKds-RootKeyData",
                "why": "Default ACLs are broader than most teams expect.",
                "action": "If Domain Users or a helpdesk group can read the key, every gMSA is in scope.",
            },
            {
                "title": "Derive a privileged gMSA secret",
                "why": "gMSA passwords are deterministic from the root key and identity.",
                "action": "Map readable gMSAs to DC services, AD FS, and Connect.",
            },
        ],
        "break_path": [
            "Tighten KDS root-key ACLs to Domain Controllers and a break-glass Tier 0 group.",
            "Rotate gMSAs after ACL reduction.",
        ],
        "detection": "LDAP reads of CN=Master Root Keys under the Configuration partition by unusual callers.",
    },
    {
        "id": "trusts",
        "name": "Trust SID history / SID filter failure",
        "category": "trust_hybrid",
        "starting_access": "Compromise of a trusted domain, or a principal with SID History write.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
        "why_da": (
            "If SID filtering is disabled on a forest trust, extra SIDs in a PAC (including Enterprise Admins "
            "from another forest) are honored. That is a cross-forest Domain Admin path."
        ),
        "match": {"prefixes": ("trust_",), "contains": ("sid_history",)},
        "stages": [
            {
                "title": "Classify each trust",
                "why": "External and forest trusts without SID filtering are the dangerous cases.",
                "action": "Flag bidirectional forest trusts and any trust with TREAT_AS_EXTERNAL / disable SID filter.",
            },
            {
                "title": "Inject or reuse a privileged SID",
                "why": "SID History or ExtraSids then grants the trusted-side DA rights locally.",
                "action": "Compromise of the far side of an unfiltered trust is a local DA path.",
            },
        ],
        "break_path": [
            "Enable SID filtering on all forest trusts; avoid SID History except during tightly controlled migrations.",
            "Prefer selective authentication.",
        ],
        "detection": "Logon PAC SIDs from foreign issuers matching local RID 512/519.",
    },
    {
        "id": "hybrid",
        "name": "Entra Connect, Seamless SSO, or AD FS identity",
        "category": "trust_hybrid",
        "starting_access": "Control of MSOL_/Sync_ Connect account, AZUREADSSOACC$, or the AD FS token-signing key.",
        "da_equivalent": True,
        "severity_if_open": Severity.CRITICAL,
        "mitre": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
        "why_da": (
            "Connect accounts often have DCSync. AZUREADSSOACC decrypts Seamless SSO tickets for any synced user. "
            "AD FS token-signing forges SAML for cloud Global Admin, which in hybrid estates maps back to DA."
        ),
        "match": {"prefixes": ("hybrid_",)},
        "stages": [
            {
                "title": "Identify hybrid control-plane accounts",
                "why": "These objects are Tier 0 even when they are not in Domain Admins.",
                "action": "MSOL_/Sync_/AAD_ membership in DA or replication rights is a confirmed DA path.",
            },
            {
                "title": "Abuse the sync or federation secret",
                "why": "Cloud admin plus password writeback, or SSO silver tickets, recover on-prem DA.",
                "action": "Harden Connect servers and AD FS as Domain Controllers.",
            },
        ],
        "break_path": [
            "Remove Connect from Domain Admins; grant only the documented replication/password rights.",
            "Rotate AZUREADSSOACC; protect AD FS signing keys with HSM; restrict Connect admins to Tier 0.",
        ],
        "detection": "Logons of MSOL_/Sync_ from non-Connect hosts; changes to AZUREADSSOACC password.",
    },
    {
        "id": "rodc",
        "name": "RODC cached privileged secrets",
        "category": "credential_access",
        "starting_access": "Physical or backup access to an RODC, or replication of its krbtgt_###### account.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.OS_CREDENTIAL_DUMP,
        "why_da": (
            "If Domain Admins or other Tier 0 accounts are allowed to cache on an RODC, stealing that RODC "
            "yields those hashes. An RODC KRBTGT also mints TGTs for its revealed set."
        ),
        "match": {"prefixes": ("rodc_",)},
        "stages": [
            {
                "title": "Inspect RevealOnDemand vs NeverReveal",
                "why": "Denied RODC Password Replication Group must include all Tier 0.",
                "action": "Any DA/EA/Schema Admin in the allowed list is an open DA path via RODC theft.",
            },
            {
                "title": "Assume RODC theft",
                "why": "RODCs sit in branch sites with weaker physical control.",
                "action": "Treat cached privileged secrets as already exposed if the site is not Tier 0 equivalent.",
            },
        ],
        "break_path": [
            "Populate Denied RODC Password Replication Group with every Tier 0 identity.",
            "Remove privileged users from Allowed RODC Password Replication Group.",
        ],
        "detection": "Privileged authentication against RODCs; changes to msDS-RevealOnDemandGroup.",
    },
    {
        "id": "dmsa",
        "name": "Delegated MSA predecessor abuse (BadSuccessor)",
        "category": "acl",
        "starting_access": "CreateChild for msDS-DelegatedManagedServiceAccount on any OU, plus write on the predecessor-link attribute.",
        "da_equivalent": True,
        "severity_if_open": Severity.CRITICAL,
        "mitre": MITRETechniques.EXPLOITATION_PRIVILEGE_ESCALATION,
        "why_da": (
            "A dMSA can inherit the identity of the account it supersedes. Linking a Domain Admin as predecessor "
            "makes the dMSA Domain Admin equivalent."
        ),
        "match": {"prefixes": ("dmsa_",)},
        "stages": [
            {
                "title": "See who can create dMSA objects",
                "why": "CreateChild on a regular OU is enough in vulnerable forests.",
                "action": "Restrict dMSA creation to a Tier 0 identity team.",
            },
            {
                "title": "Inspect predecessor links",
                "why": "A link to a privileged account is an active takeover, not a theoretical one.",
                "action": "Delete unexpected msDS-ManagedAccountPrecededByLink values immediately.",
            },
        ],
        "break_path": [
            "Apply Microsoft’s BadSuccessor mitigations; audit dMSA creation (5137) and predecessor writes (5136).",
            "Remove CreateChild for the dMSA class from non-admin groups.",
        ],
        "detection": "Creation of msDS-DelegatedManagedServiceAccount and writes to the predecessor-link attribute.",
    },
    {
        "id": "sccm",
        "name": "SCCM / Configuration Manager site takeover",
        "category": "operations_groups",
        "starting_access": "Control of a site server, a management point, or GenericAll on the System Management container.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.EXPLOITATION_PRIVILEGE_ESCALATION,
        "why_da": (
            "SCCM client push and application deployment run as SYSTEM. Pushing to a Domain Controller or "
            "a DA workstation is a standard Domain Admin finish."
        ),
        "match": {"prefixes": ("sccm_",)},
        "stages": [
            {
                "title": "Identify site servers and the System Management container",
                "why": "Site-server computer accounts often have excessive AD rights.",
                "action": "Treat every primary site server as Tier 0.",
            },
            {
                "title": "Deploy as SYSTEM to a DC or DA workstation",
                "why": "Client push does not require the target to be a client already in many configs.",
                "action": "Disable automatic client push to Domain Controllers.",
            },
        ],
        "break_path": [
            "Tier-0 the site servers; lock System Management ACLs; disable DC client push.",
            "Require HTTPS and PKI for management points.",
        ],
        "detection": "Client-push to DC hostnames; unexpected applications on DCs.",
    },
    {
        "id": "password_spray",
        "name": "Password spray against privileged or widely used passwords",
        "category": "credential_access",
        "starting_access": "Network access to Kerberos/LDAP/NTLM; no valid account required.",
        "da_equivalent": True,
        "severity_if_open": Severity.MEDIUM,
        "mitre": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
        "why_da": (
            "If lockout is disabled or weak, and privileged accounts share seasonal passwords, a spray "
            "hits Domain Admin directly. Even a non-admin hit may unlock Kerberoasting or ACL edges."
        ),
        "match": {"prefixes": ("password_spray", "password_policy", "weak_fine_grained")},
        "stages": [
            {
                "title": "Measure lockout and privileged password hygiene",
                "why": "Lockout threshold 0 is an open spray runway.",
                "action": "Smart-card or phishing-resistant MFA on all privileged users removes this path.",
            },
            {
                "title": "Spray then walk ACL/Kerberos edges",
                "why": "The first valid password is rarely DA; it is usually the first hop.",
                "action": "Combine spray success with the rest of this map rather than treating it in isolation.",
            },
        ],
        "break_path": [
            "Enable lockout with a sane threshold; ban common passwords; require MFA for privileged users.",
            "Use Protected Users and authentication silos for Tier 0.",
        ],
        "detection": "Distributed 4625/4771 across many users from one source.",
    },
    {
        "id": "hidden_primary_group",
        "name": "Hidden privileged primaryGroupID",
        "category": "acl",
        "starting_access": "Compromise of the account whose primary group is Domain Admins (RID 512) or another Tier 0 group.",
        "da_equivalent": True,
        "severity_if_open": Severity.CRITICAL,
        "mitre": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
        "why_da": (
            "primaryGroupID membership does not appear in the member attribute. The account is already a "
            "Domain Admin even though most group reviews miss it."
        ),
        "match": {
            "types": ("hidden_primary_group_privilege", "privileged_computer_account", "builtin_admin_renamed"),
            "prefixes": ("hidden_primary", "privileged_computer"),
        },
        "stages": [
            {
                "title": "Enumerate primaryGroupID 512/518/519",
                "why": "This is the classic ‘hidden DA’ trick.",
                "action": "Reset primary groups to Domain Users / Domain Computers and use visible membership only.",
            },
        ],
        "break_path": [
            "Fix primaryGroupID on every privileged outlier.",
            "Remove computer accounts from Domain Admins and operator groups.",
        ],
        "detection": "LDAP queries for primaryGroupID=512; 4738 primary group changes.",
    },
    {
        "id": "ldap_recon",
        "name": "Anonymous / Pre-Windows 2000 directory enumeration",
        "category": "recon_enabler",
        "starting_access": "Unauthenticated or any domain user, depending on the finding.",
        "da_equivalent": False,
        "severity_if_open": Severity.MEDIUM,
        "mitre": MITRETechniques.VALID_ACCOUNTS,
        "why_da": (
            "This does not grant Domain Admin by itself. It removes the need for credentials to build the "
            "target list (admins, SPNs, computers) that every other path on this map needs."
        ),
        "match": {"prefixes": ("ldap_anonymous", "ldap_prewin2k", "ldap_guest", "ldap_legacy")},
        "stages": [
            {
                "title": "Enumerate without credentials",
                "why": "Pre-Windows 2000 Compatible Access plus anonymous LDAP is the oldest AD recon path.",
                "action": "Close enumeration first so unauthenticated actors cannot even see the DA paths.",
            },
        ],
        "break_path": [
            "Disable anonymous LDAP (dSHeuristics).",
            "Remove Everyone/Authenticated Users from Pre-Windows 2000 Compatible Access.",
            "Disable Guest.",
        ],
        "detection": "Anonymous LDAP binds; 4662 from null sessions.",
    },
    {
        "id": "tier0_graph",
        "name": "Evidence-graph path into Tier-0 / Domain Admins",
        "category": "attack_path",
        "starting_access": "Any non-privileged identity that the membership/ACL/control-plane graph can reach a privileged node from.",
        "da_equivalent": True,
        "severity_if_open": Severity.CRITICAL,
        "mitre": MITRETechniques.PRIVILEGE_ESCALATION,
        "why_da": (
            "Shortest evidenced edges from a low-privilege user, computer, or reader principal into a "
            "privileged group are a complete Domain Admin path even when no single catalog technique fired."
        ),
        "match": {
            "types": ("attack_graph_tier0_path", "attack_graph_chokepoint"),
            "prefixes": ("attack_graph_",),
        },
        "stages": [
            {
                "title": "Walk every distinct route, not only the shortest",
                "why": "Fixing one hop can leave a parallel MemberOf or Enroll edge intact.",
                "action": "Record each hop type (MemberOf, Controls, Enroll) and the chokepoint nodes shared by several routes.",
            },
            {
                "title": "Break the first non-admin edge",
                "why": "The cheapest hop is the one a tester actually uses.",
                "action": "Remove the first control or nested-group edge that a non-admin holds toward Tier-0.",
            },
        ],
        "break_path": [
            "Remove nested group membership and object control that let non-admins reach Domain Admins.",
            "Re-run the evidence graph and confirm every alternative route is gone.",
        ],
        "detection": "Correlate 4728/4732 nested-group changes with 5136 ACL writes along the same chain.",
    },
    {
        "id": "adcs_control",
        "name": "AD CS control-plane ACL (CA, template, NTAuth)",
        "category": "adcs",
        "starting_access": "A non-privileged trustee with write, owner, or DACL control on a PKI object.",
        "da_equivalent": True,
        "severity_if_open": Severity.CRITICAL,
        "mitre": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
        "why_da": (
            "Control of NTAuth, a CA, or a template lets an attacker publish or issue an authentication "
            "certificate for a Domain Admin. That is ESC5-class domain takeover."
        ),
        "match": {
            "types": ("adcs_control_plane_acl", "adcs_ntauth_acl"),
            "prefixes": ("adcs_control", "adcs_ntauth"),
        },
        "stages": [
            {
                "title": "Identify the PKI object the trustee can modify",
                "why": "NTAuth and Enrollment Services are higher impact than a single unused template.",
                "action": "Confirm GenericAll/WriteDACL/WriteOwner on the named CA, template, or NTAuth container.",
            },
            {
                "title": "Issue or trust an authentication certificate",
                "why": "A writable template can be turned into ESC1; NTAuth control trusts a rogue CA.",
                "action": "Treat any non-PKI-admin trustee on those objects as Domain Admin equivalent.",
            },
        ],
        "break_path": [
            "Restore Microsoft default PKI ACLs; only Enterprise Admins / PKI admins should write CA objects.",
            "Audit NTAuthCertificates membership and template enrollment ACLs.",
        ],
        "detection": "5136 on CN=Public Key Services; unexpected certificate issuance for privileged UPNs.",
    },
    {
        "id": "gmsa_readers",
        "name": "gMSA managed-password readers",
        "category": "credential_access",
        "starting_access": "A principal allowed to retrieve a gMSA managed password, especially a Tier-0 gMSA.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
        "why_da": (
            "Anyone who can read a gMSA password can authenticate as that service identity. A Tier-0 gMSA "
            "or a gMSA with DCSync/delegation is Domain Admin equivalent."
        ),
        "match": {
            "types": (
                "gmsa_broad_password_reader",
                "gmsa_privileged_reader_path",
                "gmsa_excessive_effective_readers",
            ),
            "prefixes": ("gmsa_broad", "gmsa_privileged_reader", "gmsa_excessive"),
        },
        "stages": [
            {
                "title": "List effective msDS-GroupMSAMembership readers",
                "why": "Broad groups such as Authenticated Users are a domain-wide credential leak.",
                "action": "Confirm which non-admin principals can retrieve each gMSA password.",
            },
            {
                "title": "Use the gMSA toward DA",
                "why": "The managed identity may already be privileged or host a constrained-delegation hop.",
                "action": "Map the gMSA's groups, SPNs, and replication rights before calling the path closed.",
            },
        ],
        "break_path": [
            "Replace Authenticated Users / Domain Computers readers with the specific hosts that need the gMSA.",
            "Treat Tier-0 gMSA objects as Domain Admins for ACL review.",
        ],
        "detection": "Unusual retrieval of msDS-ManagedPassword; 4662 on gMSA objects from unexpected hosts.",
    },
    {
        "id": "adminsdholder",
        "name": "AdminSDHolder / SDProp protection drift",
        "category": "acl",
        "starting_access": "A dangerous ACE on AdminSDHolder, or a privileged object whose adminCount protection has drifted.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.PRIVILEGE_ESCALATION,
        "why_da": (
            "AdminSDHolder is the template SDProp copies onto every protected admin. A persistent ACE there "
            "re-compromises Domain Admins after every SDProp cycle."
        ),
        "match": {
            "types": (
                "adminsdholder_dangerous_ace",
                "adminsdholder_acl_drift",
                "adminsdholder_orphaned_admincount",
                "adminsdholder_inheritance_enabled",
            ),
            "prefixes": ("adminsdholder_",),
            "exclude_types": ("adminsdholder_analysis",),
        },
        "stages": [
            {
                "title": "Diff AdminSDHolder against the Microsoft default",
                "why": "A single extra ACE is enough for recurring DA takeover.",
                "action": "Remove non-default GenericAll/WriteDACL/WriteOwner trustees from AdminSDHolder.",
            },
            {
                "title": "Fix stale adminCount objects",
                "why": "Orphaned adminCount=1 objects stay protected with a stale DACL and are easy to miss.",
                "action": "Clear stale adminCount or restore the object to the protected set deliberately.",
            },
        ],
        "break_path": [
            "Reset AdminSDHolder to the documented default DACL and run SDProp.",
            "Review every adminCount=1 object that is no longer a member of a protected group.",
        ],
        "detection": "5136 on CN=AdminSDHolder; recurring 4738 on adminCount=1 objects after SDProp.",
    },
    {
        "id": "privileged_hygiene",
        "name": "Privileged-account hygiene that keeps a Domain Admin path open",
        "category": "identity",
        "starting_access": "The privileged account itself (password reuse, stale DA, missing Protected Users).",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
        "why_da": (
            "Disabled Domain Admins with a still-valid secret, nested admin groups, adminCount orphans, "
            "and privileged users outside Protected Users are the identities testers actually steal."
        ),
        "match": {
            "types": (
                "admin_count_set",
                "inactive_privileged_account",
                "disabled_domain_admin",
                "disabled_enterprise_admin",
                "too_many_domain_admins",
                "nested_admin_group",
                "privileged_user_outside_protected_users",
                "privileged_user_without_smartcard",
                "privileged_account_delegatable",
                "auth_policy_privileged_unprotected",
            ),
            "prefixes": (
                "admin_count",
                "inactive_privileged",
                "disabled_domain_admin",
                "disabled_enterprise_admin",
                "too_many_domain",
                "nested_admin",
                "privileged_user",
                "privileged_account_delegatable",
                "auth_policy_privileged",
            ),
        },
        "stages": [
            {
                "title": "Inventory every privileged identity, including disabled",
                "why": "A disabled Domain Admin hash still forges tickets until the password is rotated.",
                "action": "Rotate or delete stale DA/EA accounts; shrink nested admin groups.",
            },
            {
                "title": "Put remaining Tier 0 in Protected Users / Authentication Policy",
                "why": "Delegation and NTLM on a live DA is a one-step takeover after password theft.",
                "action": "Require Protected Users, smart card or phishing-resistant MFA, and silos for Tier 0.",
            },
        ],
        "break_path": [
            "Reduce Domain Admins to a documented break-glass set; no nested groups.",
            "Rotate secrets on disabled privileged accounts; enable Protected Users and Authentication Policies.",
        ],
        "detection": "4728/4729 on Domain Admins; 4768 without pre-auth or with NTLM from privileged users.",
    },
    {
        "id": "ad_dns",
        "name": "AD-integrated DNS takeover (WPAD / DC records)",
        "category": "acl",
        "starting_access": "Write on an AD-integrated DNS zone or a high-risk node such as WPAD or a DC hostname.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.PRIVILEGE_ESCALATION,
        "why_da": (
            "A writable DNS zone lets an attacker answer WPAD or impersonate a Domain Controller name. "
            "NTLM relay of that name to LDAP is a standard Domain Admin finish."
        ),
        "match": {"prefixes": ("ad_dns_",)},
        "stages": [
            {
                "title": "Find who can write the zone or WPAD node",
                "why": "Authenticated Users create-child on a zone is enough to plant WPAD.",
                "action": "Remove broad ACEs from AD-integrated zones; protect DC and WPAD records.",
            },
            {
                "title": "Relay the spoofed name to LDAP",
                "why": "WPAD or a DC A-record plus missing LDAP signing becomes DCSync.",
                "action": "Treat DNS write plus unsigned LDAP as one Domain Admin option.",
            },
        ],
        "break_path": [
            "Restrict AD DNS zone ACLs to DNS admins; disable WPAD via GPO.",
            "Require LDAP signing and channel binding so a spoofed name cannot be relayed.",
        ],
        "detection": "DNS record creates for WPAD/*; LDAP binds from unexpected hosts using DC names.",
    },
    {
        "id": "bitlocker",
        "name": "Readable BitLocker recovery passwords in Active Directory",
        "category": "credential_access",
        "starting_access": "LDAP read of msFVE-RecoveryPassword on a Domain Controller or DA workstation.",
        "da_equivalent": True,
        "severity_if_open": Severity.HIGH,
        "mitre": MITRETechniques.UNSECURED_CREDENTIALS,
        "why_da": (
            "BitLocker recovery keys stored in AD unlock the disk of the computer they protect. "
            "A DC or DA jump-host disk is Domain Admin equivalent."
        ),
        "match": {"prefixes": ("bitlocker_",)},
        "stages": [
            {
                "title": "See which computers have recovery passwords in AD",
                "why": "Helpdesk read on msFVE-* often includes Domain Controllers.",
                "action": "Confirm the computer is a DC, DA workstation, or Tier-0 jump host.",
            },
            {
                "title": "Unlock the disk and harvest LSASS/NTDS",
                "why": "Offline disk access bypasses the running OS's credential guard.",
                "action": "Scope BitLocker AD backup to the owning support tier; never to Authenticated Users.",
            },
        ],
        "break_path": [
            "Remove BitLocker recovery passwords for DCs from AD; use offline escrow.",
            "Restrict msFVE-* read ACLs; rotate recovery passwords after any broad read.",
        ],
        "detection": "LDAP reads of msFVE-RecoveryPassword from unusual callers.",
    },
]

OTHER_DA_SPEC: dict[str, Any] = {
    "id": "other_da",
    "name": "Other Domain Admin-relevant findings",
    "category": "other",
    "starting_access": "Depends on the listed finding; treat each as a DA-adjacent option until disproved.",
    "da_equivalent": True,
    "severity_if_open": Severity.HIGH,
    "mitre": MITRETechniques.PRIVILEGE_ESCALATION,
    "why_da": (
        "These scored findings did not match a named technique card but are still Domain Admin-adjacent "
        "(privileged credentials, control-plane writes, or DA-class vulnerabilities). They are listed so "
        "the map is complete."
    ),
    "match": {},
    "stages": [
        {
            "title": "Review every leftover high/critical finding",
            "why": "A tester who only reads named cards will miss one-off DA options.",
            "action": "For each object below, decide whether it yields DA, a stepping stone, or a false lead.",
        },
    ],
    "break_path": [
        "Remediate or formally accept each leftover finding; do not leave DA-adjacent issues untracked.",
    ],
    "detection": "Finding-specific; see each evidence row.",
}

EVIDENCE_OBJECT_LIMIT = 100
EVIDENCE_SUMMARY_LIMIT = 200

DA_RELEVANT_PREFIXES = (
    "dcsync", "kerberoast", "asrep", "certificate", "adcs", "gpp", "gpo_",
    "acl_", "shadow_admin", "rbcd", "delegat", "backup_operator", "krbtgt",
    "golden_gmsa", "gmsa_", "trust", "hybrid", "rodc", "dmsa", "sccm",
    "hidden_", "ldap_anonymous", "ldap_prewin", "ldap_guest", "attack_graph",
    "adminsdholder", "machine_quota", "zerologon", "nopac", "petitpotam",
    "printnightmare", "coercion", "laps", "key_credential", "privilege_escalat",
    "esc", "unconstrained", "constrained", "admin_count", "inactive_privileged",
    "disabled_domain_admin", "disabled_enterprise", "too_many_domain",
    "nested_admin", "privileged_user", "privileged_account", "privileged_computer",
    "auth_policy_privileged", "ad_dns", "bitlocker", "sid_history",
    "ou_delegation", "service_account_high", "lateral_movement_tier",
    "event_dcsync", "event_kerberoast", "event_asrep", "event_suspicious_certificate",
    "windows_laps", "sensitive_operator",
)


class DomainAdminTakeoverAnalyzer:
    """Build a pentest-oriented Domain Admin takeover map from scored findings."""

    def analyze(
        self,
        risks: list[dict[str, Any]] | None = None,
        users: list[dict[str, Any]] | None = None,
        groups: list[dict[str, Any]] | None = None,
        computers: list[dict[str, Any]] | None = None,
        domain: str | None = None,
        dc_ip: str | None = None,
        attack_graph: dict[str, Any] | None = None,
        assessment_identity: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return open paths, supporting evidence, and the unobserved technique catalog."""
        del users, computers
        risks = list(risks or [])
        context = {
            "domain": str(domain or "").strip() or "DOMAIN",
            "dc_ip": str(dc_ip or "").strip() or "DC_IP",
        }
        open_paths: list[dict[str, Any]] = []
        pending_paths: list[dict[str, Any]] = []
        observed_ids: set[str] = set()
        matched_indexes: set[int] = set()

        for spec in DA_PATH_CATALOG:
            evidence = []
            for index, risk in enumerate(risks):
                if self._matches(risk, spec.get("match") or {}) and not is_disproved(risk):
                    evidence.append(risk)
                    matched_indexes.add(index)
            if not evidence:
                continue
            observed_ids.add(spec["id"])
            supported = [risk for risk in evidence if not requires_validation(risk)]
            if supported:
                open_paths.append(self._build_path(spec, supported, status="open", **context))
            pending = [risk for risk in evidence if requires_validation(risk)]
            if pending:
                pending_paths.append(self._build_path(spec, pending, status="needs_validation", **context))

        leftover = [
            risk for index, risk in enumerate(risks)
            if index not in matched_indexes
            and not is_disproved(risk)
            and self._is_da_relevant(risk)
        ]
        if leftover:
            supported = [risk for risk in leftover if not requires_validation(risk)]
            if supported:
                open_paths.append(self._build_path(OTHER_DA_SPEC, supported, status="open", **context))
            pending = [risk for risk in leftover if requires_validation(risk)]
            if pending:
                pending_paths.append(self._build_path(OTHER_DA_SPEC, pending, status="needs_validation", **context))

        open_paths.sort(key=lambda item: (-SEVERITY_RANK.get(item.get("severity"), 0), item.get("name", "")))

        unobserved = [
            self._build_path(spec, [], status="not_observed", **context)
            for spec in DA_PATH_CATALOG
            if spec["id"] not in observed_ids
        ]

        from_account = build_assessment_account_view(
            assessment_identity,
            attack_graph,
            risks,
            groups,
            open_path_ids=[path["id"] for path in open_paths],
        )
        starters = build_nonadmin_starter_view(
            attack_graph,
            self._technique_rows(risks, leftover),
        )
        da_class = [path for path in open_paths if path.get("da_equivalent")]
        summary = {
            "open_path_count": len(open_paths),
            "pending_path_count": len(pending_paths),
            "da_equivalent_open_count": len(da_class),
            "critical_open_count": sum(1 for path in open_paths if path.get("severity") == Severity.CRITICAL),
            "high_open_count": sum(1 for path in open_paths if path.get("severity") == Severity.HIGH),
            "catalog_count": len(DA_PATH_CATALOG),
            "unobserved_count": len(unobserved),
            "option_count": sum(int(path.get("option_count") or 0) for path in open_paths),
            "evidence_finding_count": sum(int(path.get("evidence_count") or 0) for path in open_paths),
            "assessment_route_count": int(from_account.get("route_count") or 0),
            "assessment_option_count": int(from_account.get("option_count") or 0),
            "nonadmin_starter_count": int(starters.get("principal_count") or 0),
            "nonadmin_technique_count": int(starters.get("technique_option_count") or 0),
            "categories": sorted({path.get("category") for path in open_paths}),
            "headline": self._headline(open_paths, da_class, from_account, starters),
            "from_assessment_account": from_account.get("headline"),
            "nonadmin_starters": starters.get("headline"),
        }
        logger.info(
            "Domain Admin takeover map: %s open paths, %s non-admin starter account(s), %s routes from %s",
            summary["open_path_count"],
            summary["nonadmin_starter_count"],
            from_account.get("route_count") or 0,
            from_account.get("sam") or "unresolved",
        )
        return {
            "summary": summary,
            "open_paths": open_paths,
            "pending_paths": pending_paths,
            "unobserved_paths": unobserved,
            "from_assessment_account": from_account,
            "nonadmin_starters": starters,
            "existing_access": [
                {"id": node.get("id"), "label": node.get("label"), "sid": node.get("sid"),
                 "dn": node.get("dn"), "tier0": bool(node.get("privileged")),
                 "memberships": [edge.get("target") for edge in (attack_graph or {}).get("edges") or []
                                 if edge.get("source") == node.get("id") and edge.get("type") == "MemberOf"]}
                for node in (attack_graph or {}).get("nodes") or []
                if node.get("kind") in {"user", "computer"} and (node.get("privileged") or node.get("sensitive_access"))
            ],
        }

    def _build_path(
        self,
        spec: dict[str, Any],
        evidence: list[dict[str, Any]],
        status: str,
        domain: str = "DOMAIN",
        dc_ip: str = "DC_IP",
    ) -> dict[str, Any]:
        severity = self._severity_for(spec, evidence) if evidence else Severity.LOW
        objects = self._evidence_objects(evidence)
        options = evidence_options(evidence)
        target = objects[0] if objects else "TARGET"
        targets = ", ".join(objects[:8]) if objects else "TARGET"
        playbook = fill_playbook_fields(
            playbook_for(spec["id"]),
            target=target,
            targets=targets,
            domain=domain,
            dc_ip=dc_ip,
        )
        return {
            "id": spec["id"],
            "name": spec["name"],
            "category": spec["category"],
            "status": status,
            "da_equivalent": self._path_is_da_equivalent(spec, evidence),
            "severity": severity,
            "mitre": spec.get("mitre") or "",
            "starting_access": spec.get("starting_access") or "",
            "why_da": spec.get("why_da") or "",
            "stages": list(spec.get("stages") or []),
            "break_path": list(spec.get("break_path") or []),
            "detection": spec.get("detection") or "",
            "poc_roadmap": playbook.get("poc_roadmap") or [],
            "verify_commands": playbook.get("verify_commands") or [],
            "assessment_commands": playbook.get("assessment_commands") or [],
            "tools": playbook.get("tools") or [],
            "claim_level": "observed_condition" if status == "open" else status,
            "takeover_tested": False,
            "evidence_dossiers": [
                evidence_dossier(risk, domain_dn=domain_to_dn(domain), dc_ip=dc_ip)
                for risk in evidence
            ],
            "evidence_count": len(evidence),
            "evidence_objects": objects[:EVIDENCE_OBJECT_LIMIT],
            "evidence_types": sorted({self._risk_type(item) for item in evidence if self._risk_type(item)}),
            "evidence_summaries": self._evidence_summaries(evidence),
            "options": options,
            "option_count": len(options),
        }

    @staticmethod
    def _finding_is_privileged(risk: dict[str, Any]) -> bool:
        if risk.get("is_privileged") is True:
            return True
        return bool(risk.get("privileged_groups"))

    def _path_is_da_equivalent(self, spec: dict[str, Any], evidence: list[dict[str, Any]]) -> bool:
        """Kerberoast and AS-REP are DA-equivalent only for a privileged account."""
        if not spec.get("da_equivalent"):
            return False
        if spec.get("id") not in {"kerberoasting", "asrep"} or not evidence:
            return True
        return any(self._finding_is_privileged(risk) for risk in evidence)

    def _severity_for(self, spec: dict[str, Any], evidence: list[dict[str, Any]]) -> str:
        best = spec.get("severity_if_open") or Severity.HIGH
        best_rank = SEVERITY_RANK.get(best, 3)
        for risk in evidence:
            value = str(risk.get("severity") or risk.get("severity_level") or "").lower()
            rank = SEVERITY_RANK.get(value, 0)
            if rank > best_rank:
                best = value
                best_rank = rank
        return str(best)

    def _evidence_objects(self, evidence: list[dict[str, Any]]) -> list[str]:
        names: list[str] = []
        seen: set[str] = set()
        for risk in evidence:
            raw = (
                risk.get("affected_object")
                or risk.get("sAMAccountName")
                or risk.get("name")
                or ""
            )
            label = str(raw).strip()
            if not label or label in seen:
                continue
            seen.add(label)
            names.append(label)
        return names

    def _evidence_summaries(self, evidence: list[dict[str, Any]]) -> list[dict[str, str]]:
        summaries: list[dict[str, str]] = []
        for risk in evidence[:EVIDENCE_SUMMARY_LIMIT]:
            title = str(risk.get("title") or risk.get("name") or risk.get("type") or "").strip()
            affected = str(
                risk.get("affected_object")
                or risk.get("sAMAccountName")
                or ""
            ).strip()
            summaries.append(
                {
                    "title": title,
                    "object": affected,
                    "type": self._risk_type(risk),
                    "severity": str(risk.get("severity") or risk.get("severity_level") or "").lower(),
                }
            )
        return summaries

    @staticmethod
    def _risk_type(risk: dict[str, Any]) -> str:
        return str(risk.get("type") or risk.get("risk_type") or "").lower()

    @staticmethod
    def _replication_pair_incomplete(risk: dict[str, Any]) -> bool:
        """A single replication right is not a DCSync path."""
        risk_type = str(risk.get("type") or risk.get("risk_type") or "").lower()
        if not risk_type.startswith("acl_ds_replication"):
            return False
        evidence = risk.get("evidence") if isinstance(risk.get("evidence"), dict) else {}
        return not evidence.get("dcsync_pair_complete")

    def _matches(self, risk: dict[str, Any], match: dict[str, Any]) -> bool:
        risk_type = self._risk_type(risk)
        if not risk_type or risk_type == "acl_descriptor_unreadable" or self._replication_pair_incomplete(risk):
            return False
        for prefix in match.get("exclude_prefixes") or ():
            if risk_type.startswith(str(prefix).lower()):
                return False
        for item in match.get("exclude_types") or ():
            if risk_type == str(item).lower():
                return False
        exact = {str(item).lower() for item in match.get("types") or ()}
        if risk_type in exact:
            return True
        for prefix in match.get("prefixes") or ():
            if risk_type.startswith(str(prefix).lower()):
                return True
        for token in match.get("contains") or ():
            if str(token).lower() in risk_type:
                return True
        return False

    def _technique_rows(
        self,
        risks: list[dict[str, Any]],
        leftover: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Attach each DA-relevant finding to its catalog technique for foothold listing."""
        rows: list[dict[str, Any]] = []
        for spec in DA_PATH_CATALOG:
            for risk in risks:
                if is_disproved(risk) or not self._matches(risk, spec.get("match") or {}):
                    continue
                rows.append(
                    {
                        "risk": risk,
                        "technique_id": spec["id"],
                        "technique_name": spec["name"],
                        "why_da": spec.get("why_da") or "",
                        "category": spec.get("category") or "",
                        "da_equivalent": self._path_is_da_equivalent(spec, [risk]),
                        "pending": requires_validation(risk),
                    }
                )
        for risk in leftover:
            rows.append(
                {
                    "risk": risk,
                    "technique_id": OTHER_DA_SPEC["id"],
                    "technique_name": OTHER_DA_SPEC["name"],
                    "why_da": OTHER_DA_SPEC.get("why_da") or "",
                    "category": OTHER_DA_SPEC.get("category") or "other",
                    "da_equivalent": True,
                    "pending": requires_validation(risk),
                }
            )
        return rows

    def _is_da_relevant(self, risk: dict[str, Any]) -> bool:
        risk_type = self._risk_type(risk)
        if risk_type == "acl_descriptor_unreadable" or self._replication_pair_incomplete(risk):
            return False
        if any(risk_type.startswith(prefix) for prefix in DA_RELEVANT_PREFIXES):
            return True
        severity = str(risk.get("severity") or risk.get("severity_level") or "").lower()
        if severity in {"critical", "high"} and any(
            token in risk_type for token in ("admin", "privileg", "tier0", "tier-0", "dcsync")
        ):
            return True
        return False

    @staticmethod
    def _headline(
        open_paths: list[dict[str, Any]],
        da_class: list[dict[str, Any]],
        from_account: dict[str, Any] | None = None,
        starters: dict[str, Any] | None = None,
    ) -> str:
        account = (from_account or {}).get("headline") or ""
        count = int((starters or {}).get("principal_count") or 0)
        starter_bit = (
            f" {count} named non-admin account(s) have an evidenced foothold."
            if count
            else ""
        )
        if not open_paths:
            base = (
                "No Domain Admin takeover path is currently evidenced by scan findings. "
                "The catalog below remains the pentest checklist for conditions that were not observed."
            )
            return f"{base}{starter_bit} {account}".strip()
        top = da_class[0]["name"] if da_class else open_paths[0]["name"]
        options = sum(int(path.get("option_count") or 0) for path in open_paths)
        base = (
            f"{len(open_paths)} Domain Admin-relevant path(s) are evidenced in this domain "
            f"({options} object-level option(s)). Highest-priority open technique: {top}."
            f"{starter_bit}"
        )
        return f"{base} {account}".strip()

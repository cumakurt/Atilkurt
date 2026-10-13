"""
Mixin for building the main risk sections tab content and orchestrating risk categorization.
"""

import html as html_stdlib

from analysis.privileged_account_status import list_disabled_privileged_admins
from core.ad_identity import is_privileged_group_name, membership_names

LDAP_DIRECTORY_EXPOSURE_TYPES = frozenset({
    "ldap_anonymous_enabled",
    "ldap_prewin2k_broad_membership",
    "ldap_guest_enabled",
    "ldap_legacy_functional_level",
})
IDENTITY_PROTECTION_TYPES = frozenset({
    "reversible_encryption_enabled",
    "privileged_user_outside_protected_users",
    "privileged_user_without_smartcard",
})
ADCS_EXTENDED_TYPES = frozenset({
    "certificate_esc5",
    "certificate_esc7",
    "certificate_esc9",
    "certificate_esc10",
    "certificate_esc11",
    "certificate_esc13",
    "certificate_esc14",
    "certificate_esc15",
    "certificate_esc16",
    "certificate_certifried",
})
PASSWORD_POLICY_TYPES = frozenset({
    "password_policy_weak",
})
DOMAIN_SECURITY_TYPES = frozenset({
    "ldap_signing_disabled",
    "ntlm_restriction_weak",
    "smb_signing_disabled",
})
KERBEROS_ACCOUNT_SECURITY_TYPES = frozenset({
    "kerberos_legacy_encryption",
    "privileged_account_delegatable",
})
HIDDEN_PRIVILEGE_TYPES = frozenset({
    "hidden_primary_group_privilege",
    "privileged_computer_account",
    "builtin_admin_renamed",
})
ESCALATION_TYPES = frozenset({
    "privilege_escalation_path",
    "delegation_privilege_escalation",
    "spn_privilege_escalation",
    "computer_delegation_privilege_path",
    "acl_privilege_escalation_path",
})
EXTENDED_LDAP_TYPES = frozenset({
    "rbcd_delegation",
    "sid_history_present",
    "foreign_security_principal",
    "key_credential_link_present",
    "fine_grained_password_policy",
    "bitlocker_recovery_in_ad",
    "adminsdholder_analysis",
    "ou_gpo_inheritance_blocked",
    "ou_delegation_risk",
    "empty_group",
    "deeply_nested_group",
    "computer_account_expired",
    "printer_object_risk",
    "exchange_objects_found",
    "dns_zone_found",
    "ad_recycle_bin_enabled",
    "ad_recycle_bin_deleted_objects",
})


class RiskTabBuilderMixin:
    """Mixin for building the main risk sections tab content and orchestrating risk categorization."""

    def _generate_risk_sections(self, risks, misconfig_findings, ciso_dashboard_html="", users=None, groups=None, computers=None, password_stats=None, compliance_data=None, risk_management_data=None, domain=None, dc_ip=None, kerberoasting_targets=None, asrep_targets=None, domain_admin_takeover=None):
        """Generate HTML sections for all risks."""
        buckets = self._bucket_scored_risks(risks, users)
        user_risks = buckets['user']
        computer_risks = buckets['computer']
        group_risks = buckets['group']
        escalation_risks = self._filter_admin_users_from_escalation_paths(
            buckets['escalation'], users, groups
        ) if users and groups else buckets['escalation']
        kerberos_risks = buckets['kerberos']
        kerberoasting_risks = buckets['kerberoasting']
        asrep_risks = buckets['asrep']
        service_account_risks = buckets['service_account']
        gpo_abuse_risks = buckets['gpo']
        dcsync_risks = buckets['dcsync']
        password_policy_risks = buckets['password_policy']
        trust_risks = buckets['trust']
        certificate_risks = buckets['certificate']
        gpp_risks = buckets['gpp']
        laps_risks = buckets['laps']
        zerologon_risks = buckets['zerologon']
        printnightmare_risks = buckets['printnightmare']
        petitpotam_risks = buckets['petitpotam']
        shadow_credentials_risks = buckets['shadow_credentials']
        nopac_risks = buckets['nopac']
        domain_security_risks = buckets['domain_security']
        extended_ldap_risks = buckets['extended_ldap']
        legacy_os_risks = buckets['legacy_os']
        acl_security_risks = buckets['acl_security']
        shadow_admin_risks = buckets['shadow_admin']
        acl_escalation_risks_list = buckets['acl_escalation']
        password_spray_risks = buckets['password_spray']
        golden_gmsa_risks = buckets['golden_gmsa']
        honeypot_risks = buckets['honeypot']
        stale_objects_risks = buckets['stale_objects']
        adcs_extended_risks = buckets['adcs_extended']
        audit_policy_risks = buckets['audit_policy']
        backup_operator_risks = buckets['backup_operator']
        coercion_risks = buckets['coercion']
        gmsa_risks = buckets['gmsa']
        krbtgt_risks = buckets['krbtgt']
        lateral_movement_risks = buckets['lateral_movement']
        machine_quota_risks = buckets['machine_quota']
        replication_risks = buckets['replication']
        ldap_directory_exposure_risks = buckets['ldap_directory_exposure']
        hidden_privilege_risks = buckets['hidden_privilege']
        hybrid_identity_risks = buckets['hybrid_identity']
        rodc_attack_surface_risks = buckets['rodc']
        delegated_msa_risks = buckets['delegated_msa']
        sccm_attack_surface_risks = buckets['sccm']
        kerberos_account_security_risks = buckets['kerberos_account_security']
        identity_protection_risks = buckets['identity_protection']
        fine_grained_password_policy_risks = buckets['fine_grained_password_policy']
        critical_risks = buckets['critical']
        high_risks = buckets['high']
        privileged_account_risks = buckets['privileged']
        delegation_risks = buckets['delegation']

        all_risks_html = self._generate_risk_list(risks, "All Security Risks", "all_risks", group_by_finding=True)
        user_risks_html = self._generate_risk_list(user_risks, "User-Related Risks", "user_risks", group_by_finding=True)
        computer_risks_html = self._generate_risk_list(computer_risks, "Computer-Related Risks", "computer_risks", group_by_finding=True)
        group_risks_html = self._generate_risk_list(group_risks, "Group-Related Risks", "group_risks", group_by_finding=True)
        kerberos_risks_html = self._generate_risk_list(kerberos_risks, "Kerberos & Delegation Risks", "kerberos_delegation", group_by_finding=True)
        critical_risks_html = self._generate_risk_list(critical_risks, "Critical Risks", "critical_risks", group_by_finding=True)
        high_risks_html = self._generate_risk_list(high_risks, "High Risks", "high_risks", group_by_finding=True)
        privileged_accounts_html = self._generate_risk_list(privileged_account_risks, "Privileged Account Risks", "privileged_accounts", group_by_finding=True)
        disabled_privileged_admin_html = self._generate_disabled_privileged_admin_section(users)
        delegation_risks_html = self._generate_risk_list(delegation_risks, "Delegation Risks", "delegation_risks", group_by_finding=True)
        kerberoasting_html = self._generate_kerberoasting_section(kerberoasting_risks)
        service_accounts_html = self._generate_risk_list(service_account_risks, "Service Account Risks", "service_accounts", group_by_finding=True)
        gpo_abuse_html = self._generate_risk_list(gpo_abuse_risks, "GPO Abuse Risks", "gpo_abuse", group_by_finding=True)
        dcsync_html = self._generate_risk_list(dcsync_risks, "DCSync Rights Risks", "dcsync_risks", group_by_finding=True)
        password_policy_html = self._generate_risk_list(password_policy_risks, "Password Policy Issues", "password_policy", group_by_finding=True)
        trust_html = self._generate_risk_list(trust_risks, "Trust Relationship Risks", "trust_risks", group_by_finding=True)
        certificate_html = self._generate_risk_list(certificate_risks, "Certificate Service Risks", "certificate_risks", group_by_finding=True)
        gpp_html = self._generate_risk_list(gpp_risks, "GPP Password Risks", "gpp_risks", group_by_finding=True)
        laps_html = self._generate_risk_list(laps_risks, "LAPS Configuration Risks", "laps_risks", group_by_finding=True)
        zerologon_html = self._generate_risk_list(zerologon_risks, "ZeroLogon Vulnerabilities", "zerologon_risks", group_by_finding=True)
        printnightmare_html = self._generate_risk_list(printnightmare_risks, "PrintNightmare Vulnerabilities", "printnightmare_risks", group_by_finding=True)
        petitpotam_html = self._generate_risk_list(petitpotam_risks, "PetitPotam Risks", "petitpotam_risks", group_by_finding=True)
        shadow_credentials_html = self._generate_risk_list(shadow_credentials_risks, "Shadow Credentials Risks", "shadow_credentials", group_by_finding=True)
        nopac_html = self._generate_risk_list(nopac_risks, "NoPac (CVE-2021-42278/42287) Vulnerabilities", "nopac_risks", group_by_finding=True)
        domain_security_html = self._generate_risk_list(domain_security_risks, "LDAP/NTLM/SMB Security", "domain_security", group_by_finding=True)
        extended_ldap_html = self._generate_risk_list(extended_ldap_risks, "Extended LDAP Security (RBCD, sIDHistory, PSO, BitLocker, etc.)", "extended_ldap", group_by_finding=True)

        # ── New module HTML sections ────────────────────────────────────────
        password_spray_html = self._generate_risk_list(password_spray_risks, "Password Spray Risk Analysis", "password_spray", group_by_finding=True)
        golden_gmsa_html = self._generate_risk_list(golden_gmsa_risks, "Golden gMSA Exposure", "golden_gmsa", group_by_finding=True)
        honeypot_html = self._generate_risk_list(honeypot_risks, "Honeypot & Deception Detection", "honeypot", group_by_finding=True)
        stale_objects_html = self._generate_risk_list(stale_objects_risks, "Stale & Dormant Objects", "stale_objects", group_by_finding=True)
        adcs_extended_html = self._generate_risk_list(adcs_extended_risks, "AD CS Extended (ESC5-15, Certifried)", "adcs_extended", group_by_finding=True)
        audit_policy_html = self._generate_risk_list(audit_policy_risks, "Audit Policy Analysis", "audit_policy", group_by_finding=True)
        backup_operator_html = self._generate_risk_list(backup_operator_risks, "Backup Operators & Sensitive Groups", "backup_operators", group_by_finding=True)
        coercion_html = self._generate_risk_list(coercion_risks, "Coercion Attacks (SpoolSample, DFSCoerce, WebClient)", "coercion_attacks", group_by_finding=True)
        gmsa_html = self._generate_risk_list(gmsa_risks, "gMSA Configuration Issues", "gmsa_config", group_by_finding=True)
        krbtgt_html = self._generate_risk_list(krbtgt_risks, "KRBTGT Account Health", "krbtgt_health", group_by_finding=True)
        lateral_movement_html = self._generate_risk_list(lateral_movement_risks, "Lateral Movement Analysis", "lateral_movement", group_by_finding=True)
        machine_quota_html = self._generate_risk_list(machine_quota_risks, "Machine Account Quota", "machine_quota", group_by_finding=True)
        replication_html = self._generate_risk_list(replication_risks, "Replication Metadata Analysis", "replication_meta", group_by_finding=True)
        ldap_directory_exposure_html = self._generate_risk_list(ldap_directory_exposure_risks, "LDAP Directory Exposure", "ldap_directory_exposure", group_by_finding=True)
        hidden_privilege_html = self._generate_risk_list(hidden_privilege_risks, "Hidden Privilege & Primary Group", "hidden_privilege", group_by_finding=True)
        hybrid_identity_html = self._generate_risk_list(hybrid_identity_risks, "Hybrid Identity (Entra Connect / ADFS)", "hybrid_identity", group_by_finding=True)
        rodc_attack_surface_html = self._generate_risk_list(rodc_attack_surface_risks, "RODC Password Replication", "rodc_attack_surface", group_by_finding=True)
        delegated_msa_html = self._generate_risk_list(delegated_msa_risks, "Delegated MSA / BadSuccessor", "delegated_msa", group_by_finding=True)
        sccm_attack_surface_html = self._generate_risk_list(sccm_attack_surface_risks, "SCCM Attack Surface", "sccm_attack_surface", group_by_finding=True)
        kerberos_account_security_html = self._generate_risk_list(
            kerberos_account_security_risks,
            "Kerberos Account Encryption & Delegation Protection",
            "kerberos_account_security",
            group_by_finding=True,
        )
        identity_protection_html = self._generate_risk_list(
            identity_protection_risks,
            "Privileged Identity Protection",
            "identity_protection",
            group_by_finding=True,
        )
        fine_grained_password_policy_html = self._generate_risk_list(
            fine_grained_password_policy_risks,
            "Fine-Grained Password Policy Overrides",
            "fine_grained_password_policy",
            group_by_finding=True,
        )

        red_team_playbook_html, blue_team_checklists_html = self._generate_purple_team_section(
            risks, domain, dc_ip, kerberoasting_risks, asrep_risks, dcsync_risks,
            nopac_risks, domain_security_risks, kerberoasting_targets, asrep_targets,
            privileged_account_risks, gpp_risks, extended_ldap_risks
        )
        legacy_os_html = self._generate_legacy_os_section(legacy_os_risks)
        acl_security_html = self._generate_acl_security_section(acl_security_risks, shadow_admin_risks, acl_escalation_risks_list)
        paths_html = self._generate_attack_paths(escalation_risks, users, groups)
        misconfig_html = self._generate_misconfig_section(misconfig_findings)

        # Generate tab content with dashboard
        dashboard_tab = f"""
        <div id="dashboard" class="tab-pane show active" role="tabpanel" aria-labelledby="dashboard-tab">
            {ciso_dashboard_html}
        </div>
        """
        domain_admin_tab = f"""
        <div id="domain-admin-takeover" class="tab-pane" role="tabpanel" aria-labelledby="domain-admin-takeover-tab">
            {self._generate_domain_admin_takeover_section(domain_admin_takeover, domain=domain, dc_ip=dc_ip)}
        </div>
        """
        return f"""
        {dashboard_tab}
        {domain_admin_tab}
        <div id="risks" class="tab-pane" role="tabpanel" aria-labelledby="risks-tab">
            {all_risks_html}
        </div>
        <div id="critical-risks" class="tab-pane" role="tabpanel" aria-labelledby="critical-risks-tab">
            {critical_risks_html}
        </div>
        <div id="high-risks" class="tab-pane" role="tabpanel" aria-labelledby="high-risks-tab">
            {high_risks_html}
        </div>
        <div id="privileged-accounts" class="tab-pane" role="tabpanel" aria-labelledby="privileged-accounts-tab">
            {disabled_privileged_admin_html}
            {identity_protection_html}
            {privileged_accounts_html}
        </div>
        <div id="delegation-risks" class="tab-pane" role="tabpanel" aria-labelledby="delegation-risks-tab">
            {delegation_risks_html}
        </div>
        <div id="users" class="tab-pane" role="tabpanel" aria-labelledby="users-tab">
            {user_risks_html}
        </div>
        <div id="computers" class="tab-pane" role="tabpanel" aria-labelledby="computers-tab">
            {computer_risks_html}
        </div>
        <div id="groups" class="tab-pane" role="tabpanel" aria-labelledby="groups-tab">
            {group_risks_html}
        </div>
        <div id="kerberos" class="tab-pane" role="tabpanel" aria-labelledby="kerberos-tab">
            {kerberos_risks_html}
        </div>
        <div id="paths" class="tab-pane" role="tabpanel" aria-labelledby="paths-tab">
            {paths_html}
        </div>
        <div id="kerberoasting" class="tab-pane" role="tabpanel" aria-labelledby="kerberoasting-tab">
            {kerberoasting_html}
        </div>
        <div id="service-accounts" class="tab-pane" role="tabpanel" aria-labelledby="service-accounts-tab">
            {service_accounts_html}
        </div>
        <div id="gpo-abuse" class="tab-pane" role="tabpanel" aria-labelledby="gpo-abuse-tab">
            {gpo_abuse_html}
        </div>
        <div id="dcsync-risks" class="tab-pane" role="tabpanel" aria-labelledby="dcsync-risks-tab">
            {dcsync_html}
        </div>
        <div id="password-policy" class="tab-pane" role="tabpanel" aria-labelledby="password-policy-tab">
            {password_policy_html}
        </div>
        <div id="trust-risks" class="tab-pane" role="tabpanel" aria-labelledby="trust-risks-tab">
            {trust_html}
        </div>
        <div id="certificate-risks" class="tab-pane" role="tabpanel" aria-labelledby="certificate-risks-tab">
            {certificate_html}
        </div>
        <div id="gpp-risks" class="tab-pane" role="tabpanel" aria-labelledby="gpp-risks-tab">
            {gpp_html}
        </div>
        <div id="laps-risks" class="tab-pane" role="tabpanel" aria-labelledby="laps-risks-tab">
            {laps_html}
        </div>
        <div id="vulnerabilities" class="tab-pane" role="tabpanel" aria-labelledby="vulnerabilities-tab">
            <div class="card">
                <div class="card-header">
                    <i class="fas fa-bug"></i> Known Vulnerabilities
                </div>
                <div class="card-body">
                    <div class="row risk-section-fullstack">
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-exclamation-circle text-danger"></i> ZeroLogon (CVE-2020-1472)</h5>
                            {zerologon_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-print text-warning"></i> PrintNightmare (CVE-2021-1675, CVE-2021-34527)</h5>
                            {printnightmare_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-exchange-alt text-info"></i> PetitPotam</h5>
                            {petitpotam_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-key text-danger"></i> Shadow Credentials</h5>
                            {shadow_credentials_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-user-shield text-danger"></i> NoPac (CVE-2021-42278/42287)</h5>
                            {nopac_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-shield-alt text-warning"></i> LDAP/NTLM/SMB Security</h5>
                            {domain_security_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-database text-info"></i> Extended LDAP (RBCD, sIDHistory, PSO, BitLocker, OU, etc.)</h5>
                            {extended_ldap_html}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div id="advanced-analysis" class="tab-pane" role="tabpanel" aria-labelledby="advanced-analysis-tab">
            <div class="card">
                <div class="card-header">
                    <i class="fas fa-microscope"></i> Advanced Security Analysis
                </div>
                <div class="card-body">
                    <div class="row risk-section-fullstack">
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-spray-can text-danger"></i> Password Spray Risk</h5>
                            {password_spray_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-key text-danger"></i> Golden gMSA Exposure</h5>
                            {golden_gmsa_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-user-secret text-info"></i> gMSA Configuration</h5>
                            {gmsa_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-ticket-alt text-warning"></i> KRBTGT Account Health</h5>
                            {krbtgt_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-shield-alt text-danger"></i> Kerberos Account Encryption & Delegation Protection</h5>
                            {kerberos_account_security_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-user-lock text-warning"></i> Fine-Grained Password Policy Overrides</h5>
                            {fine_grained_password_policy_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-laptop text-warning"></i> Machine Account Quota</h5>
                            {machine_quota_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-project-diagram text-danger"></i> Lateral Movement</h5>
                            {lateral_movement_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-broadcast-tower text-danger"></i> Coercion Attacks</h5>
                            {coercion_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-certificate text-warning"></i> AD CS Extended (ESC5-15, Certifried)</h5>
                            {adcs_extended_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-users-cog text-warning"></i> Backup Operators & Sensitive Groups</h5>
                            {backup_operator_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-id-badge text-danger"></i> Hidden Privilege & Primary Group</h5>
                            {hidden_privilege_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-cloud text-danger"></i> Hybrid Identity (Entra / ADFS)</h5>
                            {hybrid_identity_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-server text-warning"></i> RODC Password Replication</h5>
                            {rodc_attack_surface_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-user-ninja text-danger"></i> Delegated MSA / BadSuccessor</h5>
                            {delegated_msa_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-network-wired text-warning"></i> SCCM Attack Surface</h5>
                            {sccm_attack_surface_html}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div id="hygiene" class="tab-pane" role="tabpanel" aria-labelledby="hygiene-tab">
            <div class="card">
                <div class="card-header">
                    <i class="fas fa-broom"></i> AD Hygiene & Monitoring
                </div>
                <div class="card-body">
                    <div class="row risk-section-fullstack">
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-clock text-warning"></i> Stale & Dormant Objects</h5>
                            {stale_objects_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-search text-info"></i> Audit Policy Analysis</h5>
                            {audit_policy_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-sync-alt text-info"></i> Replication Metadata</h5>
                            {replication_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-spider text-success"></i> Honeypot & Deception</h5>
                            {honeypot_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-project-diagram text-danger"></i> LDAP Directory Exposure</h5>
                            {ldap_directory_exposure_html}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div id="red-team-playbook" class="tab-pane" role="tabpanel" aria-labelledby="red-team-playbook-tab">
            {red_team_playbook_html}
        </div>
        <div id="blue-team-checklists" class="tab-pane" role="tabpanel" aria-labelledby="blue-team-checklists-tab">
            {blue_team_checklists_html}
        </div>
        <div id="misconfig" class="tab-pane" role="tabpanel" aria-labelledby="misconfig-tab">
            {misconfig_html}
        </div>
        <div id="directory" class="tab-pane" role="tabpanel" aria-labelledby="directory-tab">
            {self._generate_directory_section(users, groups, computers, risks)}
        </div>
        <div id="password-issues" class="tab-pane" role="tabpanel" aria-labelledby="password-issues-tab">
            {self._generate_password_issues_full_list(password_stats) if password_stats else '<div class="card"><div class="card-body text-center"><p class="text-muted">No password issues found.</p></div></div>'}
        </div>
        <div id="legacy-os" class="tab-pane" role="tabpanel" aria-labelledby="legacy-os-tab">
            {legacy_os_html}
        </div>
        <div id="acl-security" class="tab-pane" role="tabpanel" aria-labelledby="acl-security-tab">
            {acl_security_html}
        </div>
        {self._generate_compliance_section(compliance_data) if compliance_data else ''}
        {self._generate_risk_management_section(risk_management_data) if risk_management_data else ''}
        """

    def _bucket_scored_risks(self, risks, users=None):
        """Classify scored findings in a single pass with O(1) user lookup."""
        buckets = {key: [] for key in (
            'user', 'computer', 'group', 'escalation', 'kerberos', 'kerberoasting', 'asrep',
            'service_account', 'gpo', 'dcsync', 'password_policy', 'trust', 'certificate',
            'gpp', 'laps', 'zerologon', 'printnightmare', 'petitpotam', 'shadow_credentials',
            'nopac', 'domain_security', 'extended_ldap', 'legacy_os', 'acl_security',
            'shadow_admin', 'acl_escalation', 'password_spray', 'golden_gmsa', 'honeypot',
            'stale_objects', 'adcs_extended', 'audit_policy', 'backup_operator', 'coercion',
            'gmsa', 'krbtgt', 'lateral_movement', 'machine_quota', 'replication',
            'ldap_directory_exposure', 'hidden_privilege', 'hybrid_identity', 'rodc',
            'delegated_msa', 'sccm', 'kerberos_account_security', 'identity_protection',
            'fine_grained_password_policy', 'critical', 'high', 'privileged', 'delegation',
        )}
        users_by_name = {
            user.get('sAMAccountName'): user
            for user in (users or [])
            if user.get('sAMAccountName')
        }
        for risk in risks:
            rtype = str(risk.get('type') or '')
            rtype_l = rtype.lower()
            obj = risk.get('object_type')
            severity = str(risk.get('severity_level') or risk.get('severity') or '').lower()
            if obj == 'user':
                buckets['user'].append(risk)
            elif obj == 'computer':
                buckets['computer'].append(risk)
            elif obj == 'group':
                buckets['group'].append(risk)
            if rtype in ESCALATION_TYPES:
                buckets['escalation'].append(risk)
            if 'delegation' in rtype_l or 'kerberos' in rtype_l:
                buckets['kerberos'].append(risk)
            if 'kerberoasting' in rtype_l or rtype == 'user_with_spn':
                buckets['kerberoasting'].append(risk)
            if 'asrep' in rtype_l or rtype == 'kerberos_preauth_disabled':
                buckets['asrep'].append(risk)
            if 'service_account' in rtype_l:
                buckets['service_account'].append(risk)
            if 'gpo' in rtype_l:
                buckets['gpo'].append(risk)
            if 'dcsync' in rtype_l:
                buckets['dcsync'].append(risk)
            if rtype in PASSWORD_POLICY_TYPES:
                buckets['password_policy'].append(risk)
            if 'trust' in rtype_l or obj == 'trust':
                buckets['trust'].append(risk)
            if ('certificate' in rtype_l or 'esc' in rtype_l) and rtype not in ADCS_EXTENDED_TYPES:
                buckets['certificate'].append(risk)
            if 'gpp' in rtype_l:
                buckets['gpp'].append(risk)
            if 'laps' in rtype_l:
                buckets['laps'].append(risk)
            if 'zerologon' in rtype_l:
                buckets['zerologon'].append(risk)
            if 'printnightmare' in rtype_l:
                buckets['printnightmare'].append(risk)
            if 'petitpotam' in rtype_l:
                buckets['petitpotam'].append(risk)
            if 'shadow' in rtype_l and 'credential' in rtype_l:
                buckets['shadow_credentials'].append(risk)
            if 'nopac' in rtype_l:
                buckets['nopac'].append(risk)
            if rtype in DOMAIN_SECURITY_TYPES:
                buckets['domain_security'].append(risk)
            if rtype in EXTENDED_LDAP_TYPES:
                buckets['extended_ldap'].append(risk)
            if 'legacy' in rtype_l or 'eol' in rtype_l:
                buckets['legacy_os'].append(risk)
            if rtype.startswith('acl_'):
                buckets['acl_security'].append(risk)
            if rtype == 'shadow_admin':
                buckets['shadow_admin'].append(risk)
            if rtype == 'acl_privilege_escalation_path':
                buckets['acl_escalation'].append(risk)
            if 'password_spray' in rtype_l:
                buckets['password_spray'].append(risk)
            if 'golden_gmsa' in rtype_l:
                buckets['golden_gmsa'].append(risk)
            if 'honeypot' in rtype_l:
                buckets['honeypot'].append(risk)
            if 'stale_' in rtype_l:
                buckets['stale_objects'].append(risk)
            if rtype in ADCS_EXTENDED_TYPES:
                buckets['adcs_extended'].append(risk)
            if 'audit_policy' in rtype_l or 'audit_sacl' in rtype_l:
                buckets['audit_policy'].append(risk)
            if 'backup_operator' in rtype_l or 'sensitive_operator' in rtype_l:
                buckets['backup_operator'].append(risk)
            if 'coercion' in rtype_l:
                buckets['coercion'].append(risk)
            if 'gmsa_' in rtype_l and 'golden' not in rtype_l:
                buckets['gmsa'].append(risk)
            if 'krbtgt_' in rtype_l:
                buckets['krbtgt'].append(risk)
            if 'lateral_movement' in rtype_l:
                buckets['lateral_movement'].append(risk)
            if 'machine_account_quota' in rtype_l:
                buckets['machine_quota'].append(risk)
            if 'replication_' in rtype_l:
                buckets['replication'].append(risk)
            if rtype in LDAP_DIRECTORY_EXPOSURE_TYPES:
                buckets['ldap_directory_exposure'].append(risk)
            if rtype in HIDDEN_PRIVILEGE_TYPES:
                buckets['hidden_privilege'].append(risk)
            if rtype.startswith('hybrid_'):
                buckets['hybrid_identity'].append(risk)
            if rtype.startswith('rodc_'):
                buckets['rodc'].append(risk)
            if rtype.startswith('dmsa_'):
                buckets['delegated_msa'].append(risk)
            if rtype.startswith('sccm_'):
                buckets['sccm'].append(risk)
            if rtype in KERBEROS_ACCOUNT_SECURITY_TYPES:
                buckets['kerberos_account_security'].append(risk)
            if rtype in IDENTITY_PROTECTION_TYPES:
                buckets['identity_protection'].append(risk)
            if rtype == 'weak_fine_grained_password_policy':
                buckets['fine_grained_password_policy'].append(risk)
            if severity == 'critical':
                buckets['critical'].append(risk)
            if severity == 'high':
                buckets['high'].append(risk)
            if (
                risk.get('is_privileged', False)
                or rtype in ('disabled_domain_admin', 'disabled_enterprise_admin')
                or (
                    obj == 'user'
                    and self._user_is_privileged_for_report(users_by_name.get(risk.get('affected_object')))
                )
            ):
                buckets['privileged'].append(risk)
            if 'delegation' in rtype_l:
                buckets['delegation'].append(risk)
        return buckets

    @staticmethod
    def _user_is_privileged_for_report(user):
        """Return True for AdminSDHolder or exact privileged-group membership."""
        if not user:
            return False
        if str(user.get('adminCount') or '').strip().lower() in {'1', 'true'}:
            return True
        return any(is_privileged_group_name(name) for name in membership_names(user.get('memberOf')))

    def _generate_disabled_privileged_admin_section(self, users):
        """Dedicated Privileged Accounts panel for disabled DA/EA users."""
        accounts = list_disabled_privileged_admins(users)
        if not accounts:
            return """
            <div class="alert alert-success" id="disabled-privileged-admins">
                <i class="fas fa-check-circle"></i>
                No disabled Domain Admin or Enterprise Admin accounts were found.
            </div>
            """
        rows = []
        for account in accounts:
            roles = ", ".join(html_stdlib.escape(role) for role in account.get("roles") or [])
            rows.append(
                "<tr>"
                f"<td><strong>{html_stdlib.escape(str(account.get('username') or 'Unknown'))}</strong> "
                '<span class="badge bg-warning text-dark">Disabled</span></td>'
                f'<td><span class="badge bg-danger">{roles}</span></td>'
                f"<td><small>{html_stdlib.escape(str(account.get('distinguishedName') or ''))}</small></td>"
                "</tr>"
            )
        return f"""
        <div class="card border-danger mb-4" id="disabled-privileged-admins">
            <div class="card-header bg-danger text-white">
                <i class="fas fa-user-slash"></i> Disabled Domain Admin / Enterprise Admin accounts ({len(accounts)})
            </div>
            <div class="card-body">
                <p>These accounts are disabled but still members of Domain Admins or Enterprise Admins.
                Re-enabling any of them restores those rights immediately. Remove them from the privileged group before leaving the account disabled or deleted.</p>
                <div class="table-responsive">
                    <table class="table table-sm table-hover">
                        <thead><tr><th>Username</th><th>Privileged group</th><th>Distinguished name</th></tr></thead>
                        <tbody>{''.join(rows)}</tbody>
                    </table>
                </div>
            </div>
        </div>
        """

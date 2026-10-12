"""Generate a local, read-only Windows evidence collector without executing it."""

from __future__ import annotations

import base64
import json
from typing import Any


def build_validation_script(center: dict[str, Any]) -> str:
    """Encode directory-controlled input as data, never as PowerShell source."""
    manifest = {
        "domain": center["domain"],
        "rule_version": center["rule_version"],
        "findings": center["findings"],
    }
    encoded = base64.b64encode(json.dumps(manifest, ensure_ascii=True).encode()).decode("ascii")
    return _SCRIPT.replace("__MANIFEST__", encoded)


_SCRIPT = r"""# AtilKurt local evidence collection. No directory, service, or policy changes.
# Run on the computer being reviewed; administrative read permissions may be needed.
param([string]$OutputPath = '.\atilkurt-evidence.json')
$ErrorActionPreference = 'Stop'
$manifest = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__MANIFEST__')) | ConvertFrom-Json
$collectedAt = [DateTime]::UtcNow.ToString('o')
$hostName = $env:COMPUTERNAME
$observations = @()
$errors = @()
$values = @{}
try {
    $system = Get-CimInstance Win32_ComputerSystem
    if ($system.Domain -ine $manifest.domain) { throw 'Computer does not belong to the assessment domain' }
    $hostName = $system.DNSHostName + '.' + $system.Domain
} catch {
    throw "Cannot establish the evidence target: $($_.Exception.Message)"
}
$registryChecks = @(
    @{name='LDAPServerIntegrity'; path='HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'},
    @{name='LDAPServerEnforceIntegrity'; path='HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'},
    @{name='LdapEnforceChannelBinding'; path='HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'},
    @{name='RestrictNTLMInDomain'; path='HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'},
    @{name='RestrictReceivingNTLMTraffic'; path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'},
    @{name='RestrictSendingNTLMTraffic'; path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'},
    @{name='RequireSecuritySignature'; path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'},
    @{name='DefaultDomainSupportedEncTypes'; path='HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'},
    @{name='CertificateMappingMethods'; path='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel'},
    @{name='LAPSBackupDirectory'; property='BackupDirectory'; path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'},
    @{name='LAPSPasswordEncryptionEnabled'; property='ADPasswordEncryptionEnabled'; path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'},
    @{name='RunAsPPL'; path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'},
    @{name='wdigest'; property='UseLogonCredential'; path='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'}
)
foreach ($check in $registryChecks) {
    try {
        $property = if ($check.property) { $check.property } else { $check.name }
        $value = Get-ItemPropertyValue -LiteralPath $check.path -Name $property
        $values[$check.name] = $value
        $observations += @{target=$hostName; name=$check.name; value=$value; source=$check.path; collected_at=$collectedAt}
    } catch {
        $errors += @{target=$hostName; name=$check.name; error='Value absent or not readable'}
    }
}
try {
    $guard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
    $observations += @{target=$hostName; name='credential_guard'; value=@{running=(@($guard.SecurityServicesRunning) -contains 1); configured=(@($guard.SecurityServicesConfigured) -contains 1)}; source='Win32_DeviceGuard'; collected_at=$collectedAt}
} catch { $errors += @{target=$hostName; name='credential_guard'; error='Runtime protection state unavailable'} }
try {
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $ppl = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Wininit'; Id=12; StartTime=$boot} -MaxEvents 1)
    if ($ppl.Count -gt 0) {
        $observations += @{target=$hostName; name='lsa_protection'; value=@{running=$true}; source='Wininit event 12 after current boot'; collected_at=$collectedAt}
    }
} catch { $errors += @{target=$hostName; name='lsa_protection'; error='Current-boot protected-process evidence unavailable'} }
try {
    $admins = Get-LocalGroup -SID 'S-1-5-32-544' | Get-LocalGroupMember
    foreach ($admin in $admins) {
        $observations += @{target=$hostName; name='local_administrator'; value=@{principal_sid=[string]$admin.SID}; source='Local Administrators SID S-1-5-32-544'; collected_at=$collectedAt}
    }
} catch { $errors += @{target=$hostName; name='local_administrator'; error='Local group inventory unavailable'} }
try {
    $sessions = @(Get-CimInstance Win32_LogonSession | Where-Object { $_.LogonType -in @(2,10) } | Select-Object -First 100)
    foreach ($session in $sessions) {
        foreach ($account in @(Get-CimAssociatedInstance -InputObject $session -Association Win32_LoggedOnUser)) {
            if ($account.SID) {
                $observations += @{target=$hostName; name='privileged_session'; value=@{principal_sid=[string]$account.SID; logon_type=$session.LogonType}; source='Win32_LoggedOnUser'; collected_at=$collectedAt}
            }
        }
    }
} catch { $errors += @{target=$hostName; name='privileged_session'; error='Interactive session inventory unavailable'} }
try {
    # GUIDs make audit evidence independent of the Windows display language.
    $audit = @{}
    $auditRows = @(& auditpol.exe /get /subcategory:* /r)
    if ($LASTEXITCODE -ne 0) { throw 'auditpol failed' }
    foreach ($row in ($auditRows | ConvertFrom-Csv)) {
        $fields = @($row.PSObject.Properties | ForEach-Object { $_.Value })
        $guid = $fields | Where-Object { $_ -match '^\{[0-9a-fA-F-]{36}\}$' } | Select-Object -First 1
        # Setting Value is the last machine-readable column (0..3).
        $number = 0
        if ($guid -and [int]::TryParse($fields[-1], [ref]$number) -and $number -in @(0,1,2,3)) { $audit[$guid.Trim('{}').ToLowerInvariant()] = $number }
    }
    $required = @('0cce923b-69ae-11d9-bed3-505054503030','0cce923c-69ae-11d9-bed3-505054503030','0cce9237-69ae-11d9-bed3-505054503030','0cce9240-69ae-11d9-bed3-505054503030','0cce9242-69ae-11d9-bed3-505054503030')
    $requiredFlags = @{'0cce923c-69ae-11d9-bed3-505054503030'=1}
    $observations += @{target=$hostName; name='advanced_audit_policy'; value=@{subcategories=$audit; required_subcategories=$required; required_flags=$requiredFlags}; source='auditpol /get /subcategory:* /r'; collected_at=$collectedAt}
} catch { $errors += @{target=$hostName; name='advanced_audit_policy'; error='Effective audit policy unavailable'} }
try {
    $config = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    $ca = Get-ItemPropertyValue -LiteralPath $config -Name Active
    $caPath = Join-Path $config $ca
    $security = Get-ItemPropertyValue -LiteralPath $caPath -Name Security
    $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($security, 0)
    $grants = @()
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        $grants += @{sid=[string]$ace.SecurityIdentifier; mask=[int]$ace.AccessMask; denied=($ace.AceQualifier -eq 'AccessDenied'); conditional=$ace.IsCallback}
    }
    # Authorized CA managers must be supplied by the PKI owner, never inferred.
    $observations += @{target=$hostName; name='adcs_ca_permissions'; value=@{grants=$grants; complete=$true; dacl_present=(($descriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -ne 0); approved_trustees=@()}; source=$caPath; collected_at=$collectedAt}
    $flags = Get-ItemPropertyValue -LiteralPath $caPath -Name InterfaceFlags
    $observations += @{target=$hostName; name='adcs_rpc_signing'; value=(($flags -band 512) -eq 512); source=$caPath; collected_at=$collectedAt}
    $roles = Get-ItemPropertyValue -LiteralPath $caPath -Name RoleSeparationEnabled
    $observations += @{target=$hostName; name='adcs_role_separation'; value=($roles -eq 1); source=$caPath; collected_at=$collectedAt}
} catch { $errors += @{target=$hostName; name='adcs_configuration'; error='CA configuration unavailable or not applicable'} }
try {
    Import-Module WebAdministration -ErrorAction Stop
    $epa = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location 'Default Web Site/certsrv' -Filter 'system.webServer/security/authentication/windowsAuthentication/extendedProtection' -Name tokenChecking
    $observations += @{target=$hostName; name='adcs_epa'; value=([string]$epa.Value -eq 'Require'); source='IIS certsrv extendedProtection tokenChecking'; collected_at=$collectedAt}
} catch { $errors += @{target=$hostName; name='adcs_epa'; error='Enrollment endpoint EPA unavailable or not applicable'} }
foreach ($serviceName in @('Spooler', 'WebClient', 'Dfs')) {
    try {
        $service = Get-Service -Name $serviceName
        $observations += @{target=$hostName; name='service'; value=@{name=$service.Name; status=[string]$service.Status}; source='Get-Service'; collected_at=$collectedAt}
    } catch { $errors += @{target=$hostName; name=$serviceName; error='Service absent or not readable'} }
}
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $observations += @{target=$hostName; name='operating_system'; value=@{caption=$os.Caption; version=$os.Version; build=$os.BuildNumber}; source='Win32_OperatingSystem'; collected_at=$collectedAt}
    $updates = @(Get-HotFix | Select-Object HotFixID, InstalledOn)
    $observations += @{target=$hostName; name='installed_updates'; value=$updates; source='Get-HotFix (partial update inventory)'; collected_at=$collectedAt}
} catch { $errors += @{target=$hostName; name='system_inventory'; error=$_.Exception.Message} }
$rsopPath = [IO.Path]::GetFullPath($OutputPath) + '.rsop.xml'
try {
    & gpresult.exe /scope computer /x $rsopPath /f 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'gpresult could not export the computer policy' }
    $observations += @{target=$hostName; name='resultant_policy'; value=$rsopPath; source='gpresult /scope computer /x'; collected_at=$collectedAt}
} catch { $errors += @{target=$hostName; name='resultant_policy'; error=$_.Exception.Message} }
# Observations are inputs to a review, not automatic proof of CVE exploitability.
foreach ($observation in $observations) { $observation.domain = $manifest.domain }
$document = @{schema_version=1; domain=$manifest.domain; reviews=@(); exceptions=@(); observations=$observations; collection_errors=$errors; posture_values=$values}
$json = $document | ConvertTo-Json -Depth 12
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath), $json, (New-Object Text.UTF8Encoding($false)))
Write-Output "AtilKurt evidence saved: $OutputPath ($($observations.Count) observations, $($errors.Count) unavailable checks)"
"""

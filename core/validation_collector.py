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
    $hostName = $system.DNSHostName
} catch {
    throw "Cannot establish the evidence target: $($_.Exception.Message)"
}
$registryChecks = @(
    @{name='LDAPServerIntegrity'; path='HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'},
    @{name='LdapEnforceChannelBinding'; path='HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'},
    @{name='RestrictNTLMInDomain'; path='HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'},
    @{name='RequireSecuritySignature'; path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'},
    @{name='DefaultDomainSupportedEncTypes'; path='HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'},
    @{name='CertificateMappingMethods'; path='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel'},
    @{name='LAPSBackupDirectory'; property='BackupDirectory'; path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'},
    @{name='LAPSPasswordEncryptionEnabled'; property='ADPasswordEncryptionEnabled'; path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'}
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
$document = @{schema_version=1; domain=$manifest.domain; reviews=@(); exceptions=@(); observations=$observations; collection_errors=$errors; posture_values=$values}
$json = $document | ConvertTo-Json -Depth 12
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath), $json, (New-Object Text.UTF8Encoding($false)))
Write-Output "AtilKurt evidence saved: $OutputPath ($($observations.Count) observations, $($errors.Count) unavailable checks)"
"""

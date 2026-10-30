param([Parameter(Mandatory)][string]$ManifestFile)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$ticket=Get-Content -LiteralPath $ManifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
if($ticket.purpose -ne 'verify_deployment'){throw 'Verification-only authorization required'}
. (Join-Path $PSScriptRoot 'Get-DeploymentState.ps1')
$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
$rebootObserved=$false
if($ticket.state -eq 'REBOOT_REQUIRED'){
    if(-not $ticket.previous_boot_time){@{state='UNKNOWN';verified=$false;details=@{reason='missing_pre_reboot_observation'}} | ConvertTo-Json -Depth 5 -Compress;exit 0}
    $rebootObserved=[datetime]$boot -gt [datetime]$ticket.previous_boot_time
    if(-not $rebootObserved){@{state='WAITING';verified=$false;details=@{reason='reboot_not_observed'}} | ConvertTo-Json -Depth 5 -Compress;exit 0}
}
$actual=Get-SuroInstalledState $ticket.manifest
$state=if($actual.matches){'SUCCEEDED'}elseif(-not $actual.known){'UNKNOWN'}else{'WAITING'}
@{state=$state;verified=[bool]$actual.matches;details=@{version=$actual.version;boot_time=$boot;reboot_observed=$rebootObserved;source='windows_readback'}} | ConvertTo-Json -Depth 5 -Compress

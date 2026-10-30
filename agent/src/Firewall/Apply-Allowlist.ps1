param([Parameter(Mandatory)][string]$ManifestFile)
$ErrorActionPreference='Stop'
$m=Get-Content -LiteralPath $ManifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
$root="$env:ProgramData\Lantern"
$p=Get-Content "$root\policy.document.json" -Raw | ConvertFrom-Json
$management=[uri]$m.server
$managementIPs=@([System.Net.Dns]::GetHostAddresses($management.Host) | ForEach-Object IPAddressToString)
if(-not $managementIPs.Count){throw 'Management address cannot be resolved'}
foreach($ip in $managementIPs){
    $explicit=@($p.firewall_allowances | Where-Object { $_.protocol -eq 'TCP' -and $management.Port -in $_.ports -and ($_.remote -eq "$ip/32" -or $_.remote -eq "$ip/128") })
    if(-not $explicit.Count){throw 'Policy must explicitly allow the management server literal address and HTTPS port'}
}
# The kursant startup task resets the firewall at every boot; applying now would last only until restart.
$kursant=Get-ScheduledTask -TaskPath '\Custom Tasks\' -TaskName 'Running_kursant_script_at_every_startup' -ErrorAction SilentlyContinue
if($kursant -and [string]$kursant.State -ne 'Disabled'){throw 'Retire the legacy kursant startup task first'}
# Only these exact legacy rules may be migrated, and only with explicit approval; they are disabled, not deleted.
$legacyNames='^Allow outbound to (192\.168\.0\.1|10\.47\.47\.47|10\.47\.47\.74)$'
$outbound=@(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Enabled True -Action Allow | Where-Object Group -ne 'LanternPolicy')
$legacyRules=@(if($m.replace_legacy_rules){$outbound | Where-Object { $_.DisplayName -match $legacyNames -and $_.PolicyStoreSourceType -eq 'Local' }})
$conflicts=@($outbound | Where-Object { $_.Name -notin $legacyRules.Name })
if($conflicts.Count){throw 'Existing outbound allow rules require a reviewed migration; no manual rules have been removed'}
$backup="$root\firewall-$($m.job_id).wfw"
& "$env:SystemRoot\System32\netsh.exe" advfirewall export $backup | Out-Null
if($LASTEXITCODE -ne 0){throw 'Firewall backup failed'}
# Out-of-process recovery restores the full pre-change firewall if management cannot be verified.
$rollback=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\netsh.exe" -Argument "advfirewall import `"$backup`""
$trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(3)
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest -LogonType ServiceAccount
$taskName="LanternFirewallRollback-$($m.job_id)"
Register-ScheduledTask -TaskName $taskName -Action $rollback -Trigger $trigger -Principal $principal -Force | Out-Null
try{
    Get-NetFirewallRule -Group LanternPolicy -ErrorAction SilentlyContinue | Where-Object Name -like 'LanternPolicy-*' | Remove-NetFirewallRule
    $index=0
    foreach($allowance in $p.firewall_allowances){
        $index++;$name="LanternPolicy-$index"
        if(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue){Remove-NetFirewallRule -Name $name}
        $params=@{Name=$name;DisplayName=$name;Group='LanternPolicy';Direction='Outbound';Action='Allow';RemoteAddress=$allowance.remote;Protocol=$allowance.protocol;Profile='Any'}
        if($allowance.protocol -in @('TCP','UDP')){$params.RemotePort=@($allowance.ports)}
        New-NetFirewallRule @params | Out-Null
    }
    # Preserve DHCP for IPv4 and IPv6, plus necessary IPv6 neighbor discovery. No public DNS exception.
    foreach($rule in @(
        @{Name='LanternDHCPv4';Protocol='UDP';LocalPort=68;RemotePort=67;RemoteAddress=@('LocalSubnet','255.255.255.255')},
        @{Name='LanternDHCPv6';Protocol='UDP';LocalPort=546;RemotePort=547;RemoteAddress=@('fe80::/10','ff02::1:2')}
    )){
        if(-not(Get-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue)){
            New-NetFirewallRule @rule -DisplayName $rule.Name -Group LanternPolicy -Direction Outbound -Action Allow -Profile Any | Out-Null
        }
    }
    foreach($type in @(133,135,136)){
        $name="LanternNDP-$type"
        if(-not(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue)){New-NetFirewallRule -Name $name -DisplayName $name -Group LanternPolicy -Direction Outbound -Action Allow -Protocol ICMPv6 -IcmpType $type -RemoteAddress 'fe80::/10','ff02::/16' -Profile Any | Out-Null}
    }
    foreach($rule in $legacyRules){Disable-NetFirewallRule -Name $rule.Name}
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
    # Verify live HTTPS connectivity using system trust; unsigned agent requests must return 401.
    $reachable=$false
    $probe=[System.Net.HttpWebRequest]::Create("$($m.server.TrimEnd('/'))/api/v1/agent/policy")
    $probe.Timeout=20000
    try{$r=$probe.GetResponse();$reachable=$true;$r.Close()}
    catch [System.Net.WebException]{if($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401){$reachable=$true}}
    if(-not $reachable){throw 'Management TLS connectivity could not be verified'}
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}catch{
    $failure=$_
    & "$env:SystemRoot\System32\netsh.exe" advfirewall import $backup | Out-Null
    if($LASTEXITCODE -eq 0){Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue}
    throw $failure
}
@{state='SUCCEEDED';details=@{backup=$backup;management_tls_verified=$true;legacy_rules_disabled=@($legacyRules.DisplayName);effective_rule_verification_required=$true}} | ConvertTo-Json -Compress

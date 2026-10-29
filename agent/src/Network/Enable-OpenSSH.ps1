param([Parameter(Mandatory)][string]$ManifestFile)
$ErrorActionPreference='Stop'
$m=Get-Content -LiteralPath $ManifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
$capability=Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
if($capability.State -ne 'Installed'){throw 'Install the matching offline Windows OpenSSH capability source first'}
if($m.admin_account -notmatch '^[A-Za-z][A-Za-z0-9_-]{0,19}$' -or $m.public_key -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]+( .*)?$'){throw 'Invalid SSH identity'}
$management=[uri]$m.server
$addresses=@([System.Net.Dns]::GetHostAddresses($management.Host) | ForEach-Object IPAddressToString)
if(-not $addresses.Count){throw 'Cannot resolve management infrastructure'}
$rules=@(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow)
foreach($rule in $rules){
    $ports=$rule | Get-NetFirewallPortFilter
    if($ports.Protocol -eq 'TCP' -and '22' -in $ports.LocalPort -and $rule.Name -ne 'LanternSSH'){
        if($rule.Name -eq 'OpenSSH-Server-In-TCP' -and $m.approve_disable_default_ssh_rule){Disable-NetFirewallRule -Name $rule.Name}
        else {throw 'Existing SSH inbound rule must be reviewed before enabling restricted SSH'}
    }
}
$config="$env:ProgramData\ssh\sshd_config"
if(-not(Test-Path $config)){Copy-Item "$env:SystemRoot\System32\OpenSSH\sshd_config_default" $config}
$original=Get-Content -LiteralPath $config -Raw
$backup="$config.lantern-$($m.job_id).bak"
Copy-Item -LiteralPath $config -Destination $backup
# Replace only explicitly managed global directives; preserve unrelated configuration and Match blocks.
$lines=$original -split '\r?\n'; $result=New-Object 'System.Collections.Generic.List[string]'; $inMatch=$false
foreach($line in $lines){
    if($line -match '^\s*Match\s'){$inMatch=$true}
    if(-not $inMatch -and $line -match '^\s*(PasswordAuthentication|PubkeyAuthentication|AllowUsers)\s'){
        if($line -match '^\s*AllowUsers\s' -and $line -notmatch "\b$([regex]::Escape($m.admin_account))\b"){throw 'Existing AllowUsers directive requires an explicit migration review'}
        continue
    }
    $result.Add($line)
}
$prefix=@('PasswordAuthentication no','PubkeyAuthentication yes',"AllowUsers $($m.admin_account)")
($prefix + $result) | Set-Content -LiteralPath $config -Encoding ASCII
& "$env:SystemRoot\System32\OpenSSH\sshd.exe" -t -f $config
if($LASTEXITCODE -ne 0){Copy-Item -LiteralPath $backup -Destination $config -Force;throw 'SSH configuration validation failed; restored previous configuration'}
$authorized="$env:ProgramData\ssh\administrators_authorized_keys"
if(Test-Path $authorized){Copy-Item $authorized "$authorized.lantern-$($m.job_id).bak"}
$keys=if(Test-Path $authorized){@(Get-Content $authorized)}else{@()}
if($m.public_key -notin $keys){Add-Content -LiteralPath $authorized -Value $m.public_key -Encoding ASCII}
& icacls.exe $authorized '/inheritance:r' '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
if($LASTEXITCODE -ne 0){throw 'Could not protect authorized SSH keys'}
if(Get-NetFirewallRule -Name LanternSSH -ErrorAction SilentlyContinue){Remove-NetFirewallRule -Name LanternSSH}
New-NetFirewallRule -Name LanternSSH -DisplayName 'Lantern management SSH' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -RemoteAddress $addresses -Profile Any | Out-Null
Set-Service sshd -StartupType Automatic
Restart-Service sshd
@{state='SUCCEEDED';details=@{service_running=((Get-Service sshd).Status -eq 'Running');management_addresses=$addresses;host_keys=@(Get-Content "$env:ProgramData\ssh\ssh_host_*_key.pub")}} | ConvertTo-Json -Depth 5 -Compress

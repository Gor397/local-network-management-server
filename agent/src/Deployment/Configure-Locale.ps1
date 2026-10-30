param([Parameter(Mandatory)][string]$ManifestFile)
$ErrorActionPreference='Stop'
$m=Get-Content -LiteralPath $ManifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
if($m.language -notmatch '^[a-z]{2,3}-[A-Za-z]{2,8}$' -or $m.user_account -notmatch '^[A-Za-z][A-Za-z0-9_-]{0,19}$'){throw 'Invalid locale request'}
$culture=[Globalization.CultureInfo]::GetCultureInfo($m.language)
# Display-language resources must already have been installed by an approved offline package.
if(-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\MUI\UILanguages\$($m.language)")){throw 'Required Windows display-language resources are not installed'}
$user=Get-LocalUser -Name $m.user_account
$layouts=@($m.keyboard_layouts | Where-Object {$_})
foreach($layout in $layouts){if($layout -notmatch '^[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}$' -or -not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\$($layout.Split(':')[1])")){throw 'Requested keyboard layout is unavailable'}}
$layoutArgument=if($layouts.Count){' -KeyboardLayouts '+($layouts -join ',')}else{''}
$root="$env:ProgramData\Lantern"
$userScript=Join-Path $root "locale-$($m.job_id).ps1"
# Use the shipped, Authenticode-signed script; parameters are passed as validated arguments.
$script=Join-Path $PSScriptRoot 'Apply-UserLocale.ps1'
$action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -ExecutionPolicy AllSigned -File `"$script`" -Language $($m.language)$layoutArgument"
$trigger=New-ScheduledTaskTrigger -AtLogOn -User $user.Name
$principal=New-ScheduledTaskPrincipal -UserId $user.SID.Value -LogonType Interactive -RunLevel Limited
$taskName="LanternLocale-$($m.job_id)"
# Standard users need read/execute on this single signed script, not the protected agent directory.
$publicScript="$env:ProgramData\LanternLocale-$($m.job_id).ps1"
Copy-Item -LiteralPath $script -Destination $publicScript
& icacls.exe $publicScript '/inheritance:r' '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' "*$($user.SID.Value):RX" | Out-Null
if($LASTEXITCODE -ne 0){throw 'Failed to grant target user read access to locale script'}
$action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -ExecutionPolicy AllSigned -File `"$publicScript`" -Language $($m.language)$layoutArgument"
# A later approved locale supersedes older Suro locale tasks for this same user.
Get-ScheduledTask -TaskName 'LanternLocale-*' -ErrorAction SilentlyContinue | Where-Object {$_.Principal.UserId -in @($user.Name,$user.SID.Value)} | ForEach-Object {Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false}
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Set-WinSystemLocale -SystemLocale $culture.Name
@{state='PENDING_USER_LOGON';details=@{language=$culture.Name;user_sid=$user.SID.Value;keyboard_layouts=$layouts;task=$taskName;sign_out_required=$true}} | ConvertTo-Json -Compress

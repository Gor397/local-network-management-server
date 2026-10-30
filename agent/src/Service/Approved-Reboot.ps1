param([Parameter(Mandatory)][string]$ManifestFile)
$ErrorActionPreference='Stop'
$m=Get-Content -LiteralPath $ManifestFile -Raw | ConvertFrom-Json
if($m.operation -ne 'system.reboot'){throw 'Explicit reboot authorization required'}
if((Get-CimInstance Win32_ComputerSystem).UserName){throw 'Interactive user is logged on; graceful reboot requires a later maintenance window'}
$action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\shutdown.exe" -Argument '/r /t 0 /d p:4:1'
$trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2)
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "LanternReboot-$($m.job_id)" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
@{state='REBOOT_REQUIRED';details=@{boot_time=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');scheduled=$true;delay_seconds=120;force_close_apps=$false}} | ConvertTo-Json -Compress

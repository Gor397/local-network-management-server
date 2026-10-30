# Opens the Suro registration window for the signed-in user right after onboarding; runs as SYSTEM.
$ErrorActionPreference = 'Stop'
$interactive = (Get-CimInstance Win32_ComputerSystem).UserName
if (-not $interactive) { exit 0 }  # Nobody signed in: the HKLM Run entry opens it at the next sign-in.
$ui = Join-Path (Split-Path -Parent $PSScriptRoot) 'IdentityUI\SuroIdentity.exe'
$action = New-ScheduledTaskAction -Execute $ui
$principal = New-ScheduledTaskPrincipal -UserId $interactive -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName SuroIdentificationInitial -Action $action -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName SuroIdentificationInitial

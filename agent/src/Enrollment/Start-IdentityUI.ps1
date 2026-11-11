# Opens the Suro registration window for the signed-in user right after onboarding; runs as SYSTEM.
$ErrorActionPreference = 'Stop'
$interactive = (Get-CimInstance Win32_ComputerSystem).UserName
if (-not $interactive) { exit 0 }  # Nobody signed in: the HKLM Run entry opens it at the next sign-in.
$installation = Split-Path -Parent $PSScriptRoot
# SuroSetup.exe installs the window next to the agent (shared runtime); the older MSI layout uses IdentityUI\.
$ui = @((Join-Path $installation 'SuroIdentity.exe'), (Join-Path $installation 'IdentityUI\SuroIdentity.exe')) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $ui) { throw 'Identity window is not installed' }
$action = New-ScheduledTaskAction -Execute $ui
$principal = New-ScheduledTaskPrincipal -UserId $interactive -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName SuroIdentificationInitial -Action $action -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName SuroIdentificationInitial

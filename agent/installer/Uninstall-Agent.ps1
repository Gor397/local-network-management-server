#Requires -RunAsAdministrator
param([Parameter(Mandatory)][ValidatePattern('^\{[A-Fa-f0-9-]{36}\}$')][string]$ProductCode)
$ErrorActionPreference='Stop'
Write-Warning 'Revoke the device certificate and network authorization in the dashboard first. Local evidence and identity are retained for recovery.'
Stop-Service LocalNetworkPolicyAgent -ErrorAction SilentlyContinue
$process=Start-Process "$env:SystemRoot\System32\msiexec.exe" -ArgumentList @('/x',$ProductCode,'/qn','/norestart') -Wait -PassThru
if($process.ExitCode -notin @(0,3010)){throw "Uninstall failed: $($process.ExitCode)"}
Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SuroIdentification -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName SuroIdentificationInitial -Confirm:$false -ErrorAction SilentlyContinue

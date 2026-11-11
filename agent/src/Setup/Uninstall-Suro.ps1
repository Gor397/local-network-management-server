# Removes the Suro Client installed by SuroSetup.exe: service, sign-in entry, uninstall entry and program files.
# The device identity in %ProgramData%\Lantern is kept on purpose: revoke it in the dashboard (Reset enrollment)
# when the computer leaves management. Removing the client of a computer that must run it restricts its network.
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Opened from Settings > Apps without elevation: ask for administrator rights once.
    Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    exit
}
$installation = Split-Path -Parent $PSScriptRoot
if ((Split-Path -Leaf $installation) -ne 'Lantern Policy Agent') { throw 'Unexpected installation folder' }
Stop-Service LocalNetworkPolicyAgent -ErrorAction SilentlyContinue
& "$env:SystemRoot\System32\sc.exe" delete LocalNetworkPolicyAgent | Out-Null
Get-Process SuroIdentity -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SuroIdentification -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName SuroIdentificationInitial -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SuroClient' -Recurse -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $env:ProgramData 'Lantern\install-manifest.json') -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Remove-Item -LiteralPath $installation -Recurse -Force

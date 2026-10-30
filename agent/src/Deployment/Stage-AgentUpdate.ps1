param([Parameter(Mandatory)][string]$ManifestFile, [Parameter(Mandatory)][string]$PackageFile)
$ErrorActionPreference = 'Stop'
$m = Get-Content -LiteralPath $ManifestFile -Raw | ConvertFrom-Json
if ($m.kind -ne 'agent_update' -or [IO.Path]::GetExtension($PackageFile) -ne '.msi') { throw 'Signed MSI update required' }
if ((Get-FileHash -LiteralPath $PackageFile -Algorithm SHA256).Hash -ne $m.sha256) { throw 'Hash mismatch' }
$signature = Get-AuthenticodeSignature -LiteralPath $PackageFile
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $m.publisher_thumbprint) { throw 'Untrusted update publisher' }
$config = Get-Content "$env:ProgramData\Lantern\config.json" -Raw | ConvertFrom-Json
if ($m.publisher_thumbprint -ne $config.agent_publisher_thumbprint) { throw 'Agent update signer must match pinned publisher' }
if(-not $m.metadata.expected_version){throw 'Expected agent version required'}
$build=[int](Get-CimInstance Win32_OperatingSystem).BuildNumber
$arch=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
if($build -lt $m.metadata.minimum_build -or $build -gt $m.metadata.maximum_build -or $arch -ne $m.metadata.architecture){throw 'Incompatible agent update'}
$current=(Get-Item (Join-Path $env:ProgramFiles 'Lantern Policy Agent\NetworkPolicyClient.exe')).VersionInfo.FileVersion
if([version]$m.metadata.expected_version -lt [version]$current){throw 'Agent downgrade requires the documented recovery procedure'}

$script=Join-Path $PSScriptRoot 'Complete-AgentUpdate.ps1'
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy AllSigned -File `"$script`" -ManifestFile `"$ManifestFile`" -PackageFile `"$PackageFile`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest -LogonType ServiceAccount
Register-ScheduledTask -TaskName 'LanternApprovedAgentUpdate' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
# Completion must be checked after restart; staging is never reported as a verified update.
@{state='AWAITING_RESTART';exit_code=0;verified=$false;details=@{boot_time=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')}} | ConvertTo-Json -Depth 5 -Compress

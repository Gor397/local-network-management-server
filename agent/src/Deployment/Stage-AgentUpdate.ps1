param([Parameter(Mandatory)][string]$ManifestFile, [Parameter(Mandatory)][string]$PackageFile)
$ErrorActionPreference = 'Stop'
$m = Get-Content -LiteralPath $ManifestFile -Raw | ConvertFrom-Json
if ($m.kind -ne 'agent_update' -or [IO.Path]::GetExtension($PackageFile) -ne '.msi') { throw 'Signed MSI update required' }
if ((Get-FileHash -LiteralPath $PackageFile -Algorithm SHA256).Hash -ne $m.sha256) { throw 'Hash mismatch' }
$signature = Get-AuthenticodeSignature -LiteralPath $PackageFile
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $m.publisher_thumbprint) { throw 'Untrusted update publisher' }
$config = Get-Content "$env:ProgramData\Lantern\config.json" -Raw | ConvertFrom-Json
if ($m.publisher_thumbprint -ne $config.agent_publisher_thumbprint) { throw 'Agent update signer must match pinned publisher' }
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\msiexec.exe" -Argument "/i `"$PackageFile`" /qn /norestart /l*v `"$ManifestFile.update.log`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest -LogonType ServiceAccount
Register-ScheduledTask -TaskName 'LanternApprovedAgentUpdate' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
# Completion must be checked after restart; staging is never reported as a verified update.
@{state='UNKNOWN';exit_code=0;verified=$false} | ConvertTo-Json -Compress

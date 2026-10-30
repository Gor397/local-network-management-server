param([Parameter(Mandatory)][string]$ManifestFile,[Parameter(Mandatory)][string]$PackageFile)
$ErrorActionPreference='Stop'
$m=Get-Content -LiteralPath $ManifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
if($m.kind -ne 'agent_update' -or $m.task_id -notmatch '^[0-9a-fA-F-]{36}$'){throw 'Invalid update authorization'}
$config=Get-Content "$env:ProgramData\Lantern\config.json" -Raw | ConvertFrom-Json
if((Get-FileHash -LiteralPath $PackageFile -Algorithm SHA256).Hash -ne $m.sha256){throw 'Update integrity failure'}
$signature=Get-AuthenticodeSignature -LiteralPath $PackageFile
if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $config.agent_publisher_thumbprint -or $m.publisher_thumbprint -ne $config.agent_publisher_thumbprint){throw 'Untrusted update publisher'}
$code=$null
try {
    $process=Start-Process "$env:SystemRoot\System32\msiexec.exe" -ArgumentList @('/i',"`"$PackageFile`"",'/qn','/norestart','/l*v',"`"$ManifestFile.update.log`"") -Wait -PassThru
    $code=$process.ExitCode
} finally {
    @{exit_code=$code;finished_at=[datetime]::UtcNow.ToString('o')} | ConvertTo-Json -Compress | Set-Content -LiteralPath "$ManifestFile.receipt.json" -Encoding UTF8
    # The service must resume even after a rejected/failed upgrade. The old MSI remains available for an approved rollback.
    Start-Service LocalNetworkPolicyAgent -ErrorAction Continue
}

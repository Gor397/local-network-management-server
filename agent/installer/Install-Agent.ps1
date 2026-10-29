#Requires -RunAsAdministrator
param([Parameter(Mandatory)][string]$MsiPath, [Parameter(Mandatory)][string]$ProvisioningFile)
$ErrorActionPreference = 'Stop'
$os = Get-CimInstance Win32_OperatingSystem
if ([int]$os.BuildNumber -lt 22000 -or -not [Environment]::Is64BitOperatingSystem) { throw 'A supported 64-bit Windows 11 installation is required' }
$provision = Get-Content -LiteralPath $ProvisioningFile -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $provision.token -or -not $provision.agent_publisher_thumbprint -or -not $provision.signing_public_key) { throw 'Incomplete provisioning file' }
if (([uri]$provision.server).Scheme -ne 'https') { throw 'HTTPS required' }
$signature = Get-AuthenticodeSignature -LiteralPath $MsiPath
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $provision.agent_publisher_thumbprint) { throw 'Installer publisher does not match trusted provisioning data' }
$root = "$env:ProgramData\Lantern"
New-Item -ItemType Directory -Path $root -Force | Out-Null
& icacls.exe $root '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to protect agent state' }
if (Test-Path "$root\config.json") { throw 'Existing identity preserved. Use MSI upgrade and documented re-enrollment instead.' }
$config = @{ server=$provision.server; primary_mac=$provision.primary_mac; signing_public_key=$provision.signing_public_key; agent_publisher_thumbprint=$provision.agent_publisher_thumbprint; poll_seconds=120 }
$config | ConvertTo-Json -Depth 5 | Set-Content "$root\config.json" -Encoding UTF8
$provision.token | Set-Content "$root\enrollment.token" -Encoding ASCII
$process = Start-Process "$env:SystemRoot\System32\msiexec.exe" -ArgumentList @('/i',"`"$MsiPath`"",'/qn','/norestart') -Wait -PassThru
if ($process.ExitCode -notin @(0,3010)) { throw "MSI installation failed: $($process.ExitCode)" }
$installation = "$env:ProgramFiles\Lantern Policy Agent"
& icacls.exe $installation '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to protect installed files' }
# SCM permissions: only SYSTEM and Administrators can modify or stop the service.
& sc.exe sdset LocalNetworkPolicyAgent 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to protect service configuration' }
& sc.exe failure LocalNetworkPolicyAgent 'reset=' '86400' 'actions=' 'restart/60000/restart/120000/restart/300000' | Out-Null
& "$installation\NetworkPolicyClient.exe" --enroll
if ($LASTEXITCODE -ne 0) { throw 'Enrollment failed. Protected token retained for retry until it expires.' }
Start-Service LocalNetworkPolicyAgent
Write-Output 'Enrolled in Audit Mode. Securely remove the original provisioning file.'

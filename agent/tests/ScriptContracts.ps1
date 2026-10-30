$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\src\Deployment\Get-DeploymentState.ps1')
$script:passed=0
function Assert-Suro($Condition,[string]$Name){if(-not $Condition){throw $Name};$script:passed++;Write-Output "PASS $Name"}
Assert-Suro (Test-SuroVersion '0.2.0.0' '0.2.0') 'Version normalization accepts matching Windows file versions'
Assert-Suro (-not(Test-SuroVersion '0.1.0.0' '0.2.0')) 'An old version cannot verify a requested update'
# Mock Windows read-only inventory commands. This script never invokes an installer or changes settings.
function Join-Path {param($Path,$ChildPath) return "$Path\$ChildPath"}
function Test-Path {param($LiteralPath) return $true}
function Get-ItemProperty {param($LiteralPath,$Name) return @{DisplayVersion='2.3.4'}}
function Get-WindowsOptionalFeature {param([switch]$Online,$FeatureName) return @{State='Enabled'}}
function Get-WindowsDriver {param([switch]$Online,[switch]$All) return @(@{OriginalFileName='approved.inf';Version='2.3.4'})}
$m=[pscustomobject]@{kind='msi';action='update';metadata=[pscustomobject]@{product_code='{12345678-1234-1234-1234-123456789ABC}';expected_version='2.3.4'}}
Assert-Suro ((Get-SuroInstalledState $m).matches) 'Registry product and requested version are read back'
$m.metadata.expected_version='9.0'
Assert-Suro (-not(Get-SuroInstalledState $m).matches) 'Product presence alone cannot verify a different requested version'
$m=[pscustomobject]@{kind='script';action='install';metadata=[pscustomobject]@{}}
Assert-Suro (-not(Get-SuroInstalledState $m).known) 'A script exit code alone has no installation detector'
$m=[pscustomobject]@{kind='driver';action='install';metadata=[pscustomobject]@{driver_original_inf='approved.inf';expected_version='2.3.4'}}
Assert-Suro ((Get-SuroInstalledState $m).matches) 'Driver inventory and version verify the selected package'
Write-Output "$script:passed readback contracts passed; Windows installation and behavior still need VM testing."

param([Parameter(Mandatory)][string]$ManifestFile, [Parameter(Mandatory)][string]$PackageFile)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$m = Get-Content -LiteralPath $ManifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
if ((Get-FileHash -LiteralPath $PackageFile -Algorithm SHA256).Hash -ne $m.sha256) { throw 'Package hash mismatch' }
$sig = Get-AuthenticodeSignature -LiteralPath $PackageFile
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne $m.publisher_thumbprint) { throw 'Untrusted publisher or invalid signature' }
$build = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
if ($build -lt $m.metadata.minimum_build -or $build -gt $m.metadata.maximum_build) { throw 'Windows build is incompatible' }
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
if ($arch -ne $m.metadata.architecture) { throw 'Architecture is incompatible' }
. (Join-Path $PSScriptRoot 'Get-DeploymentState.ps1')
$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
$product = $m.metadata.product_code
function ProductInstalled {
    if (-not $product) { return $false }
    return ((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$product") -or (Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$product"))
}
if ($m.action -eq 'install' -and (Get-SuroInstalledState $m).matches) { @{state='SKIPPED';exit_code=0;verified=$true} | ConvertTo-Json -Compress; exit 0 }
$windows = $env:SystemRoot
$exitCode = 0
$verified = $false
function Execute([string]$exe, [string[]]$arguments) {
    # Fixed trusted executables and approved installers, no shell concatenation or Invoke-Expression.
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $exe; $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    # Windows PowerShell 5.1 lacks ArgumentList. Quote each token using Windows CRT escaping.
    $quoted = foreach ($arg in $arguments) { '"' + [regex]::Replace([regex]::Replace($arg, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"' }
    $info.Arguments = $quoted -join ' '
    $p = [System.Diagnostics.Process]::Start($info); $p.WaitForExit(); return $p.ExitCode
}
switch ($m.kind) {
    'msi' {
        $verb = if ($m.action -eq 'uninstall') {'/x'} else {'/i'}
        $target = if ($m.action -eq 'uninstall') {$product} else {$PackageFile}
        $exitCode = Execute "$windows\System32\msiexec.exe" @($verb,$target,'/qn','/norestart','/l*v',"$ManifestFile.install.log")
        $verified = if ($m.action -eq 'uninstall') {-not (ProductInstalled)} else {ProductInstalled}
    }
    'exe' {
        $exitCode = Execute $PackageFile @($m.arguments)
        $verified = if ($m.action -eq 'uninstall') {($product -and -not (ProductInstalled))} else {ProductInstalled}
    }
    'script' { $exitCode = Execute "$windows\System32\WindowsPowerShell\v1.0\powershell.exe" (@('-NoProfile','-NonInteractive','-ExecutionPolicy','AllSigned','-File',$PackageFile) + @($m.arguments)) }
    'msix' {
        if(-not $m.metadata.msix_name){throw 'MSIX name is required for detection and removal'}
        if ($m.action -eq 'uninstall') {
            Get-AppxPackage -AllUsers -Name $m.metadata.msix_name | ForEach-Object {Remove-AppxPackage -AllUsers -Package $_.PackageFullName}
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq $m.metadata.msix_name | ForEach-Object {Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName | Out-Null}
        }else{Add-AppxProvisionedPackage -Online -PackagePath $PackageFile -SkipLicense | Out-Null}
        # Provisioning is distinct from installation into every existing user profile.
    }
    'driver' {
        $expanded = "$ManifestFile.expanded"
        New-Item -Path $expanded -ItemType Directory -Force | Out-Null
        $listing = & "$windows\System32\expand.exe" '-D' $PackageFile
        if ($LASTEXITCODE -ne 0 -or ($listing -match '\.\.[\\/]')) { throw 'Invalid driver archive' }
        $exitCode = Execute "$windows\System32\expand.exe" @($PackageFile,'-F:*',$expanded)
        if ($exitCode -eq 0) { $exitCode = Execute "$windows\System32\pnputil.exe" @('/add-driver',"$expanded\*.inf",'/subdirs','/install') }
        # PnP matching enforces hardware compatibility; independent inventory readback remains required.
    }
    'windows_update' {
        if ([IO.Path]::GetExtension($PackageFile) -eq '.msu') { $exitCode = Execute "$windows\System32\wusa.exe" @($PackageFile,'/quiet','/norestart') }
        else { $exitCode = Execute "$windows\System32\dism.exe" @('/Online','/Add-Package',"/PackagePath:$PackageFile",'/Quiet','/NoRestart','/PreventPending') }
    }
    'language_pack' {
        $exitCode = Execute "$windows\System32\dism.exe" @('/Online','/Add-Package',"/PackagePath:$PackageFile",'/Quiet','/NoRestart')
        # User display language is separately changed in interactive user context, never SYSTEM's preferences.
    }
    'feature' {
        if (-not $m.metadata.feature_name -or $m.metadata.feature_name -notmatch '^[A-Za-z0-9_.-]+$') { throw 'Invalid feature name' }
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $m.metadata.feature_name
        if ($feature.State -eq 'Enabled') { @{state='SKIPPED';exit_code=0;verified=$true} | ConvertTo-Json -Compress; exit 0 }
        $exitCode = Execute "$windows\System32\dism.exe" @('/Online','/Enable-Feature',"/FeatureName:$($m.metadata.feature_name)","/Source:$([IO.Path]::GetDirectoryName($PackageFile))",'/LimitAccess','/All','/NoRestart')
        $verified = (Get-WindowsOptionalFeature -Online -FeatureName $m.metadata.feature_name).State -eq 'Enabled'
    }
    default { throw 'Unsupported deployment package kind' }
}
$detected=Get-SuroInstalledState $m
$verified=$detected.matches
$state = if ($exitCode -in @(3010,1641)) {'REBOOT_REQUIRED'} elseif ($exitCode -ne 0) {'FAILED'} elseif ($verified) {'SUCCEEDED'} else {'UNKNOWN'}
@{state=$state;exit_code=$exitCode;verified=[bool]$verified;details=@{boot_time=$boot;version=$detected.version;source='windows_readback'}} | ConvertTo-Json -Depth 5 -Compress

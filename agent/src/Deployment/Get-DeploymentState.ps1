# Read-only detection shared by installation and post-restart verification.
function Test-SuroVersion([string]$Actual,[string]$Expected) {
    if(-not $Expected){return $true}
    try {
        $a=[version]$Actual;$e=[version]$Expected
        return (@($a.Major,$a.Minor,[Math]::Max(0,$a.Build),[Math]::Max(0,$a.Revision)) -join '.') -eq (@($e.Major,$e.Minor,[Math]::Max(0,$e.Build),[Math]::Max(0,$e.Revision)) -join '.')
    }catch{return $false}
}
function Get-SuroInstalledState($Manifest) {
    $metadata=$Manifest.metadata;$present=$false;$version=$null;$known=$true
    switch($Manifest.kind){
        {$_ -in @('msi','exe','agent_update')} {
            if(-not $metadata.product_code){$known=$false;break}
            if($metadata.product_code -notmatch '^\{[0-9A-Fa-f-]{36}\}$'){throw 'Invalid product identifier'}
            foreach($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')){
                $path=Join-Path $root $metadata.product_code
                if(Test-Path -LiteralPath $path){$present=$true;$version=(Get-ItemProperty -LiteralPath $path).DisplayVersion;break}
            }
            if($Manifest.kind -eq 'agent_update' -and $present){
                $exe=Join-Path $env:ProgramFiles 'Lantern Policy Agent\NetworkPolicyClient.exe'
                $signature=Get-AuthenticodeSignature -LiteralPath $exe
                $present=$signature.Status -eq 'Valid' -and $signature.SignerCertificate.Thumbprint -eq $Manifest.publisher_thumbprint
                $version=(Get-Item -LiteralPath $exe).VersionInfo.FileVersion
            }
        }
        'feature' { $present=(Get-WindowsOptionalFeature -Online -FeatureName $metadata.feature_name).State -eq 'Enabled' }
        'msix' {
            if(-not $metadata.msix_name){$known=$false;break}
            if($metadata.msix_name -notmatch '^[A-Za-z0-9_.-]{1,128}$'){throw 'Invalid MSIX name'}
            $provisioned=@(Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq $metadata.msix_name)
            $registered=@(Get-AppxPackage -AllUsers -Name $metadata.msix_name)
            $present=if($Manifest.action -eq 'uninstall'){$registered.Count -gt 0 -or $provisioned.Count -gt 0}else{$provisioned.Count -gt 0}
            if($provisioned.Count){$version=[string]$provisioned[0].Version}
        }
        {$_ -in @('windows_update','language_pack')} {
            if(-not $metadata.package_identity){$known=$false;break}
            if($metadata.package_identity -notmatch '^[A-Za-z0-9_.~-]{1,256}$'){throw 'Invalid servicing identity'}
            $package=Get-WindowsPackage -Online -PackageName $metadata.package_identity -ErrorAction SilentlyContinue
            $present=$package -and $package.PackageState -eq 'Installed'
        }
        'driver' {
            if(-not $metadata.driver_original_inf){$known=$false;break}
            $drivers=@(Get-WindowsDriver -Online -All | Where-Object {[IO.Path]::GetFileName($_.OriginalFileName) -eq $metadata.driver_original_inf})
            $present=$drivers.Count -gt 0
            if($present){$version=[string]$drivers[0].Version}
        }
        default {$known=$false}
    }
    if($metadata.detection){
        $rule=$metadata.detection;$known=$true
        switch($rule.kind){
            'file_sha256' {
                $full=[IO.Path]::GetFullPath($rule.path)
                $roots=@($env:ProgramFiles,${env:ProgramFiles(x86)}) | Where-Object {$_}
                if(-not @($roots | Where-Object {$full.StartsWith($_+'\',[StringComparison]::OrdinalIgnoreCase)}).Count){throw 'Detection path outside approved program directories'}
                if(Test-Path -LiteralPath $full -PathType Leaf){
                    $item=Get-Item -LiteralPath $full
                    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse-point detector forbidden'}
                    $present=(Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash -eq $rule.sha256
                }else{$present=$false}
            }
            'registry' {
                if($rule.path -notmatch '^HKLM:\\SOFTWARE\\[A-Za-z0-9_ .{}()\\-]+$' -or $rule.path -match '(?i)\\(SAM|SECURITY)(\\|$)'){throw 'Invalid registry detector'}
                $actual=Get-ItemProperty -LiteralPath $rule.path -Name $rule.value_name -ErrorAction SilentlyContinue
                $present=$actual -and [string]$actual.($rule.value_name) -ceq $rule.expected_value
            }
            default {throw 'Unknown detection kind'}
        }
    }
    $matches=$known -and $(if($Manifest.action -eq 'uninstall'){-not $present}else{$present -and (Test-SuroVersion $version $metadata.expected_version)})
    return @{known=[bool]$known;matches=[bool]$matches;version=$version}
}

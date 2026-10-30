#Requires -Version 7
param([string]$SigningCertificateThumbprint, [string]$TimestampUrl, [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version='0.1.0',
      # Optional site.json for the onboarding-page installer (see agent/installer/site.example.json). Never a token.
      [string]$SiteFile)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$publish = Join-Path $root 'publish'
dotnet publish "$root\..\src\NetworkPolicyClient.csproj" -c Release -p:Version=$Version -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=false -o $publish
if ($LASTEXITCODE -ne 0) { throw 'Agent publish failed' }
dotnet publish "$root\..\ui\Suro.Identity.UI.csproj" -c Release -p:Version=$Version -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=false -o "$publish\IdentityUI"
if ($LASTEXITCODE -ne 0) { throw 'Identity UI publish failed' }
if ($SiteFile) {
    $site = Get-Content -LiteralPath $SiteFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $allowed = @('server','signing_public_key','agent_publisher_thumbprint','server_certificate_sha256','ui_language')
    $extra = @($site.PSObject.Properties.Name | Where-Object { $_ -notin $allowed })
    if ($extra.Count) { throw "site.json may contain only $($allowed -join ', '); found $($extra -join ', ')" }
    if (([uri]$site.server).Scheme -ne 'https' -or -not $site.signing_public_key -or -not $site.agent_publisher_thumbprint) { throw 'Incomplete site.json' }
    Copy-Item -LiteralPath $SiteFile -Destination (Join-Path $publish 'site.json') -Force
}
if (-not $SigningCertificateThumbprint) { throw 'Production installers require a trusted code-signing certificate in the build account certificate store' }
$cert = Get-Item "Cert:\CurrentUser\My\$SigningCertificateThumbprint"
$signingOptions = @{ Certificate=$cert; HashAlgorithm='SHA256' }
if ($TimestampUrl) { $signingOptions.TimestampServer=$TimestampUrl }
Get-ChildItem $publish -Recurse -File | Where-Object Extension -in @('.exe','.dll','.ps1') | ForEach-Object {
    $signed = Set-AuthenticodeSignature -FilePath $_.FullName @signingOptions
    if ($signed.Status -ne 'Valid') { throw "Signing failed: $($_.Name)" }
}
$namespace = 'http://wixtoolset.org/schemas/v4/wxs'
$doc = New-Object System.Xml.XmlDocument
$wix = $doc.CreateElement('Wix',$namespace); $doc.AppendChild($wix) | Out-Null
$fragment = $doc.CreateElement('Fragment',$namespace); $wix.AppendChild($fragment) | Out-Null
$group = $doc.CreateElement('ComponentGroup',$namespace); $group.SetAttribute('Id','PublishedFiles'); $fragment.AppendChild($group) | Out-Null
$directoryRef = $doc.CreateElement('DirectoryRef',$namespace); $directoryRef.SetAttribute('Id','INSTALLFOLDER'); $fragment.AppendChild($directoryRef) | Out-Null
$script:counter = 0
function AddFiles($path, $parent) {
    foreach ($directory in Get-ChildItem $path -Directory) {
        $script:counter++
        $node = $doc.CreateElement('Directory',$namespace); $node.SetAttribute('Id',"Dir$script:counter"); $node.SetAttribute('Name',$directory.Name); $parent.AppendChild($node) | Out-Null
        AddFiles $directory.FullName $node
    }
    foreach ($file in Get-ChildItem $path -File | Where-Object Name -ne 'NetworkPolicyClient.exe') {
        $script:counter++; $id="File$script:counter"
        $component=$doc.CreateElement('Component',$namespace); $component.SetAttribute('Id',$id); $component.SetAttribute('Guid','*'); $parent.AppendChild($component) | Out-Null
        $node=$doc.CreateElement('File',$namespace); $node.SetAttribute('Source',$file.FullName); $node.SetAttribute('KeyPath','yes'); $component.AppendChild($node) | Out-Null
        $reference=$doc.CreateElement('ComponentRef',$namespace); $reference.SetAttribute('Id',$id); $group.AppendChild($reference) | Out-Null
    }
}
AddFiles $publish $directoryRef
$doc.Save((Join-Path $root 'PublishedFiles.wxs'))
dotnet build "$root\Agent.wixproj" -c Release -p:AgentVersion=$Version
if ($LASTEXITCODE -ne 0) { throw 'MSI build failed' }
$msi = Get-ChildItem "$root\bin" -Recurse -Filter '*.msi' | Select-Object -First 1
$signed = Set-AuthenticodeSignature -FilePath $msi.FullName @signingOptions
if ($signed.Status -ne 'Valid') { throw 'MSI signature invalid' }
Write-Output $msi.FullName

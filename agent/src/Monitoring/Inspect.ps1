param([Parameter(Mandatory)][string]$PolicyFile, [Parameter(Mandatory)][string]$AgentPath, [string]$Publisher)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$policy = Get-Content -LiteralPath $PolicyFile -Raw -Encoding UTF8 | ConvertFrom-Json
$claims = @{}
$inventory = @{}
$health = @{}
function Claim($name, $status, $actual, $evidence = @{}) { $claims[$name] = @{ status = $status; actual = $actual; evidence = $evidence } }
function BoolClaim($name, [bool]$passed, $actual) { if ($passed) { Claim $name 'PASS' $actual } else { Claim $name 'FAIL' $actual } }
try {
    $users = @(Get-LocalUser | Select-Object Name, Enabled, @{n='sid';e={$_.SID.Value}})
    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
    $inventory.users = @($users | ForEach-Object { @{ name=$_.Name; enabled=$_.Enabled; sid=$_.sid; administrator=($_.sid -in $admins) } })
    $admin = $users | Where-Object Name -eq $policy.admin_account
    $user = $users | Where-Object Name -eq $policy.user_account
    BoolClaim 'account.admin.exists' ([bool]($admin -and $admin.Enabled)) ([bool]$admin)
    BoolClaim 'account.admin.member_of_administrators' ([bool]($admin -and $admin.sid -in $admins)) ([bool]($admin.sid -in $admins))
    BoolClaim 'account.user.exists' ([bool]($user -and $user.Enabled)) ([bool]$user)
    BoolClaim 'account.user.not_administrator' ([bool]($user -and $user.sid -notin $admins)) ([bool]($user -and $user.sid -notin $admins))
    # Preserve built-in identities; report unexpected privilege rather than deleting anyone.
    $approved = @($policy.approved_admins) + @($policy.admin_account)
    $unexpected = @($users | Where-Object { $_.sid -in $admins -and $_.Name -notin $approved -and $_.sid -notmatch '-500$' })
    BoolClaim 'account.unexpected_administrators.absent' ($unexpected.Count -eq 0) @($unexpected.Name)
} catch { Claim 'account.user.not_administrator' 'UNKNOWN' $null @{ error=$_.Exception.GetType().Name } }
try {
    $inventory.partitions = @(Get-Partition | Select-Object DiskNumber, PartitionNumber, DriveLetter, Type, Size, IsBoot, IsSystem)
    $inventory.volumes = @(Get-Volume | ForEach-Object { @{ drive=[string]$_.DriveLetter; filesystem=$_.FileSystem; health=[string]$_.HealthStatus; size=$_.Size; free=$_.SizeRemaining } })
    $c = $inventory.volumes | Where-Object drive -eq 'C'
    $d = $inventory.volumes | Where-Object drive -eq 'D'
    BoolClaim 'disk.c.valid' ([bool]($c -and $c.health -eq 'Healthy')) $c
    BoolClaim 'disk.d.valid' ([bool]($d -and $d.filesystem -eq 'NTFS' -and $d.health -eq 'Healthy')) $d
    $health.disk_free_bytes = if ($c) { $c.free } else { $null }
    $inventory.bitlocker = @(Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint, VolumeStatus, ProtectionStatus, LockStatus)
    $inventory.storage_readiness = @{ backup_restore_tested=$false; filesystem_healthy=([bool]($c.health -eq 'Healthy')); shrink_supported=$false; recovery_key_escrowed=$false }
} catch { Claim 'disk.d.valid' 'UNKNOWN' $null @{ error=$_.Exception.GetType().Name } }
try {
    if ($user -and (Test-Path "Registry::HKEY_USERS\$($user.sid)\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")) {
        $folders = Get-ItemProperty "Registry::HKEY_USERS\$($user.sid)\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        $paths = @($folders.Personal, $folders.Desktop, $folders.'My Pictures', $folders.'My Video', $folders.'{374DE290-123F-4565-9164-39C4925E467B}')
        $inventory.data_locations = $paths
        BoolClaim 'disk.user_data_location.valid' (($paths.Count -eq 5) -and (@($paths | Where-Object { -not $_ -or $_ -notmatch '^D:\\' }).Count -eq 0)) $paths
    } else { Claim 'disk.user_data_location.valid' 'UNKNOWN' $null @{ reason='profile_hive_not_loaded' } }
} catch { Claim 'disk.user_data_location.valid' 'UNKNOWN' $null }
try {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowLocalFirewallRules)
    $inventory.firewall = @{ profiles=$profiles }
    BoolClaim 'firewall.enabled' (($profiles.Count -eq 3) -and (@($profiles | Where-Object { $_.Enabled -ne 'True' }).Count -eq 0)) $profiles
    BoolClaim 'firewall.outbound_policy.valid' (($profiles.Count -eq 3) -and (@($profiles | Where-Object { $_.DefaultOutboundAction -ne 'Block' -or $_.DefaultInboundAction -ne 'Block' }).Count -eq 0)) $profiles
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Outbound -Action Allow)
    $conflicts = @($rules | Where-Object Group -ne 'LanternPolicy')
    $inventory.firewall.conflicts = @($conflicts | Select-Object Name, DisplayName, PolicyStoreSourceType)
    # Rule existence isn't enough: full remote-address/port equivalence needs the allowlist inspector.
    Claim 'firewall.managed_rules.valid' $(if ($conflicts.Count) {'FAIL'} else {'UNKNOWN'}) @($conflicts.Name)
} catch { Claim 'firewall.enabled' 'UNKNOWN' $null @{ error=$_.Exception.GetType().Name } }
try {
    # media_type/description/permanent_mac let the server repeat the legacy script's Wi-Fi MAC selection.
    $inventory.network_adapters = @(Get-NetAdapter | Where-Object MacAddress | ForEach-Object { @{ id=[string]$_.InterfaceGuid; name=$_.Name; mac=$_.MacAddress.Replace('-',':'); permanent_mac=[string]$_.PermanentAddress; status=[string]$_.Status; media_type=[string]$_.MediaType; description=[string]$_.InterfaceDescription } })
    $ip = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1
    $health.ip = [string]$ip.IPv4Address.IPAddress
    $health.gateway = [string]$ip.IPv4DefaultGateway.NextHop
} catch {}
try {
    # Pre-Suro "kursant" scripts: a SYSTEM startup task resets the firewall at every boot. Read-only; see docs/developers/legacy-credentials.md.
    $legacy = @{ startup_task=$null; persisting_scripts=@(); firewall_rule_addresses=@(); winre_state=$null }
    $task = Get-ScheduledTask -TaskPath '\Custom Tasks\' -TaskName 'Running_kursant_script_at_every_startup' -ErrorAction SilentlyContinue
    if ($task) {
        $arguments = [string]($task.Actions | Select-Object -First 1).Arguments
        $kursant = if ($arguments -match '-KursantUsername\s+"?([^"\s]+)') { $Matches[1] } else { $null }
        $legacy.startup_task = @{ state=[string]$task.State; kursant_username=$kursant }
    }
    $legacy.persisting_scripts = @(Get-ChildItem -LiteralPath "$env:windir\System32\SystemScripts" -Filter 'kursant_persisting*.ps1' -ErrorAction SilentlyContinue | ForEach-Object Name)
    $legacy.firewall_rule_addresses = @(Get-NetFirewallRule -DisplayName 'Allow outbound to *' -ErrorAction SilentlyContinue | Get-NetFirewallAddressFilter | ForEach-Object { [string]($_.RemoteAddress -join ',') })
    $reagent = "$env:windir\System32\Recovery\ReAgent.xml"
    if (Test-Path -LiteralPath $reagent) { $legacy.winre_state = [string]([xml](Get-Content -LiteralPath $reagent -Raw)).WindowsRE.InstallState.state }
    $inventory.legacy = $legacy
} catch {}
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $inventory.hardware = @{ cpu=$cpu.Name; ram_bytes=([long]$os.TotalVisibleMemorySize * 1024) }
    $inventory.os = @{ caption=$os.Caption; version=$os.Version; build=$os.BuildNumber; architecture=$os.OSArchitecture }
    $interactive=(Get-CimInstance Win32_ComputerSystem).UserName
    if($interactive){
        $sid=([System.Security.Principal.NTAccount]$interactive).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $inventory.session=@{windows_account=$interactive;windows_sid=$sid}
    }
    $health.cpu_percent = $cpu.LoadPercentage
    $health.ram_percent = [math]::Round(100 * (1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize), 1)
    $health.last_boot = $os.LastBootUpTime.ToUniversalTime().ToString('o')
    $health.uptime_seconds = [long]((Get-Date) - $os.LastBootUpTime).TotalSeconds
} catch {}
try {
    $service = Get-Service LocalNetworkPolicyAgent
    BoolClaim 'agent.service_running' ($service.Status -eq 'Running') ([string]$service.Status)
    $health.service_running = ($service.Status -eq 'Running')
    $sig = Get-AuthenticodeSignature -LiteralPath $AgentPath
    BoolClaim 'agent.integrity_valid' ([bool]($Publisher -and $sig.Status -eq 'Valid' -and $sig.SignerCertificate.Thumbprint -eq $Publisher)) ([string]$sig.Status)
} catch { Claim 'agent.integrity_valid' 'UNKNOWN' $null }
# Full effective restriction verification is edition- and policy-dependent; never infer it from intent.
Claim 'security.user_restrictions.valid' 'UNKNOWN' $null @{ reason='effective_policy_verification_required' }
@{ claims=$claims; inventory=$inventory; health=$health } | ConvertTo-Json -Depth 20 -Compress

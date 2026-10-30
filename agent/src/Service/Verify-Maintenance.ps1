param([Parameter(Mandatory)][string]$ManifestFile)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$t=Get-Content -LiteralPath $ManifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
if($t.purpose -ne 'verify_maintenance' -or $t.job_id -notmatch '^[0-9a-fA-F-]{36}$'){throw 'Invalid readback authorization'}
$verified=$false;$waiting=$true
switch($t.operation){
    'windows.locale' {
        $sid=$t.data.result.user_sid
        if($sid -notmatch '^S-1-5-[0-9-]+$'){$waiting=$false;break}
        $base="Registry::HKEY_USERS\$sid"
        if(-not(Test-Path -LiteralPath $base)){break}
        $desktop=Get-ItemProperty -LiteralPath "$base\Control Panel\Desktop" -ErrorAction SilentlyContinue
        $intl=Get-ItemProperty -LiteralPath "$base\Control Panel\International" -ErrorAction SilentlyContinue
        $profile=Get-ItemProperty -LiteralPath "$base\Control Panel\International\User Profile" -ErrorAction SilentlyContinue
        $preload=Get-ItemProperty -LiteralPath "$base\Keyboard Layout\Preload" -ErrorAction SilentlyContinue
        $installed=@($preload.PSObject.Properties | Where-Object Name -match '^\d+$' | ForEach-Object {[string]$_.Value})
        $missing=@($t.data.keyboard_layouts | Where-Object {$_.Split(':')[1] -notin $installed})
        $verified=($t.data.language -in @($desktop.PreferredUILanguages)) -and $intl.LocaleName -eq $t.data.language -and $t.data.language -in @($profile.Languages) -and $missing.Count -eq 0
        if($verified){
            Unregister-ScheduledTask -TaskName "LanternLocale-$($t.job_id)" -Confirm:$false -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "$env:ProgramData\LanternLocale-$($t.job_id).ps1" -ErrorAction SilentlyContinue
        }
    }
    'system.reboot' {
        if(-not $t.data.result.boot_time){$waiting=$false;break}
        $verified=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime() -gt [datetime]$t.data.result.boot_time
    }
    default {$waiting=$false}
}
@{state=$(if($verified){'SUCCEEDED'}elseif($waiting){'WAITING'}else{'UNKNOWN'});details=@{verified=[bool]$verified;source='windows_readback'}} | ConvertTo-Json -Depth 5 -Compress

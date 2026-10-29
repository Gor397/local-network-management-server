param([Parameter(Mandatory)][ValidateSet('firewall.enable','account.demote_user','settings.hide_c')][string]$Operation,
      [Parameter(Mandatory)][string]$PolicyFile)
$ErrorActionPreference = 'Stop'
$policy = Get-Content -LiteralPath $PolicyFile -Raw | ConvertFrom-Json
switch ($Operation) {
    'firewall.enable' { Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True }
    'account.demote_user' {
        if ($policy.user_account -eq $policy.admin_account) { throw 'Refusing to demote administrative recovery identity' }
        $admin = Get-LocalUser -Name $policy.admin_account
        $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544')
        if (-not $admin.Enabled -or $admin.SID -notin $members.SID) { throw 'Approved recovery administrator must exist and be enabled' }
        $user = Get-LocalUser -Name $policy.user_account
        if ($user.SID -in $members.SID) { Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $user.SID }
    }
    'settings.hide_c' {
        $user = Get-LocalUser -Name $policy.user_account
        $key = "Registry::HKEY_USERS\$($user.SID)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path "Registry::HKEY_USERS\$($user.SID)")) { throw 'User hive is not loaded; manual intervention required' }
        if ($policy.hide_c) { New-Item -Path $key -Force | Out-Null; New-ItemProperty -Path $key -Name NoDrives -PropertyType DWord -Value 4 -Force | Out-Null }
    }
}

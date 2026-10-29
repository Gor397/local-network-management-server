#Requires -RunAsAdministrator
param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z][A-Za-z0-9_-]{0,19}$')][string]$AdminName,
      [Parameter(Mandatory)][ValidatePattern('^[A-Za-z][A-Za-z0-9_-]{0,19}$')][string]$UserName)
$ErrorActionPreference='Stop'
if($AdminName -eq $UserName){throw 'Distinct administrator and standard user accounts are required'}
# Console provisioning only. Credentials are never embedded in source, sent to agents by policy, or logged.
if(-not(Get-LocalUser -Name $AdminName -ErrorAction SilentlyContinue)){
    $password=Read-Host 'New approved administrator password' -AsSecureString
    New-LocalUser -Name $AdminName -Password $password | Out-Null
}
$admin=Get-LocalUser -Name $AdminName
if(-not $admin.Enabled){throw 'Existing administrator is disabled; review migration before changing it'}
if($admin.SID -notin @(Get-LocalGroupMember -SID 'S-1-5-32-544').SID){Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $admin.SID}
if(-not(Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)){
    $password=Read-Host 'New standard user password' -AsSecureString
    New-LocalUser -Name $UserName -Password $password | Out-Null
}
$user=Get-LocalUser -Name $UserName
if($user.SID -in @(Get-LocalGroupMember -SID 'S-1-5-32-544').SID){Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $user.SID}
if($user.SID -notin @(Get-LocalGroupMember -SID 'S-1-5-32-545').SID){Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user.SID}
# Existing accounts, profiles, files, built-in identities and service accounts are never deleted.

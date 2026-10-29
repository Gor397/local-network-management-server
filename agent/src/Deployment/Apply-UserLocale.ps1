param([Parameter(Mandatory)][ValidatePattern('^[a-z]{2,3}-[A-Za-z]{2,8}$')][string]$Language)
$ErrorActionPreference='Stop'
$existing=Get-WinUserLanguageList
$list=New-WinUserLanguageList -Language $Language
foreach($item in $existing){if($item.LanguageTag -ne $Language){$list.Add($item)}}
Set-WinUserLanguageList -LanguageList $list -Force
Set-WinUILanguageOverride -Language $Language
Set-Culture -CultureInfo $Language
# Existing languages and keyboard layouts are preserved after the newly selected language.

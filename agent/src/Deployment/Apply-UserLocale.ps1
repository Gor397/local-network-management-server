param([Parameter(Mandatory)][ValidatePattern('^[a-z]{2,3}-[A-Za-z]{2,8}$')][string]$Language,[ValidatePattern('^[0-9A-Fa-f:,]*$')][string]$KeyboardLayouts='')
$ErrorActionPreference='Stop'
$existing=Get-WinUserLanguageList
$list=New-WinUserLanguageList -Language $Language
foreach($layout in @($KeyboardLayouts.Split(',') | Where-Object {$_})){if(-not $list[0].InputMethodTips.Contains($layout)){$list[0].InputMethodTips.Add($layout)}}
foreach($item in $existing){if($item.LanguageTag -ne $Language){$list.Add($item)}}
Set-WinUserLanguageList -LanguageList $list -Force
Set-WinUILanguageOverride -Language $Language
Set-Culture -CultureInfo $Language
# Existing languages and keyboard layouts are preserved after the newly selected language.

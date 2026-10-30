param([Parameter(Mandatory)][string]$ManifestFile)
# Disables (never deletes) the pre-Suro startup task that runs "netsh advfirewall reset" at every boot.
# The firewall rules in effect now are left untouched, so connectivity is unchanged; they simply stop
# being reset at boot. legacy.restore_startup_task re-enables the task. See docs/developers/legacy-credentials.md.
$ErrorActionPreference='Stop'
$m=Get-Content -LiteralPath $ManifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
$root="$env:ProgramData\Lantern"
$path='\Custom Tasks\';$name='Running_kursant_script_at_every_startup'
$restore=$m.operation -eq 'legacy.restore_startup_task'
$task=Get-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue
if(-not $task){
    # Nothing to change; report it so the server can refresh its inventory instead of retrying.
    @{state=$(if($restore){'FAILED'}else{'SUCCEEDED'});details=@{task_present=$false;verified=(-not $restore)}} | ConvertTo-Json -Compress
    exit 0
}
$backup="$root\legacy-kursant-task-$($m.job_id).xml"
Export-ScheduledTask -TaskPath $path -TaskName $name | Set-Content -LiteralPath $backup -Encoding Unicode
$before=[string]$task.State
if($restore){if($before -eq 'Disabled'){Enable-ScheduledTask -TaskPath $path -TaskName $name | Out-Null}}
elseif($before -ne 'Disabled'){Disable-ScheduledTask -TaskPath $path -TaskName $name | Out-Null}
$after=[string](Get-ScheduledTask -TaskPath $path -TaskName $name).State
$verified=if($restore){$after -ne 'Disabled'}else{$after -eq 'Disabled'}
$winre=$null
if(-not $restore -and $m.enable_winre){
    # Re-enabling WinRE does not touch partitions it cannot find; a failure is reported, not retried.
    $output=& "$env:SystemRoot\System32\reagentc.exe" /enable 2>&1
    $winre=@{exit_code=$LASTEXITCODE;output=([string]($output -join "`n")).Substring(0,[Math]::Min(500,([string]($output -join "`n")).Length))}
}
if(-not $verified){throw "Task state after change is $after"}
@{state='SUCCEEDED';details=@{task_present=$true;state_before=$before;state_after=$after;backup=$backup;verified=$true;winre=$winre}} | ConvertTo-Json -Compress -Depth 5

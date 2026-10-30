# Legacy kursant scripts and administrator passwords

Before Suro, computers were prepared with the scripts kept outside version control in `k_t_scr_/`. This guide records what they did, how Suro stays compatible with them and how new computers should be handled.

## What the scripts changed

`running_kursant_script_*.ps1` started `kursant_script_*.ps1` as SYSTEM through PsExec. That script:

1. ran `netsh advfirewall reset`, set every profile's default outbound action to Block and allowed outbound traffic only to `192.168.0.1`, `10.47.47.47` and `10.47.47.74`;
2. restricted the ACL of `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess` to SYSTEM and Administrators;
3. ran `reagentc /disable`, which turns off the Windows Recovery Environment;
4. created `AcademyAdmin` with a MAC-derived password and added it to Administrators;
5. removed the logged-on user from Administrators and added that user to Users;
6. registered the SYSTEM startup task `\Custom Tasks\Running_kursant_script_at_every_startup`, which runs `C:\Windows\System32\SystemScripts\kursant_persisting_*.ps1 -KursantUsername <user>`.

**At every boot the persisting script resets Windows Firewall and re-applies the three-address allowlist.** Any rule Suro adds is removed on restart. The Suro agent can reach the server after a restart only if the server address is in that allowlist. While the agent reports the task as active, the server refuses `firewall.apply_allowlist` (`maintenance.legacy_task_active`), and `Apply-Allowlist.ps1` refuses it again on the endpoint.

## Retiring the startup task

Both steps are typed maintenance jobs: the computer must be in Maintenance or Approved remediation mode, and approval needs the `approve` permission. The **Local administrator** tab offers them in order.

1. `legacy.retire_startup_task` (`agent/src/Legacy/Retire-KursantTask.ps1`) exports the task XML to `%ProgramData%\Lantern\legacy-kursant-task-<job>.xml`, **disables** the task and reads its state back. It does not delete the task or the persisting script, and it does not touch the firewall. The rules in effect now keep the current connectivity; they simply stop being reset at boot. An already-disabled task is reported as verified without change. With `enable_winre` it also runs `reagentc /enable` and reports the exit code.
2. `firewall.apply_allowlist` with `replace_legacy_rules` keeps the existing safeguards: the policy must explicitly allow the server's literal address and port, a full `netsh advfirewall export` backup is taken and a 3-minute rollback task is registered. It then adds the Suro rules, **disables** only the locally stored rules named exactly `Allow outbound to 192.168.0.1|10.47.47.47|10.47.47.74`, and verifies HTTPS to the server. Any failure imports the backup. Any other non-Suro outbound allow rule still stops the job.

`legacy.restore_startup_task` re-enables the task, which resets the firewall again from the next boot. A local administrator can do the same with `Enable-ScheduledTask -TaskPath '\Custom Tasks\' -TaskName Running_kursant_script_at_every_startup`. The rules disabled in step 2 can be re-enabled with `Enable-NetFirewallRule -DisplayName 'Allow outbound to *'`.

The `_ru` variants use localized group names (`Администраторы`, `Пользователи`). The English persisting script misspells `Admisnistrators`, so its startup re-demotion never worked on English Windows. The Russian `PasswordGenerator_ru.ps1` uses `Select-Object 1` instead of `-First 1`, so it probably printed no usable password. The account creation itself used `-First 1` in both languages. `loog.txt` contains script output but no password.

## The password algorithm

`Convert-MacToUniquePassword` turns the six MAC bytes into a 10-character password: three uppercase letters, two digits, three letters of mixed case, one of `!@#$%^&*`, and a digit or uppercase checksum character. `backend/app/services/legacy_credentials.py::legacy_mac_v1` is a line-for-line port. Never change it: existing computers would lose their recovery password.

The MAC was taken from `Get-NetAdapter` entries whose `MediaType` was `Native 802.11` and whose description did not match `Virtual|Hyper-V`, sorted by `Status` descending (so `Up` came first). `legacy_mac_candidates` repeats that selection from the agent's inventory, then also lists factory (permanent) addresses, other Wi-Fi adapters and the registered MAC. It lists all of them because:

- an adapter may have been replaced since the script ran;
- Windows PowerShell does not guarantee the order of two adapters with the same status;
- a randomized hardware address may have been active.

If no Wi-Fi adapter existed when the script ran, the password argument was empty. That may have created the account with a blank password. Treat such computers as needing manual recovery.

### Confirming the port against Windows PowerShell

The vectors in `backend/tests/test_legacy_credentials.py` agree with an independent statement-by-statement transliteration (5,004 vectors). Neither has been checked against Windows PowerShell itself. The port relies on one PowerShell behavior: `[byte] -shl 3` widens to Int32 instead of truncating to 8 bits. Confirm it once on any Windows computer (this changes nothing):

```powershell
# Paste only the Convert-MacToUniquePassword function from PasswordGenerator_en.ps1, then:
'00-11-22-33-44-55','A4-C3-F0-85-7E-21','FF-FF-FF-FF-FF-FF','00-00-00-00-00-01' |
  ForEach-Object { "$_ $(Convert-MacToUniquePassword -MacAddress $_)" }
# Expected: TNW20StG!Y, DCP83vUt*Y, DHS49dtI&8, FHC33IQA&K
```

If any line differs, do not reveal legacy passwords until the port is fixed to match.

## Getting the password of an existing computer

1. Update the agent so its inventory reports adapter media type and the legacy artifacts (`Monitoring/Inspect.ps1`), then run a recheck.
2. Open the computer → **Local administrator**. The panel lists the old-script findings, the standard user named in the startup task and the candidate MACs.
3. An owner chooses **Use this MAC** for the first candidate and gives a reason. Suro stores only the MAC; the password is derived when it is needed.
4. **Show password** requires recent TOTP verification even when MFA is otherwise optional. It writes `credential.revealed` with the reason to the audit log. The password is never written to the audit log, the database or request logs.
5. Sign in, then **Record sign-in result**. If it fails, try the next candidate MAC. If none works, the computer needs manual recovery. Suro never resets a password.

The API is `GET|POST /api/v1/devices/{id}/admin-credential`, `POST …/reveal` and `POST …/verification` (`backend/app/api/credentials.py`). Registering and revealing need the owner-only `credentials` permission.

## Security implications and new computers

The legacy password depends only on the Wi-Fi MAC, which every nearby radio receives in clear. Anyone with these scripts can compute every `AcademyAdmin` password. Only `PasswordGenerator_*.ps1` deleted itself; `kursant_script_*.ps1` contains the same function and did not. Treat all legacy passwords as known to anyone who has seen the scripts.

New computers therefore use `RANDOM_V1`: a 20-character random password, sealed with the server Vault key and revealed through the same audited path. **Generate random password** creates the record in state `PENDING_APPLY`. Nothing changes on the computer. Set the password on the managed administrator account during provisioning (`Provision-ApprovedAccounts.ps1` prompts for it), then record the sign-in result. Move legacy computers to a random password during planned maintenance, only after the new one has been confirmed by signing in.

The random passwords are only as safe as the server's `ENCRYPTION_KEY` and its backups. Include the key in the offline backup procedure ([recovery](../recovery.md)). Without it, the sealed passwords cannot be recovered.

## Remaining work

- No agent operation sets or rotates the password. That would require sending a secret to the endpoint and verifying the sign-in, which needs Windows VM validation first.
- `Retire-KursantTask.ps1` and the `replace_legacy_rules` path of `Apply-Allowlist.ps1` have not run on Windows. In particular, whether legacy rules report `PolicyStoreSourceType` `Local` in the ActiveStore needs confirming. If they don't, the job stops on the conflict check without making any change.
- Inventory additions (`media_type`, `permanent_mac`, `legacy`) have not been executed on Windows. The `ReAgent.xml` `InstallState` read in particular needs confirming on Windows 10 and 11.

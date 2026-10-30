# Validation and laboratory testing

## Automated checks available now

| Command | Verifies | Does not verify |
|---|---|---|
| `.venv/bin/python -m pytest backend/tests -q` | Auth/RBAC/CSRF/MFA, enrollment signatures, replay, policy/evidence gates, uploads/jobs, migrations and RouterOS fixtures | Real Windows or RouterOS packet behavior |
| `cd frontend && npm test` | Locale-catalog consistency and Unicode | Every page interaction, layout or translation quality |
| `cd frontend && npm run build` | TypeScript and production bundling | Browser end-to-end behavior |
| `dotnet build agent/src/NetworkPolicyClient.csproj -c Release` | Windows-target compilation | Windows execution, ACLs or service lifecycle |
| `dotnet run --project agent/tests/AgentContractTests.csproj -c Release` | Signed bytes, tamper rejection, key/device/expiry validation | Windows certificate-store persistence or Authenticode trust |
| `python3 scripts/check_docs.py` | Local documentation links and project-skill references | Mermaid rendering or technical correctness of hardware claims |

Tests use fake installer bytes only to exercise upload/orchestration. They never execute those bytes. Production agents still require valid hashes and trusted publisher signatures.

## Backend fixture design

`conftest.py` creates a temporary SQLite database and isolated signing/CA keys. The `admin` fixture logs in through the real API, then sets recent-MFA state directly for tests unrelated to TOTP. A separate TOTP test exercises setup, confirmation and replay protection.

Agent tests generate real RSA keys and CSRs, enroll a device, and sign requests in the documented protocol. Router tests use `httpx.MockTransport`, not network connections. A connection failure test checks that enforcement stays `ERROR`.

Run PostgreSQL integration tests for actual row locks, advisory locks and concurrent publication/claims. SQLite's successful unit suite does not establish these concurrency guarantees. Complete PostgreSQL concurrency stress coverage remains pending.

## Isolated Compose lab

Use a distinct project name, test keys, test database and loopback port. The lab override accepts `LAB_ENV_FILE` and `LAB_DATA_DIR` so it cannot accidentally reuse production bind mounts.

```sh
# First create a lab env/key directory as described by the lab helper's help.
python3 scripts/lab.py prepare
python3 scripts/lab.py up
python3 scripts/lab.py smoke
python3 scripts/lab.py down
```

The helper uses project `lantern-lab`, `/tmp/lantern-lab.env`, `/tmp/lantern-lab-data`, and `127.0.0.1:18443`. It never registers a router. Down preserves the database volume; deleting test data is a separate deliberate action.

A passing smoke test should establish HTTPS, API login, dashboard delivery, device registration, policy publication/assignment and authenticated inventory queries against PostgreSQL. It still does not prove router or Windows enforcement.

## Windows VM acceptance

Create snapshots before each mutation test. Use a throwaway Windows 11 VM with offline installation media, a trusted lab code-signing certificate and the management server's trusted TLS certificate. Give it an isolated virtual NIC and a separate recovery console.

| Test | Procedure | Evidence to retain |
|---|---|---|
| Install/enroll | Build/sign MSI and scripts; install through protected provisioning; approve CSR | Service status, certificate/private-key accessibility as SYSTEM, token removal |
| Noninteractive service | Sign out the standard user; reboot | Valid heartbeats without a logged-in user |
| Standard-user tamper | Attempt service stop, install-directory modification and state-file modification | Access denied with authorized admin recovery still working |
| Audit preservation | Use existing accounts, custom firewall rules and D: data | Before/after comparison showing no unapproved mutations |
| Firewall drift | Disable a profile as lab admin; enable approved remediation | Failure evidence, remediation record, re-read effective profile |
| Firewall migration | Approve exact allowlist with management path and conflict review | Backup file, recovery task, IPv4/IPv6 traffic tests and rollback on loss |
| Package install | Deploy a signed test MSI; repeat; cancel pending work | Signature/hash validation, product detection, exit code and no unnecessary reinstall |
| Interrupted install | Reboot/disconnect while installer is running | Ambiguous task remains unknown; no automatic replay |
| Locale | Install matching offline language resources, request locale job, log on | Correct intended user's display/culture/keyboards and preserved existing languages |
| SSH | Enable offline capability; pin host key; use browser session | Wrong host key rejected, public-key auth only, restricted inbound reachability, termination |
| Storage assessment | VM without D:, BitLocker and recovery partitions | Assessment flags; no resize/format operation is triggered |
| Legacy kursant computer | Snapshot a VM, run the original `kursant_script_*.ps1` on it, install the agent, recheck | `legacy` inventory (task, `kursant_username`, allowlist, `ReAgent.xml` state), adapter `media_type`; the revealed `AcademyAdmin` password signs in |
| Legacy task retirement | On the kursant VM snapshot: retire the task with WinRE, reboot, then migrate the firewall with `replace_legacy_rules`, reboot again | Task Disabled with XML backup; rules unchanged after the first reboot; Suro rules present, legacy rules disabled and heartbeats continuing after the second; forced management failure restores the backup |
| Policy features | Install agent 0.2 on a VM assigned a policy with `min_d_gb` and `ip_mode=static` plus a device address; then downgrade to 0.1 | 0.2 heartbeat lists features and receives the keys; claims for D: size and IP match `Get-Volume`/`Get-NetIPConfiguration`; loop follows `heartbeat_seconds`; 0.1 still accepts its v1 projection |
| Client requirement (pilot) | Follow [testing one laptop](client-admission.md#testing-one-laptop) on a CHR or lab router, never the production controller first | Gate rules first in each chain; grant appears/expires; service stop revokes after timeout + grace; removal leaves only manual rules; portal MSI enrolls only after approval; planted `%ProgramData%\Lantern\config.json` by a standard user makes the service refuse to start |
| Legacy algorithm | Run only `Convert-MacToUniquePassword` on the vectors in [legacy credentials](legacy-credentials.md#confirming-the-port-against-windows-powershell) | Identical output; no machine change |

Do not simulate Windows success by changing database rows or relaxing unknown checks. Tests should observe actual effective Windows state.

## MikroTik CHR and physical AP acceptance

Use an isolated CHR lab for routing/DHCP/firewall tests and physical APs for wireless features CHR cannot provide. Keep WinBox/console recovery on a separate management path.

Test modern WiFi, legacy wireless and CAPsMAN separately. For every model/package combination, record RouterOS version, packages, interface/menu support, authentication features and VLAN behavior.

Required checks include:

1. Import existing manual rules and unique credentials; confirm repeated discovery does not alter them.
2. Allocate outside DHCP pools and manual static ranges; race two reservation requests and reject duplicates.
3. Change the router manually after preview; applying that stale preview must fail.
4. Fail transport after one write; preserve the partial operation record and avoid verified enforcement claims.
5. Check rejection ordering and disassociation behavior on every AP, including roaming.
6. Test direct client-to-client Layer 2 traffic, routed traffic and IPv4/IPv6 internet traffic separately.
7. Test maintenance connectivity and release; do not assume wireless rejection retains remediation access.
8. Stop the server and an AP independently; confirm failure policy preserves recovery and distinguishes missing verification from a confirmed powered-off device.

A router configuration readback is only one test artifact. Full isolation needs packet-path observations from relevant endpoint/network vantage points. Record those observations before marking an adapter's protection verified.

## Acceptance mapping

The A–N scenarios in the project brief are tracked in [progress](../progress.md). Automated coverage is strongest for identity, unknown/stale evidence, version changes, exceptions, developer labeling, preservation and error handling. Physical quarantine, Windows effectiveness, storage migration and complete remote software verification remain laboratory/implementation work.

## Suro extension qualification

Run `backend/tests/test_suro.py` and `test_suro_migration.py` for identity/owner separation, group precedence, shared-repository rollout, authorization, AP previews/readback, reboot success/failure/uncertainty, recovery loops/upstream guards, cross-source correlation, native API framing and migration preservation. Frontend tests cover all native help catalogs, search/dialog interactions and Armenian/default password-only login. `dev-check.py --area agent` now builds both Windows projects.

Before rollout, add these VM/CHR/physical tests to your release record:

1. Install a signed MSI as administrator, sign in as a standard user, complete Armenian onboarding with and without rank, log out/in, confirm no repeated prompt. Repeat RU/EN and enrollment without an interactive session.
2. Disconnect networking before submission, reconnect, confirm exactly one SID record. Attempt a spoofed SID/prefabricated local pipe, malformed lengths and simultaneous clients. Confirm standard users cannot read ProgramData credentials or replace binaries/SCM configuration. Directly upgrade the original MSI and confirm the same key/device identity plus executable-only user permissions.
3. Import actual modern WiFi, legacy wireless and CAPsMAN devices read-only; compare WinBox and encrypted/redacted snapshots. Record unavailable sensors accurately. Test REST/API-SSL TLS failures and insufficient permissions.
4. On isolated APs, preview a Unicode SSID change, preserve private passphrases/manual settings, verify readback and reviewed inverse restoration. Remove the management route mid-operation and retain honest unknown/failure states.
5. Reboot a group sequentially. Test protected names, stale previews, changed generation, window expiry, cancellation after issuance, API outage, missing uptime reset, server restart and a declared independent path that is itself restarting. Verify no second disruption before the first result is known.
6. Use vendor-approved compatible NPK files and a trusted pinned SFTP key on disposable hardware. Test wrong architecture/hash/version, major transition rejection, binary backup/restore matching, reboot recovery and offline console access. CHR cannot qualify every physical wireless/firmware behavior.
7. Generate correlated AP and client failures; confirm one primary incident, native translations, confidence, facts, maintenance suppression and history. Simulate upstream outage and resource overload; prove cooldown/attempt gates prevent recovery loops.
8. Run controlled many-device polling and package-transfer load together. Record p50/p95 API latency, worker heartbeat gap, cgroup CPU/RAM, database/storage growth and transfer concurrency at the configured caps. No measured fleet-size guarantee exists yet.

Record actual observations separately from this checklist. A successful cross-build or simulated callback is not a completed Windows/AP acceptance test.

`backend/tests/test_recovery_controls.py` additionally covers narrow radio correction, opt-out/unknown desired state, execution-time revocation, expired windows, shared/gateway pressure, supported-condition validation and protected-metadata authorization. Developer-helper tests reject unsafe lab key regeneration. Dashboard component tests exercise approved-only firmware choices, AP group diagnostic scope, persisted recovery options and typed conditions.

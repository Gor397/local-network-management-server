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

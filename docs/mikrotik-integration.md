# MikroTik integration and safe network changes

## Supported transport and discovery

Suro supports RouterOS REST over verified HTTPS and an API-SSL adapter for legacy devices supporting the modern API login protocol (RouterOS 6.43+). Both verify the device certificate. Select `REST` with `https://IP:443` or `API_SSL` with `https://IP:8729`; the latter scheme describes TLS, not an HTTP connection. Pinned SSH/SFTP is used separately for approved binary backup/restore and RouterOS package transfer, not as a generic configuration fallback. Enable `www-ssl` with a valid certificate and a dedicated restricted management account according to [MikroTik's REST documentation](https://manual.mikrotik.com/docs/developer-guides/rest-api/).

REST credentials remain server-side. Current RouterOS documentation describes `read`, `api` and `rest-api` permissions for read-only access; confirm the exact permissions on your installed version. Avoid broad administrative/sensitive permissions for initial discovery. Use a separate reviewed write-capable account only when ready for controlled changes.

Do not disable TLS verification. If the router uses a local CA, place the public CA file under `data/trust/` and enter its container path, such as `/data/trust/router-ca.crt`, during registration. The TLS certificate must contain the literal management IP used by the connector.

The application accepts literal private/allowlisted management IPs to reduce SSRF/DNS-rebinding risk. Keep RouterOS management reachable only from approved management infrastructure and retain a separate WinBox/console recovery path.

### Plain API (read-only fallback)

Older routers often have `api` on 8728 but `api-ssl` without a certificate. Modern TLS clients cannot complete that handshake ("no peer certificate"). With `ROUTER_PLAINTEXT_API_ALLOWED=true` you can register such a router with transport `API` and address `https://IP:8728`. The scheme is ignored for this transport.

- The login password and all data cross the LAN unencrypted.
- The adapter refuses every write, and `services/safety.py` also blocks writes to it in every mode.
- To allow changes later, install a certificate for `api-ssl` (or `www-ssl` on RouterOS 7) and switch the router to `API_SSL` or `REST`.

Measured on 2026-10-30 against a RouterOS 6.49 CAPsMAN controller: full discovery took 5.6 s and about 1 MB. It returned 80 remote CAPs, 189 CAPsMAN radios, 237 registrations, 853 leases and 153 ARP entries.

Native transports count log lines first (`count-only`) and skip logs larger than 2000 lines instead of streaming them. Such routers show no log events in health data.

### CAPsMAN access points

When a registered controller reports `caps-man/remote-cap` (or RouterOS 7 `interface/wifi/capsman/remote-cap`), each CAP becomes an entry in **Routers & access points**. These entries use transport `CAPSMAN` and record their controller (`routers.controller_id`, migration `0007`).

- **Data source.** Status, model, version and client count come from the controller on every discovery and health poll. Suro never connects to a CAP and never writes to it. Discovery and batch operations on a CAP are refused.
- **Radio-to-CAP mapping.** A radio belongs to the CAP whose base MAC is closest below the radio MAC, within 8. CAPsMAN interface names do not reliably follow CAP identities: on the real controller only 110 of 189 names matched, while the MAC rule matched exactly.
- **Missing or unreachable.** A CAP the controller stops reporting is marked `UNAVAILABLE` and kept. If the controller itself is unreachable, its CAPs show `UNKNOWN`.
- **Groups and deletion.** CAPs can be members of AP groups. Archiving or permanently deleting a controller does the same to its CAPs. A deleted CAP that is still connected reappears at the next discovery.

## Minimal RouterOS accounts

Create these accounts yourself, through your existing administration path, after backing up the router. Suro never creates users or changes `/ip service`. The policy names below are RouterOS 7 names. Check `/user group print` on your version, because `rest-api` does not exist on older releases.

```routeros
# Read-only discovery and monitoring (REST over www-ssl, or API-SSL)
/user group add name=suro-read policy=read,api,rest-api comment="Suro read-only"
/user add name=suro-reader group=suro-read address=<SURO_SERVER_IP>/32 password="<LONG_RANDOM_PASSWORD>"
```

`address=` limits where the account may log in from. Leave out `sensitive`: Suro does not need existing passphrases, and preserving them does not require reading them. Store the password only in the dashboard registration form, which keeps it encrypted in the database (`Vault`) and never shows it again. Each router can have its own account and password. Never put router passwords in `.env`, source code, tickets or documentation.

For a later `controlled_test` pilot, use a **separate** group that also has `write`. Add `reboot` only if the pilot includes reboots, and `ssh,ftp` only for pinned-SFTP backup/restore/upgrade. Register that account on the pilot routers only, and list them in `TEST_ROUTERS`.

`OPERATION_MODE` (see the [dual-network guide](development/dual-network-setup.md#3-safety-modes)) is the server-wide gate. Even with a write-capable account, `read_only` and `dry_run` refuse every write in the transport layer.


1. Back up the router with existing administration tooling and confirm recovery access.
2. Add its name, HTTPS address, dedicated username/password and optional CA path in the dashboard.
3. Run read-only discovery (with `OPERATION_MODE=read_only`).
4. Review RouterOS version, packages, interfaces, DHCP servers/networks/leases, pools, ARP, bridge/VLAN data, firewall data and wireless menus.
5. Compare discovered state with WinBox. No existing passwords or manual entries should change.

Discovery probes modern `interface/wifi`, legacy `interface/wireless`, and legacy CAPsMAN menus individually. A missing menu is different from an authentication failure. Modern CAPsMAN behavior follows the installed WiFi stack; menu discovery is not proof of all controller-specific configuration support.

| Capability | Current treatment |
|---|---|
| Wireless stack/menu availability | Probed programmatically |
| Router version, board and package names | Read from device |
| Bridge VLAN filtering flag | Observed from configuration |
| PPSK/private-passphrase support | Requires model/package/lab validation |
| Dynamic per-client VLAN assignment | Unverified; automatic provisioning incomplete |
| Complete Layer 2 isolation | Unverified; packet-path tests required |

Secret-bearing snapshots are encrypted at rest. Browser responses redact password/passphrase/secret/key fields. An account without sensitive-read permission may not reveal existing credentials; preserving them does not require overwriting or exporting them.

## Address allocation

Create an allocation profile only after identifying the correct DHCP server and matching network. Declare an exclusively managed range outside dynamic pools and all known manual static assignments, plus explicit exclusions. Discovery cannot discover every powered-off machine's manually configured address; authoritative IPAM ownership of the allocation range is a prerequisite.

The allocator excludes router/ARP/lease addresses, pools, exclusions and all centrally registered reservations. Database constraints reject duplicate addresses and applicable MAC reservations. Overlapping routed address spaces are not supported by the current globally unique reservation model.

APs in the same Layer 2 network normally share a DHCP server; do not create independent duplicate reservations on every AP. Different routed subnets need separate addressing records. The system does not promise one unchanged IP across unrelated Layer 3 networks.

## Developer MAC-only workflow

The dashboard/API accepts a MAC and allocation profile, creates an unmanaged inventory entry and produces a lease preview. Existing static leases can be reused without rewriting them. Endpoint compliance stays `UNVERIFIED / UNMANAGED` and no agent is required.

**Current limitation:** the lease workflow does not automatically grant Wi-Fi access, install private credentials, provision a developer VLAN or prove network authorization. Preserve existing per-device Wi-Fi credentials during import and use the supported, reviewed network authorization workflow for your hardware. Complete automatic developer admission is tracked as unfinished in [progress](progress.md).

MAC admission can be spoofed. A stronger optional design uses a dedicated developer segment and supported 802.1X/RADIUS or device-specific credentials; availability depends on your APs and authentication infrastructure.

## Change lifecycle

```mermaid
flowchart LR
    Inspect["Fresh discovery"] --> Preview["Structured preview + baseline hash"]
    Preview --> Approve["Explicit approval + both write gates"]
    Approve --> Lock["Claim router generation/lock"]
    Lock --> Backup["Persist encrypted before-state"]
    Backup --> Apply["Minimal owned changes"]
    Apply --> Readback["Read actual configuration"]
    Readback --> Outcome["VERIFIED configuration or ERROR"]
```

Writes require both `ROUTER_WRITES_ENABLED=true` and that router's write-enable flag. A preview expires after ten minutes. Relevant configuration changes invalidate its baseline hash. Managed comments use `lantern:DEVICE_UUID:purpose`; unrelated manual entries must not be edited or deleted.

The network-admission write allowlist includes leases, selected address-list operations and wireless access/registration tables. The separate infrastructure subsystem adds typed system-identity, wireless-interface, backup, reboot, compatible-package upgrade and bounded ping operations; see [Suro operations](suro-operations.md). It is not a generic RouterOS command API and does not replace the whole router firewall or bridge configuration.

## Quarantine limitations

Wireless rejection previews are implemented for the discovered stacks. They place rejection before potentially matching entries and can request disassociation. Readback checks the resulting configuration.

That does not establish complete quarantine. Wired paths, other APs, existing shared-Layer-2 traffic, IPv6 and remediation connectivity need separate topology-specific protection and tests. The current system therefore reports `RESTRICTION_APPLIED_VERIFICATION_REQUIRED`, rather than declaring full isolation verified.

Automatic enforcement additionally requires continuous mode, explicit policy opt-in, elapsed grace period, warm server state and fresh reachable routers/association evidence. A server outage alone must not become a speculative disconnect operation.

See the [CHR/AP test matrix](developers/testing.md) before enabling these writes. Full production/remediation VLAN provisioning and independent release verification remain implementation work.

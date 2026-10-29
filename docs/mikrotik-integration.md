# MikroTik integration and safe network changes

## Supported transport and discovery

The current production transport implementation is RouterOS REST over verified HTTPS. RouterOS API-SSL and SSH fallback adapters are not implemented. Enable `www-ssl` with a valid certificate and a dedicated restricted management account according to [MikroTik's REST documentation](https://manual.mikrotik.com/docs/developer-guides/rest-api/).

REST credentials remain server-side. Current RouterOS documentation describes `read`, `api` and `rest-api` permissions for read-only access; confirm the exact permissions on your installed version. Avoid broad administrative/sensitive permissions for initial discovery. Use a separate reviewed write-capable account only when ready for controlled changes.

Do not disable TLS verification. If the router uses a local CA, place the public CA file under `data/trust/` and enter its container path, such as `/data/trust/router-ca.crt`, during registration. The TLS certificate must contain the literal management IP used by the connector.

The application accepts literal private/allowlisted management IPs to reduce SSRF/DNS-rebinding risk. Keep RouterOS management reachable only from approved management infrastructure and retain a separate WinBox/console recovery path.

## First connection

1. Back up the router with existing administration tooling and confirm recovery access.
2. Add its name, HTTPS address, dedicated username/password and optional CA path in the dashboard.
3. Run read-only discovery.
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
    Preview --> Approve["MFA approval + both write gates"]
    Approve --> Lock["Claim router generation/lock"]
    Lock --> Backup["Persist encrypted before-state"]
    Backup --> Apply["Minimal owned changes"]
    Apply --> Readback["Read actual configuration"]
    Readback --> Outcome["VERIFIED configuration or ERROR"]
```

Writes require both `ROUTER_WRITES_ENABLED=true` and that router's write-enable flag. A preview expires after ten minutes. Relevant configuration changes invalidate its baseline hash. Managed comments use `lantern:DEVICE_UUID:purpose`; unrelated manual entries must not be edited or deleted.

The current write allowlist includes leases, selected address-list operations and wireless access/registration tables. It is not a generic RouterOS command API and does not replace the whole router firewall or bridge configuration.

## Quarantine limitations

Wireless rejection previews are implemented for the discovered stacks. They place rejection before potentially matching entries and can request disassociation. Readback checks the resulting configuration.

That does not establish complete quarantine. Wired paths, other APs, existing shared-Layer-2 traffic, IPv6 and remediation connectivity need separate topology-specific protection and tests. The current system therefore reports `RESTRICTION_APPLIED_VERIFICATION_REQUIRED`, rather than declaring full isolation verified.

Automatic enforcement additionally requires continuous mode, explicit policy opt-in, elapsed grace period, warm server state and fresh reachable routers/association evidence. A server outage alone must not become a speculative disconnect operation.

See the [CHR/AP test matrix](developers/testing.md) before enabling these writes. Full production/remediation VLAN provisioning and independent release verification remain implementation work.

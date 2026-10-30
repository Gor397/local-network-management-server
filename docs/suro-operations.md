# Administering Suro

Suro opens in Armenian for a new browser profile. Use the language selector to switch instantly to Russian or English. A question mark beside a field/action opens help in that language. The Help Center searches the current language's explanations. Technical evidence retains original system field names so it can be compared with Windows or RouterOS.

## Start safely

1. Install using the existing [Compose procedure](installation.md), establish HTTPS trust, and create a unique administrator password.
2. Sign in with username and password. OTP is optional; see [authentication](authentication.md).
3. Keep `OPERATION_MODE=read_only` and leave software deployment, SSH, and automatic recovery disabled initially. The banner under the top bar shows the active mode.
4. Register one test router/AP, run read-only discovery, and compare imported state with your existing administration tools.
5. Enroll a Windows test machine in Audit Mode. Review owner information separately from compliance.

Rebranding does not require recreating the database, changing Compose project name, rotating keys, or reinstalling existing agents. Preserve `.env`, all of `data/`, and the database volume. Back up before migration; `docker compose up -d` runs additive migrations through the existing migration service. A binary rollback alone does not reverse a schema migration; use a reviewed database restore if necessary.

## Staged rollout

| Stage | Mode | Do | Continue only when |
|---|---|---|---|
| 1. Inventory | `read_only` | Register routers with read-only accounts, discover, review **Network inventory**, classify infrastructure and admin workstations | WinBox shows no change; management devices are identified |
| 2. Recovery path | `read_only` | Take router backups with your existing tools, write down console/WinBox recovery steps, register developer/admin exceptions | A management path independent of Suro is tested |
| 3. Dry run | `dry_run` | Preview the intended admission/reservation/batch changes and review the exact operations | The operations touch only the intended entries |
| 4. Pilot | `controlled_test` | List one or two routers in `TEST_ROUTERS` and a few laptops in `TEST_DEVICES`; enroll, apply, verify readback, restart client/server/router | Exempt and unrelated devices keep access; failures recover |
| 5. Gradual | `production` | Enable per-router writes group by group | Each group stays healthy for an agreed period |

Full-network enforcement is never switched on automatically. Each stage change is an edit to `.env` and a restart, made by an administrator.

## Network explorer and computer status

Network → **Network explorer** shows AP groups, their access points and the registered computers on them now. Selecting an access point lists its connected and previously seen computers; selecting a computer links to its full page. The status cards filter the lists.

Four facts are shown separately because they come from different sources: **registered** (in the Suro registry), **on Wi-Fi** (the newest MikroTik association list, trusted for three minutes), **agent online** (signed heartbeats within the deadline) and **compliance** (verified agent evidence). A wired computer or one on an AP Suro does not poll shows "Wi-Fi: no recent data", not offline. "Never seen" means neither source has ever observed the computer.

## Local administrator passwords

Computers prepared with the old kursant script have an `AcademyAdmin` password derived from the Wi-Fi MAC. Open the computer's **Local administrator** tab to see the old-script findings, choose the MAC, show the password (owner role and recent TOTP; audited) and record whether sign-in worked. Give new computers a generated random password. See [legacy credentials](developers/legacy-credentials.md), including the firewall reset the old startup task performs at every boot.

## Owners and device groups

The first logged-in user of an enrolled Windows machine sees a separate small identification window. Armenian is the default. Full name is required; rank is optional and “no military rank” is supported. The explanation identifies the administrative purpose. The background service securely submits the report. Without a logged-in user, identification remains pending.

Open Windows Devices → Owners / Users to search by assigned name or Windows account, filter by rank, inspect reported identities, and assign or correct an owner. A user report is not verification. Mark information verified only after your organization's review. Assignment history and export are permission-protected and audited. Use the authorized CSV export rather than copying database files.

Device Groups may overlap. A group can receive a policy, a compliance-sync request, an existing offline package, or a typed maintenance job. Before a group policy rollout, inspect the effective-policy view on a representative endpoint. Conflicting group controls are blocked; resolve them explicitly. Deleting a group does not delete its devices or repository files.

## Register and inspect MikroTik infrastructure

Network → Access Points contains physical routers, APs, and controllers. Choose the correct role; a management gateway is protected automatically. Editing the role, protection flag or pinned host key requires approval permission. For REST use the verified HTTPS origin. For legacy API-SSL use the TLS origin with port 8729 and select API_SSL. Trust the router's CA; never disable certificate validation. RouterOS versions before the supported modern login protocol require manual administration.

Discovery imports interfaces, SSIDs, DHCP, VLANs, firewall and available security metadata without changing existing Wi-Fi passwords. Unsupported metrics show as unavailable. The detail page exposes inventory, health, connections, logs, and backups. Sensitive fields are redacted. Read-only discovery cannot prove that every powered-off device's static IP is known.

AP Groups organize physical infrastructure and may overlap. A group template describes only supported wireless settings, such as SSID/disabled state; it does not replace firewall/bridge configuration. Conflicting group templates block application. Review compatibility separately for every target.

## Preview, authorize, verify

For an SSID change, interface change, reboot, backup, restore, upgrade, or diagnostic:

1. Choose the operation and targets. Declare independent management path IDs (or explicitly confirm separate recovery access). Set a schedule/window, batch size (default one), and stop-on-failure behavior.
2. Read the exact target list, differences, unsupported-feature warnings, and connectivity impact.
3. Establish an independent management/recovery path. Protected infrastructure requires typing its exact name and confirming recovery access.
4. Approve the concrete preview. Writes additionally need both global and per-router write gates enabled.
5. Watch each target's state in Maintenance Jobs. Approval/queueing is not completion. A reboot remains waiting until the API returns with evidence of an uptime reset.

Do not choose a large batch simply to finish faster. Disconnecting all APs may also disconnect the management path. Suro excludes already restarting routers from its available-path check, but it cannot infer an unmeasured physical topology; the administrator must verify recovery access.

A configuration snapshot is encrypted before mutation. Reviewed inverse-field restoration is available only when the earlier fields can be safely set back. Binary backup/restore requires pinned SSH/SFTP and the appropriate RouterOS permissions. Binary restore is limited to known matching hardware serial/version and can interrupt service. Retain WinBox/console access and an external backup. There is no automatic blanket firewall or bridge replacement.

## RouterOS package upgrades

Use Package Repository to upload a `.npk` with its SHA-256, exact RouterOS architecture, and expected version. Obtain it through a trusted vendor channel, then explicitly approve it. `.npk` packages do not use Windows Authenticode thumbprints; RouterOS performs its own package-signature validation. Suro checks object hash/architecture and expected returned version, but does not implement its own MikroTik package-signature parser.

Pin the router SSH host key through an independently trusted channel. Preview an upgrade on one test AP first. Suro creates an encrypted binary backup, transfers the approved file over pinned SFTP, and issues a controlled reboot. Newer releases within the same major version are supported by this workflow. Major migrations/downgrades, unknown compatibility, and complete bootloader recovery require a separate reviewed vendor procedure. Do not treat an upload or command acknowledgment as a successful upgrade.

## Incidents and automatic recovery

Network Diagnostics and the Incident Center show facts, probable causes, confidence, suggested actions, and linked infrastructure/endpoints. A common upstream outage is grouped rather than becoming one independent root-cause incident per PC. Buffered Windows events become available after a disconnected client reconnects. No observation source proves everything; investigate the evidence before acting.

Acknowledge an incident, assign an administrator, investigate, then resolve with a reason. New evidence can reopen a resolved incident. Maintenance windows suppress expected network downtime during planned work.

Automatic Recovery is off by default. Choose recovery conditions separately: sustained critical CPU/RAM pressure, or an unexpectedly disabled radio. Radio recovery is opt-in and requires approved desired state explicitly declaring that interface enabled, a supported wireless stack, and several sustained API observations. Suro restores only the enabled flag, reads it back, and prefers this correction over rebooting the AP; it preserves the SSID and credentials. Offline, authentication, drift, restart, weak-signal and error incidents remain visible for investigation; they do not all trigger automatic reboots. An unreachable AP has no API reboot path. There is no independent power-controller integration in this release.

Enabling recovery requires a reviewed AP role, a known independent management path, an appropriate maintenance window, cooldown, and attempt budget. Gateways/protected infrastructure are excluded. Shared/upstream problems block AP reboot proposals, including simultaneous critical pressure across multiple APs or the management gateway. Queued recovery rechecks current authorization and maintenance/upstream gates before connecting. Repeated failures or the attempt budget disable recovery and escalate. Review all results; never enable recovery to hide a cabling, upstream, or power fault.

## Topology and resource budgets

Topology shows observed reachability/association and configured groups, subnets, and VLAN metadata. Unknown physical uplinks remain unknown. Use filters and select a node for details. A diagram is not proof of isolation between clients on the same broadcast domain.

Settings → Monitoring Settings controls low-resource mode, health/full-inventory intervals, bounded router concurrency, retention, and the global recovery gate. Defaults favor lightweight operation: a single worker, short health polls, less frequent full inventory, bounded diagnostics, and the existing bounded software-transfer subsystem. Expensive transfer tasks run separately from health polling within that worker. Use System Health to observe actual memory/CPU before increasing concurrency. No fleet-size performance guarantee has been established yet.

## Recovery and remaining boundaries

Preserve standard-user security boundaries and all original configuration. Complete VLAN admission/quarantine and independent traffic-path verification remain separate implementation work; an ACL readback is not global quarantine. Disk migration remains assessment-only and never repartitions during onboarding. Windows installation, real AP operations, roaming, and firmware recovery still need the documented lab validation. See [progress](progress.md), [recovery](recovery.md), and [testing](developers/testing.md).

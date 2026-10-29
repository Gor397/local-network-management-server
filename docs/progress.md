# Implementation and verification ledger

Last local verification: **2026-10-29**. This is a development release, not a statement that all requested production behavior is complete.

Legend: **Implemented** means executable source exists; **Automated** means a relevant local test/build passed; **Simulated** means fake external-system responses were used; **Hardware** means actual Windows/RouterOS behavior was observed. A build does not count as hardware verification.

## Phase checklist

| Phase | Implemented | Validation | Outstanding |
|---|---|---|---|
| 1 — Foundation | FastAPI, PostgreSQL models/migrations, sessions/RBAC/TOTP, basic dashboard, Compose | Backend tests, migration round-trip, frontend build/catalog tests; isolated HTTPS/PostgreSQL smoke passed | Broader browser E2E, security/load review |
| 2 — MikroTik inventory | Verified-HTTPS REST, three wireless menu families, encrypted discovery, read-only inventory, allocation/lease previews, developer inventory | Simulated fixtures and error paths | Physical models, CHR concurrency/conflict tests, alternate transport, complete Wi-Fi admission/VLAN provisioning |
| 3 — Windows audit agent | Native Service source, CNG identity, approved enrollment, signed requests, heartbeat, inventory and cache | Windows-target cross-build; cross-platform cryptographic contracts | Real Windows Service/certificate/ACL/inventory VM verification; signed MSI build/install |
| 4 — Policy/compliance | Immutable signed versions, scopes, assignment, exceptions, explicit check catalog/freshness, safe allowlisted correction, alerts | Policy/evidence/auth tests | Complete effective-rule/settings verification, scope UI, timing consistency, account/profile migration |
| 5 — Network enforcement | Reviewed wireless rejection, ownership/baseline/readback checks, partial-failure records, gated automatic path | Simulated connector/planner/error tests | Complete production/remediation VLANs, wired/L2/IPv6 isolation, independent evidence and verified release |
| 6 — Storage/restrictions | Read-only migration assessment, backup/blocker report, account/firewall maintenance tooling | Assessment safety tests; compilation | Approved destructive storage executor and verified known-folder/data migration are unavailable; Windows effective-policy verification |
| 7 — Hardening/operations | MFA, signed manifest/package checks, SSH broker, resource caps, low-resource settings, offline/backup/recovery scripts, docs | Auth/upload/task/maintenance tests; build checks | Restore drill, crash/concurrency/load tests, certificate rotation, retention cleanup, signed update completion verification, independent security review |

## Additional mandatory features

| Feature | Current implementation | Verification / gap |
|---|---|---|
| English / Armenian / Russian | Locale context and separate Unicode catalogs; instant browser switching | Catalog consistency tested; dynamic error/check/action coverage is incomplete and requires UI review |
| Offline packages | Resumable upload, deduplicated objects, approval, bounded task claims, signed manifests, ranged/throttled download | API tests; real installers/signatures/drivers need Windows tests |
| One/group/all deployment targets | Backend supports explicit device IDs, groups or all managed devices | Basic UI supports one/all; complete multi/group workflow UI remains incomplete |
| Driver/update/feature/language packs | Typed Windows handlers and compatibility/signature gates | Source implemented; full bundle/catalog and post-install detection need expansion/testing |
| Display language / keyboard | Typed maintenance job, offline-resource prerequisite, intended-user logon task | Windows VM verification required; completion after logon is not yet automatically verified |
| Signed agent updates | Pinned-publisher external MSI staging | Post-restart verification/update recovery incomplete |
| Browser SSH | MFA/RBAC, ticket, pinned key, WebSocket terminal, encrypted frames, timeout/termination | Core implementation; full live broker/Windows integration tests pending |
| Docker production | Backend/worker image, PostgreSQL, multistage dashboard/proxy, migrations, persistent storage and configurable caps | Images built; all long-running lab services healthy and HTTPS/PostgreSQL smoke passed |
| Low Resource Mode | Bounded processes, worker cadence, content-addressed files, incremental ETags, configurable limits | Full workload benchmarks/global transfer limiter/cleanup remain incomplete |
| Reusable Codex context | Three short tracked skills, code map, focused-check and lab helpers | All three skill validators passed; 25 documentation/skill files checked; helper preservation/idempotency tests passed |

## Current automated evidence

| Check | Most recent observed result |
|---|---|
| Backend suite | 28 tests passed, including developer-helper checks |
| Agent Release cross-build | Succeeded with zero warnings/errors |
| Agent cryptographic contract executable | 7 passed |
| Frontend catalog tests | 2 passed |
| Frontend production build | Succeeded |
| Frontend dependency audit | Zero known vulnerabilities in last audit |
| Docker images | Backend/web built locally; startup test found and corrected unquoted tmpfs options; Compose configuration valid |
| Isolated HTTPS/PostgreSQL smoke | Passed: TLS validation, MFA login, device registration, policy publish/assign, unverified gate, resource API |
| Windows VM, real AP, CHR, destructive storage | Not performed |

## Acceptance scenarios

| Scenario | Status |
|---|---|
| A — New managed computer | Protocol tested; real Windows onboarding not yet verified |
| B — Existing configuration | Audit-preserving code/fixtures; real Windows before/after test pending |
| C — No D: volume | Assessment reports manual intervention; no automatic disk changes |
| D — Firewall drift | Detection/correction source exists; Windows behavior pending |
| E — Missing mandatory check | Automated: cannot reach 100% |
| F — Missing heartbeat | Automated stale-state/worker behavior; network action requires infrastructure tests |
| G — Noncompliant device | Wireless change path simulated; complete quarantine not delivered |
| H — Policy update | Automated publication/assignment invalidation; endpoint application requires VM test |
| I — Device exception | Automated isolation of exception scope and core-gate protection |
| J — Developer MAC | Automated unmanaged inventory/lease preview; complete automatic authorization pending |
| K — AP roaming | Central identity/address model exists; physical roaming test pending |
| L — API failure | Automated: enforcement failure stays error |
| M — Existing MikroTik entries | Simulated preservation/redaction; real hardware import pending |
| N — Security/recovery | Auth/crypto tests and recovery tooling exist; Windows permission and restore drills pending |

## Next work in dependency order

1. Complete restore validation and PostgreSQL concurrency/crash tests beyond the passing Compose smoke.
2. Build/sign/install MSI in Windows VMs and verify SYSTEM identity persistence, ACLs, audit inventory and safe operations.
3. Complete locale/error coverage, layer/group management UI and browser E2E flows.
4. Implement capability-specific segmented admission/quarantine and independent traffic-path verification in CHR/AP labs.
5. Complete installer-specific detection, bundle handling, maintenance expiry, update verification and retention controls.
6. Implement the separately approved backup-bound storage workflow only after its recovery and file-integrity tests exist.

Do not bypass unknown checks or enable production enforcement to conceal these gaps. Update each row when there is new implementation or actual verification evidence.

# Implementation and verification ledger

Last local verification: **2026-10-30**. This is a development release, not a statement that all requested production behavior is complete.

Legend: **Implemented** means executable source exists; **Automated** means a relevant local test/build passed; **Simulated** means fake external-system responses were used; **Hardware** means actual Windows/RouterOS behavior was observed. A build does not count as hardware verification.

## Phase checklist

| Phase | Implemented | Validation | Outstanding |
|---|---|---|---|
| 1 — Foundation | FastAPI, PostgreSQL models/migrations, sessions/RBAC/TOTP, basic dashboard, Compose | Backend tests, migration round-trip, frontend build/catalog tests; isolated HTTPS/PostgreSQL smoke passed | Broader browser E2E, security/load review |
| 2 — MikroTik inventory | Verified-HTTPS REST, three wireless menu families, encrypted discovery, read-only inventory, allocation/lease previews, developer inventory | Simulated fixtures and error paths | Physical models, CHR concurrency/conflict tests, API-SSL hardware interoperability, complete Wi-Fi admission/VLAN provisioning |
| 3 — Windows audit agent | Native Service source, CNG identity, approved enrollment, signed requests, heartbeat, inventory and cache | Windows-target cross-build; cross-platform cryptographic contracts | Real Windows Service/certificate/ACL/inventory VM verification; signed MSI build/install |
| 4 — Policy/compliance | Immutable signed versions, scopes, assignment, exceptions, explicit check catalog/freshness, safe allowlisted correction, alerts | Policy/evidence/auth tests | Complete effective-rule/settings verification, timing consistency, account/profile migration |
| 5 — Network enforcement | Reviewed wireless rejection, ownership/baseline/readback checks, partial-failure records, gated automatic path | Simulated connector/planner/error tests | Complete production/remediation VLANs, wired/L2/IPv6 isolation, independent evidence and verified release |
| 6 — Storage/restrictions | Read-only migration assessment, backup/blocker report, account/firewall maintenance tooling | Assessment safety tests; compilation | Approved destructive storage executor and verified known-folder/data migration are unavailable; Windows effective-policy verification |
| 7 — Hardening/operations | MFA, signed manifest/package checks, SSH broker, resource caps, low-resource settings, offline/backup/recovery scripts, docs | Auth/upload/task/maintenance tests; build checks | Restore drill, crash/concurrency/load tests, certificate rotation, retention/load review, signed update completion verification, independent security review |

## Additional mandatory features

| Feature | Current implementation | Verification / gap |
|---|---|---|
| English / Armenian / Russian | Locale context and separate Unicode catalogs; instant browser switching | Catalog consistency tested; Armenian default; native help rendering/search and login tested; comprehensive linguistic/browser review remains necessary |
| Offline packages | Resumable upload, deduplicated objects, approval, bounded task claims, signed manifests, ranged/throttled download | API tests; real installers/signatures/drivers need Windows tests |
| One/group/all deployment targets | Backend supports explicit device IDs, groups or all managed devices | UI supports individual/all and group rollout; multi-target API covered; installer-specific verification requires Windows |
| Driver/update/feature/language packs | Typed Windows handlers and compatibility/signature gates | Source implemented; full bundle/catalog and post-install detection need expansion/testing |
| Display language / keyboard | Typed maintenance job, offline-resource prerequisite, intended-user logon task | Windows VM verification required; completion after logon is not yet automatically verified |
| Signed agent updates | Pinned-publisher external MSI staging | Post-restart verification/update recovery incomplete |
| Browser SSH | Optional enforced MFA/RBAC, ticket, pinned key, WebSocket terminal, encrypted frames, timeout/termination | Core implementation; full live broker/Windows integration tests pending |
| Docker production | Backend/worker image, PostgreSQL, multistage dashboard/proxy, migrations, persistent storage and configurable caps | Images built; all long-running lab services healthy and HTTPS/PostgreSQL smoke passed |
| Low Resource Mode | Bounded processes, worker cadence, content-addressed files, incremental ETags, configurable limits | Full workload benchmarks/global transfer limiter/cleanup remain incomplete |
| Reusable Codex context | Three short tracked skills, code map, focused-check and lab helpers | All three skill validators passed; 28 documentation/skill files checked; helper preservation/idempotency tests passed |

## Current automated evidence

| Check | Most recent observed result |
|---|---|
| Backend suite | See Suro validation below; original regression coverage retained |
| Agent Release cross-build | Succeeded with zero warnings/errors |
| Agent cryptographic contract executable | 7 passed |
| Frontend catalog tests | 16 passed |
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
3. Review native translations and broaden browser E2E; layer/group/owner/AP/incident interfaces now exist.
4. Implement capability-specific segmented admission/quarantine and independent traffic-path verification in CHR/AP labs.
5. Complete installer-specific detection, bundle handling, maintenance expiry, update verification and retention controls.
6. Implement the separately approved backup-bound storage workflow only after its recovery and file-integrity tests exist.

Do not bypass unknown checks or enable production enforcement to conceal these gaps. Update each row when there is new implementation or actual verification evidence.

## Suro expansion — phases A–F

The rows below extend the original ledger. “Implemented” refers to executable source, not a claim of hardware qualification or complete production readiness.

| Phase | Implemented | Automated / simulated coverage | Still unverified or constrained |
|---|---|---|---|
| A — Branding, language, help | Suro brand/title/login; Armenian initial locale; instant HY/RU/EN switching; versioned native articles and searchable help; grouped navigation; optional MFA defaults | Component tests exercise Armenian login, optional OTP, native question-mark dialogs/search, translation structure; production bundle | Linguistic/accessibility review across every workflow; full browser E2E |
| B — Owners and device groups | Separate owner/current user/self-report; optional rank; SID-bound named-pipe onboarding helper; administrative correction/verification/history/export; group CRUD, overlapping membership, policy conflicts/effective view, group software/maintenance jobs | API Unicode/owner separation/history/CSV formula/auth tests; group conflicts and repository reuse; service/helper cross-build | Windows interactive-session, standard-user pipe/SCM/ACL, first logon and signed MSI upgrade tests |
| C — AP inventory/groups | Physical inventory separate from radios; model/serial/OS/available sensors/interfaces/SSIDs/DHCP/VLAN/firewall/security/logs; REST + API-SSL; overlapping AP groups; recent/stale client inventory | Fixtures preserve passwords/manual entries; unknown sensor nulls; native framing/optional-menu error tests; existing PostgreSQL migration preserved | API-SSL device interoperability, model-specific sensor/radio data, physical discovery/roaming; no broad unauthenticated LAN scan |
| D — Safe AP operations | Typed wireless/system-name edits, snapshots, pinned SFTP binary backup/restore and approved .npk upgrade, diagnostics, archive; expiring previews; sequential durable batches, protected confirmations, declared management paths, readback and uptime-reset verification | Configuration preservation/backup/readback; invalid SSID; protected confirmation; success/uncertain/unreachable reboot paths; stops after failure; firmware hash/returned-version contracts and real loopback SFTP host-key rejection | Real firmware/SFTP/recovery testing; no generic raw commands; no blanket firewall/VLAN editor; major OS transitions/downgrades require separate manual review; no RouterOS safe-mode transaction claim |
| E — Monitoring/correlation | Bounded async health polling; less frequent inventory; adaptive failure cadence; bounded Windows WLAN/event buffer; deduplicated incidents combining client/AP evidence; upstream aggregation; CPU/RAM, restarts, signal, auth errors, DHCP duplicates, configuration drift/interface errors | Correlated client/AP facts and confidence; single shared-outage incident; diagnostics dedup/secret stripping; resource settings validation | Real event/log coverage and timing; topology-specific VLAN/firewall/DHCP root causes are not all implemented; large-fleet benchmarks |
| F — Recovery/topology/operations | Disabled-by-default sustained-resource recovery and opt-in approved-radio restoration; maintenance/path/upstream/protected/cooldown/attempt gates; loop escalation; observed/configured/unknown topology; incident assignment/history; persistent monitoring settings/retention; lightweight lazy pages | Recovery rejects insufficient/upstream/protected/repeated failures; topology assurance labels; Compose HTTPS/PostgreSQL smoke with preserved lab state | Automatic executor supports corroborated sustained CPU/RAM and explicitly approved radio-enabled correction; no independent power controller; no proof of arbitrary physical links; restore/crash/load drills still required |

### Suro validation

- Backend: **76 tests passed**, including the final preservation and authorization regressions.
- Dashboard: **16 component/catalog tests passed**, production build passed; no missing direct literal UI keys in the latest scan.
- Agent: .NET 10 Release cross-build of the service and separate user-session helper succeeded; **7 cryptographic contracts passed**. No Windows VM execution or signed MSI build was performed here.
- Compose: backend/web images built, existing isolated PostgreSQL upgraded, all long-running services healthy. Verified HTTPS, optional TOTP and password-only login, policy publication/assignment, missing-evidence score gate, Unicode owners, separate groups, topology, disabled recovery defaults and resource endpoint. The 2026-10-29 rebuilt-image HTTPS/PostgreSQL smoke passed and the lab was stopped. On 2026-10-30 the retained volume existed but matching temporary keys/environment were absent; the new preservation guard refused initialization. No fresh Compose smoke was claimed for this continuation.
- Initial isolated idle observation: API cgroup memory approximately **104 MiB**, under its configured 384 MiB cap. This is one idle sample, not a fleet-load result.
- Production routers/endpoints were not contacted or modified. All AP mutation/recovery behavior is fixture-tested only. Full network quarantine and destructive disk migration retain the original restrictions above.

### Requested Suro acceptance cases

| Cases | Evidence |
|---|---|
| 1–3 brand, Armenian default, localized help | Dashboard component/catalog tests and built HTML |
| 4–5 non-destructive import/register | RouterOS mock API/import fixtures and durable inventory; physical test pending |
| 6–7 AP/device groups and offline repository | API/group/conflict/deployment tests; AP batch simulations |
| 8–9 user identification/owner editing | Unicode API/history tests plus compiled WinForms/pipe source; Windows execution pending |
| 10–11 password login and optional MFA | Backend tests and Compose HTTPS smoke; native MFA docs in three languages |
| 12–13 AP health/cross-source incidents | Sensor tests and combined client/AP correlation fixtures |
| 14–16 recovery loops, batch safety, unreachable AP | Guard, stop-on-failure, declared-path and observed-uptime simulations |
| 17–18 validated/audited edits and honest topology | Configuration/readback/audit APIs; invalid-value tests; assurance labels |
| 19 Compose deployment | Rebuilt image startup/migration/HTTPS smoke |
| 20 constrained resources | Existing container caps, bounded I/O/jobs, retention and resource endpoint; load qualification pending |

### 2026-10-30 continuation

Implemented separately selected recovery conditions, radio-first correction with readback, execution-time authorization/window/upstream checks, shared/gateway resource-pressure suppression, approval-only protection/host-key metadata edits, persisted recovery settings in the dashboard, approved-package selectors and additional AP group actions. New translations/help cover Armenian, Russian and English. Backend regression suite: **76 passed**. Dashboard: **16 tests passed** and the production bundle built after the final locale fix. Native Windows source was not changed in this continuation; its previous cross-build/contracts remain historical evidence rather than a new Windows test.

The lab storage guard preserves retained PostgreSQL data when temporary matching keys/configuration are missing. Recover the complete matching lab backup before running a new Compose smoke. This condition does not affect production configuration, which was not read or changed. Full Windows/AP/CHR qualification and the original incomplete segmentation/storage workflows remain outstanding.

### 2026-10-30 safety continuation (Claude Code)

A concurrent Codex session was stopped at the user's request. Its finished work (post-restart verification, transfer limits, developer admission profiles) passes the backend suite. Its unfinished disk-storage workflow (`services/storage.py`, `api/storage.py`) is **not mounted** and remains unavailable; see [audit findings](audit/findings.md).

| Area | Implemented | Automated evidence | Still unverified |
|---|---|---|---|
| Safety modes | `OPERATION_MODE` read_only/dry_run/controlled_test/production; transport wrapper on every RouterOS adapter; plan, batch, SFTP, recovery and worker gates; agent work claims and signed `AUDIT` mode; dashboard banner and `/safety` | `test_safety_modes.py` (10 tests, fake transport) | Real router/agent behavior; agent refetch after a mode change (ETag includes mode, and the agent accepts equal revisions per `PolicyWorker.cs`) not executed on Windows |
| Passive network inventory | `/network/inventory` merging stored DHCP/ARP/Wi-Fi data; randomized-MAC and duplicate-IP flags; provable client state; descriptive labels (migration `0006`); dashboard page in HY/RU/EN with help | `test_inventory.py` (2), frontend test, migration up/down/up on SQLite | Real router data; PostgreSQL migration run |
| Dual-network laptop | `scripts/netcheck.py` (read-only); bootstrap writes narrow subnets and `read_only`; Compose falls back to loopback | `test_netcheck.py` (2); run on the development laptop, where it correctly flagged the uplink overlap and the Ethernet egress | Network B topology (Wi-Fi was down) |
| Agent setup | `CLAUDE.md`, `.claude/skills` links, `.claude/settings.json` deny/ask rules, `AGENTS.md` safety and context sections | Skills discovered by Claude Code; docs check | — |

Backend: **103 passed**. Dashboard: **17 passed**, production build passed. Not run: .NET agent build (no SDK here), Compose smoke, hardware.

### 2026-10-30 first real-network read (Claude Code)

Read-only contact with the live RouterOS 6.49 CAPsMAN controller, approved by the user, plain API only. Added the opt-in read-only `API` transport (`PlainRouterOS`), CAPsMAN `remote-cap` discovery, network-address rejection, tolerance for legacy-encoded values and bounded log reads. All of these were found against this real router. **Hardware (read-only):** discovery returned 80 CAPs, 237 Wi-Fi registrations, 853 leases and 153 ARP entries in 5.6 s. No write was attempted. Backend: **109 passed**. Write paths and API-SSL with a certificate remain unverified on hardware.

CAPsMAN follow-up: the 80 CAPs are now listed, groupable access points, observed only through the controller. Connected clients are attributed to their CAP, with DHCP hostname and access-list label. Network inventory lists end devices first. Covered by `test_capsman.py` (4 tests, fixture shaped like the real data). The mapping was checked against the stored real snapshot: 80 CAPs, 92/93 clients attributed. Backend: **116 passed**; dashboard: **17 passed**.


### 2026-10-30 legacy credentials and Network Explorer (Claude Code)

| Area | Implemented | Automated evidence | Still unverified |
|---|---|---|---|
| Legacy kursant compatibility | Exact port of `Convert-MacToUniquePassword`; candidate-MAC selection matching the script; `AdminCredential` table (migration `0008`); owner-only `credentials` permission; reveal needs recent TOTP regardless of the optional-MFA setting, is audited without the secret and sent `no-store`; random 20-character scheme sealed with the Vault for new computers; detection of the boot-time firewall-reset task, its allowlist versus the server address, the named standard user and WinRE state; device **Local administrator** tab in HY/RU/EN | `test_legacy_credentials.py` (7); 5,004 vectors agree with an independent JavaScript transliteration; migration round-trip | Output of the original PowerShell function (one `-shl` widening assumption; see [legacy credentials](developers/legacy-credentials.md)); `Inspect.ps1` additions not executed on Windows; no agent password set/rotate or task-retirement operation |
| Network Explorer | `GET /network/explorer`: registered, Wi-Fi association, agent heartbeat, compliance, awaiting enforcement, failed operations and never-seen as separate fields with sources; CAP attribution shared with `/network/clients`; tree page with lazy branches, status filters, search and details pane; help in HY/RU/EN | `test_explorer.py` (3), existing CAPsMAN/client tests; `explorer.test.tsx` (4) including Armenian/Russian rendering | Real 80-CAP data volume; rendered-browser layout check (no headless browser on the development laptop) |
| Usability CSS | 40px buttons/inputs, larger table/badge/tab text, visible `:focus-visible`, wrapping grids and toolbars | Production build | Visual review of every page in all three locales |

Backend: **126 passed**. Dashboard: **21 passed**, production build passed. Not run: .NET build (no SDK), Windows VM, Compose smoke, browser E2E.

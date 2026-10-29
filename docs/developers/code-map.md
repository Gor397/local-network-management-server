# Code map: where behavior lives

All paths below are relative to the repository root. Start with the smallest row matching the task instead of loading every module.

## Backend

| Responsibility | Files | What to look for |
|---|---|---|
| Application creation and request boundary | `backend/app/main.py` | `create_app`, router mounting, error formatting, request limits |
| Configuration | `backend/app/config.py` | Environment names, safe feature gates, low-resource defaults |
| Database sessions and time | `backend/app/db.py`, `backend/app/auth/dependencies.py` | UTC storage, commit/rollback behavior, `db_session` |
| Persistent records | `backend/app/models/__init__.py` | Foreign keys, uniqueness, timestamps; schema changes need migrations |
| Browser authentication | `backend/app/api/auth.py` | Argon2, sessions, CSRF, TOTP setup and replay protection |
| Authorization | `backend/app/auth/dependencies.py` | `PERMISSIONS`, `require`, recent MFA |
| Cryptography | `backend/app/security/crypto.py` | `Vault`, RSA policy signatures, device certificate issuance |
| Inventory and exceptions | `backend/app/api/devices.py`, `backend/app/services/devices.py` | Registration, effective state, reassessment, alert deduplication |
| Declarative schema and check catalog | `backend/app/policies/schema.py` | `PolicyDocument`, `CATALOG`, `merge_layers` |
| Policy layering | `backend/app/policies/resolver.py` | Global/class/group/device applicability |
| Publication and assignment | `backend/app/api/policies.py` | Immutable versions, optimistic concurrency, invalidation |
| Compliance decisions | `backend/app/compliance/engine.py` | Freshness, source/version checks, mandatory gates, score |
| Agent protocol | `backend/app/api/agent.py` | Enrollment approval, ETags, heartbeat, evidence intake |
| Router transport | `backend/app/mikrotik/connector.py` | HTTPS validation, optional menu probing, redaction, stable hash |
| Router planning | `backend/app/mikrotik/planner.py` | Allocation, lease previews, wireless rejection and readback |
| Router orchestration | `backend/app/services/network.py` | Durable claim, backup, ownership check, apply, verification |
| Router-facing admin API | `backend/app/api/mikrotik.py` | Register/discover, subnets, developer MAC workflow, approvals |
| Offline packages and deployments | `backend/app/api/deployments.py` | Resumable uploads, approvals, leases, concurrency, ranged downloads |
| Typed maintenance | `backend/app/api/maintenance.py` | Locale, OpenSSH, firewall and reboot jobs; no arbitrary command field |
| SSH sessions | `backend/app/api/ssh.py` | Pinned host key, tickets, WebSocket bridge, encrypted recordings |
| Dashboard and events | `backend/app/api/operations.py` | Counters, alerts, groups, roles, resource metrics, small SSE events |
| Background processing | `backend/app/workers/main.py` | Discovery loop, expiry, retention, warm-up and enforcement gates |
| Local administrator recovery | `backend/app/cli.py` | Interactive first admin and console recovery |
| Storage assessment | `backend/app/services/migration.py` | Report generation; destructive execution is intentionally unavailable |

The empty package directories under `monitoring`, `notifications`, and similar names are organizational slots, not separate running services. Current notification code is `notify()` in `services/devices.py`; monitoring is in the worker and agent inspector.

## Windows agent

```text
Program.cs
 ├─ --enroll → Enrollment/EnrollmentClient.cs
 └─ Windows Service → Service/PolicyWorker.cs
                       ├─ Security/AgentTransport.cs
                       ├─ PolicyEngine/SignedDocument.cs
                       ├─ Monitoring/Inspect.ps1
                       ├─ PolicyEngine/Remediate.ps1
                       ├─ Service/MaintenanceRunner.cs
                       └─ Deployment/DeploymentRunner.cs
```

| Area | Entry point | Important detail |
|---|---|---|
| Machine identity | `Enrollment/EnrollmentClient.cs` | Persistent CNG machine key; CSR retained for retry |
| Request signing | `Security/AgentTransport.cs` | Signs method, target, timestamp, nonce and exact body hash |
| Cached state and logs | `Security/LocalState.cs` | Atomic replacement and bounded local log files |
| Policy validation | `PolicyEngine/SignedDocument.cs` | Signature first, then device, expiry, revision and schema |
| Inventory | `Monitoring/Inspect.ps1` | Read effective Windows state; unsupported checks remain unknown |
| Safe remediation | `PolicyEngine/Remediate.ps1` | Fixed `ValidateSet`; never accepts a shell command |
| Installer execution | `Deployment/Install.ps1` | Hash, Authenticode, publisher, build and architecture checks |
| Agent update staging | `Deployment/Stage-AgentUpdate.ps1` | External scheduled MSI task so the service does not replace itself |
| Firewall maintenance | `Firewall/Apply-Allowlist.ps1` | Backup, conflict check, management connectivity and recovery task |
| SSH enablement | `Network/Enable-OpenSSH.ps1` | Requires installed offline capability and reviews existing rules |
| User language | `Deployment/Configure-Locale.ps1`, `Apply-UserLocale.ps1` | User preferences run as the user at logon, not as SYSTEM |
| MSI | `agent/installer/` | WiX, signing, ACLs, SCM permissions and enrollment wrapper |

Paths in this table are relative to `agent/src/` unless explicitly stated otherwise.

## Dashboard

| File | Responsibility |
|---|---|
| `frontend/src/App.tsx` | Current page components, forms, modals, auth shell and navigation |
| `frontend/src/api/client.ts` | Same-origin requests, CSRF and normalized API errors |
| `frontend/src/hooks/useData.ts` | Request lifecycle and revision-triggered refresh |
| `frontend/src/i18n.tsx` | Locale context and dictionary lookup |
| `frontend/src/locales/{en,hy,ru}.json` | Separate Unicode translation catalogs |
| `frontend/src/types/index.ts` | Shared browser interfaces |
| `frontend/src/style.css` | Responsive layout, tables, forms and terminal styling |

Navigation uses `location.hash`, for example `#devices/DEVICE_UUID`; there is no React Router dependency. SSH and incremental SHA-256 code are loaded on demand. SSE sends small revision markers, then pages fetch the records they need.

Page functions currently live together in `App.tsx`; splitting a substantial page into `src/pages/` is appropriate as it grows. Avoid inventing an additional frontend framework.

## Database changes

The initial migration is an explicit schema snapshot. Later migrations add globally unique reservation addresses and policy scopes. Production uses `alembic upgrade head`; tests that call `Base.metadata.create_all` do not substitute for the separate migration round-trip test.

Use [contribution recipes](contributing.md) when adding a field, check, page or RouterOS capability.

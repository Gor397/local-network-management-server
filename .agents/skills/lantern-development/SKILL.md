---
name: lantern-development
description: Change or debug Suro's FastAPI backend, policies, compliance, React dashboard, or developer documentation in the local-network-management-server repository.
---

Work from the repository root. Read `docs/progress.md` for current implementation and verification limits, then load only the relevant row of [the code map](../../../docs/developers/code-map.md). Do not load the entire documentation tree.

Route work by behavior:

| Change | Start | Focused check |
|---|---|---|
| Authentication/API | `backend/app/api/`, `auth/dependencies.py` | `python3 scripts/dev-check.py --area backend` |
| Check/evidence | `policies/schema.py`, `compliance/engine.py`, `services/devices.py` under `backend/app/` | Backend checks; source/freshness/version cases |
| Policy precedence | `backend/app/policies/{schema,resolver}.py`, `api/policies.py` | Backend checks; compiled version invalidation |
| Dashboard/locales | `frontend/src/App.tsx`, `api/client.ts`, `locales/{en,hy,ru}.json` | `python3 scripts/dev-check.py --area frontend` |
| Docs/skills | `docs/developers/README.md`, `.agents/skills/` | `python3 scripts/dev-check.py --area docs` |
| Suro owners/groups/help | `backend/app/api/{identities,groups}.py`, `frontend/src/pages/SuroPages.tsx`, `src/help/v1/` | Backend + frontend checks; consult `docs/developers/suro-expansion.md` for cross-component work |

Preserve these project boundaries: unknown/stale/wrong-version evidence cannot pass; network evidence cannot enter through agent claims; developer devices stay unmanaged with no endpoint percentage; published versions remain immutable. Human sessions and device credentials are separate. Use typed policy operations, never a remote command field.

Model changes need a new Alembic migration and migration validation. Frontend actions use the shared API/CSRF helper. New visible labels belong in all three catalogs; matching catalog keys alone do not prove complete translation coverage.

Default locale is Armenian; preserve saved preferences. Keep owners distinct from current accounts and user-reported names. Group conflicts require explicit resolution. MFA is optional by default; retain its implementation and preserve device authentication. Legacy state/cookie/Compose/SCM names intentionally survive Suro rebranding.

For mechanics, consult only the needed [contribution recipe](../../../docs/developers/contributing.md), [protocol section](../../../docs/developers/protocols.md), or [policy reference](../../../docs/policy-reference.md). Use the Windows or infrastructure skill when the change depends on those platforms. Report separately what passed locally and what needs hardware; keep the implementation ledger current.

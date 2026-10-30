# Visual policy editor

Administrators configure Windows policy at **Policies** without seeing JSON. The form is not hand-written: the dashboard renders `GET /api/v1/policies/catalog`, which comes from `backend/app/policies/catalog.py`. A setting appears only if it maps to a real `PolicyDocument` field (or is an explicitly labelled protected or unavailable row). Validation is always done by the server.

## Pieces

| Concern | File |
|---|---|
| Stored document, validation, layer relaxation rules | `backend/app/policies/schema.py` |
| Labels, controls, categories, enforcement, risk, templates, diff, server checks, agent projection | `backend/app/policies/catalog.py` |
| Which checks a document's own settings switch off | `not_required()` in `backend/app/compliance/engine.py` |
| Drafts, validate, preview, publish, diff, restore, targets, per-policy compliance | `backend/app/api/policies.py` |
| Explanation of a computer's effective policy (`layers`) | `GET /devices/{id}/effective-policy` in `api/groups.py` |
| Editor UI (lazy chunk) | `frontend/src/pages/PolicyStudio.tsx` |
| Labels and help | `policySetting.*`, `policyCategory.*`, `check.*`, `ps.*` keys and `policy-<category>` help articles in all three locales |

## Lifecycle

1. **Create** from a built-in template (`standard`, `restricted`, `maintenance`, `custom`) or by copying another policy. The new policy has only a draft. Templates include the Suro server firewall rule when `PUBLIC_ORIGIN` is a private IP literal.
2. **Save draft** (`PUT /policies/{id}/draft`): full validation. `expected_draft_at` refuses to overwrite another administrator's newer save. Drafts never reach computers.
3. **Preview** (`POST /policies/{id}/preview`): setting-level diff against the active version, a risk class per change (`safe`, `restart`, `network`, `high`), whether publishing applies the change automatically, warnings, and how many assigned computers are online or offline.
4. **Publish** (`POST /policies/{id}/publish` without `document`): signs a new immutable version from the draft and clears the draft. It recompiles computers that already use the policy. Publishing with an explicit `document` (API and rollback) leaves the draft alone.
5. **Assign** (`POST /policies/{id}/assignment-preview`, then `/assign-targets`): computers, Windows computer groups or all managed computers; developer devices are always excluded. AP groups are a different table and cannot be targeted.
6. **Compare / restore**: `GET /policies/{id}/diff?base=&target=` (version id, `active` or `draft`); `POST /restore` copies a version into the draft for review. The older `POST /rollback` still publishes a version directly.

Every step is audited with the changed setting keys, not the values.

## Precedence

A computer has exactly one assigned policy. Inside it the layers apply in order: policy, `GLOBAL`, `CLASS`, `GROUP`, `DEVICE`; later layers win. `merge_layers` refuses a layer that weakens security (for example `block_internet` true→false, a lower `min_d_gb`, `ip_mode` back to `unmanaged`, extra allowances or administrators, any `auto_remediate`) unless the layer carries approved relaxation. Two group layers that disagree raise `policy.group_conflict` until a device layer resolves the setting. A computer's static address (`static_ip_address`) can only be a `DEVICE` layer, and `duplicate_static_address` refuses an address that another computer's layer or DHCP reservation already uses.

## Enforcement status

The `enforcement` value on each setting is shown as a badge and must stay truthful:

| Value | Meaning | Settings today |
|---|---|---|
| `agent` | The agent changes it in Continuous / Approved remediation mode | `auto_remediate` flags (firewall back on, demote user, hide C:), `heartbeat_seconds` (agent 0.2+) |
| `approval` | Only an approved maintenance job with connection check and rollback changes it | `block_internet`, `firewall_allowances` (`firewall.apply_allowlist`) |
| `detected` | Agent reports it; nothing is changed | accounts, `require_d`, `min_d_gb`, `require_user_data_on_d`, `ip_mode` and static fields, `hide_c` without the auto flag |
| `server` | Server behavior | `allow_software_deployment` (creation and claim refused; agent updates exempt), freshness, quarantine, `mandatory_checks` |
| `protected` | Always-on rule, not stored | file preservation, backup before disk work, no automatic repartitioning, Suro server always allowed, connectivity check, offline cache |
| `unavailable` | Not implemented, never reported as met | extra C: protection, automatic IP application, automatic retry |

The server enforces the protected Suro rule as well as displaying it. While `block_internet` is on, a document without the exact `firewall.apply_allowlist` management allowance (server IP/32, TCP, port) fails with `policy.management_not_allowed`, and the editor offers a one-click fix. If `PUBLIC_ORIGIN` is a host name the server cannot check, so it only warns.

## Agent compatibility

v0.1 agents reject a policy containing any key outside their allowlist (`SignedDocument.ValidatePolicy`). The server therefore delivers `agent_document(document, device.agent_features)`:

- the v1 keys, always;
- `min_d_gb` and the `ip_*` / `dns_servers` / `static_ip_address` keys only when the agent's heartbeat listed `min_d_gb` or `ip_mode`.

Agent 0.2 sends `policy_features` with each heartbeat. The policy ETag includes the features, so an upgraded agent refetches at once. Server-only keys (`block_internet`, `require_*`, `allow_software_deployment`) are never sent.

An old agent cannot report `endpoint.ip_configuration.valid` or the D: size, so a policy that manages IP leaves those computers **unverified**, never compliant. The compliance view lists each computer's reported features.

## Adding a setting

1. Add the field to `PolicyDocument` with a default that keeps older documents' meaning, and add validation and a relaxation rule if weakening it matters.
2. Add a `SETTINGS` entry with an honest `enforcement` and `risk`, and a `visible_if` if it depends on another setting. Use `feature` if the agent must receive it.
3. If the agent needs it: add the key to `AGENT_FEATURE_KEYS` and to the C# allowlist, and add the feature name to `PolicyWorker.Features`. Implement the inspection/remediation, and gate checks in `not_required` if the setting can switch a check off.
4. Add `policySetting.<id>` and `.help` (and `policyOption.*`) to `en`, `hy` and `ru`.
5. Regenerate the dashboard fixture and run both suites:

```sh
cd backend && ../.venv/bin/python -c "import json; from app.policies.catalog import *; from app.policies.schema import CATALOG, PolicyDocument; o='https://192.168.88.10:8443'; json.dump({'categories':CATEGORIES,'settings':SETTINGS,'templates':templates(o),'checks':{k:{'source':v[0],'severity':v[1]} for k,v in CATALOG.items()},'default':PolicyDocument().model_dump(),'management':management_allowance(o)}, open('../frontend/tests/fixtures/policy-catalog.json','w'), indent=1, sort_keys=True)"
cd .. && .venv/bin/python -m pytest backend/tests/test_policy_studio.py -q && (cd frontend && npx vitest run tests/policy-studio.test.tsx)
```

`test_every_stored_setting_maps_to_a_real_document_field` fails when a field has no control, or a control has no field. `test_dashboard_fixture_matches_the_server_catalog` fails when the fixture is stale.

## Known limits

- The agent changes (`policy_features`, policy-driven interval, D: size and IP inspection) have not been built or run on Windows.
- IP configuration is detection only. Applying static addresses needs a staged maintenance operation with rollback, like the firewall job.
- `security.user_restrictions.valid` and the router-side `network.*` checks are in the default requirement list but have few or no producers. A policy that keeps them stays unverified; the editor says so in each check's fix text.
- The editor shows compliance from the latest stored report per computer. It does not re-run evaluation, so the device page remains the authority for fresh per-check evidence.

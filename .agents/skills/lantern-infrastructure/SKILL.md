---
name: lantern-infrastructure
description: Maintain Suro's Docker Compose deployment, offline image/recovery tooling, or capability-specific RouterOS discovery and reviewed network changes.
---

Work from the repository root. Read the current [implementation ledger](../../../docs/progress.md), then only the needed [Docker installation](../../../docs/installation.md), [RouterOS integration](../../../docs/mikrotik-integration.md), or [recovery](../../../docs/recovery.md) section.

Production is `compose.yaml`: web HTTPS proxy/dashboard, backend, worker, PostgreSQL, and one-shot migration. Windows agents remain native services. Preserve persistent data, TLS/key ownership, non-root/read-only containers, health checks and configurable resource caps. Never commit `.env`, private keys or package objects.

For local validation use `python3 scripts/lab.py prepare`, `build`, `up`, `smoke`, and `down`. These select project `lantern-lab`, temporary bind mounts and loopback port 18443. Do not substitute the unqualified production Compose project for this lab. `down` preserves volumes. Builds and restores are different from read-only inspection; follow the user's authorization and do not use a skill as extra deployment permission.

Router code is `backend/app/mikrotik/{connector,planner}.py` and `services/network.py`. Every adapter is wrapped by `services/safety.py` (`GuardedRouter`); a new write path must call `ensure_router_write` and respect `OPERATION_MODE`. The passive inventory (`services/inventory.py`) reads stored snapshots only. Run `scripts/netcheck.py` before touching a real router. Probe capabilities; distinguish unsupported menus from auth/transport failure. Preserve manual entries and secrets, use ownership comments, store an encrypted baseline, reject stale hashes/generations, serialize changes and read results back. An API acknowledgment is not verification. Partial failure must retain its applied-operation record.

Suro AP batches live in `services/infrastructure.py`; polling, correlation and disabled-by-default recovery in `services/{telemetry,diagnostics,recovery}.py`. API-SSL is `mikrotik/native.py`. Read `docs/suro-operations.md` for operator gates. Default sequential execution, declared independent paths, protected confirmations, uptime-reset evidence, maintenance windows/cooldowns/attempt budgets and upstream suppression must survive changes. Never count an arbitrary responding router as an independent management path.

A DHCP lease is not admission; an AP ACL readback is not global isolation; a gateway rule cannot block all shared-Layer-2 paths. Never mark full quarantine or internet restriction verified from those weaker signals. Use [CHR/physical AP tests](../../../docs/developers/testing.md) when protection claims change.

Run backend fixtures for adapter/planner changes and the isolated Compose smoke test for deployment changes. For documentation/scripts, run `python3 scripts/dev-check.py --area docs`. Update exact commands, offline/recovery procedures and verification status together. Do not contact or change production routers during development.

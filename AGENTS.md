# Suro repository context

This is a local-only Windows/MikroTik management system. Production runs through `compose.yaml`; agents are native Windows Services. Existing router and endpoint configurations must be preserved during development.

Read [progress](docs/progress.md) first for implemented versus unverified behavior. Then use the smallest relevant section of the [code map](docs/developers/code-map.md). Avoid loading all guides for a small change.

Repository skills:

- [lantern-development](.agents/skills/lantern-development/SKILL.md): backend, policy/compliance, dashboard and docs.
- [lantern-windows](.agents/skills/lantern-windows/SKILL.md): .NET Service, signatures, PowerShell and MSI.
- [lantern-infrastructure](.agents/skills/lantern-infrastructure/SKILL.md): Compose, recovery, RouterOS and isolated labs.

`make help` lists the development and production commands (`make test T=...`, `make check`, `make lab`, `make netcheck TARGET=...`, `make prod-*`). Never run `make prod-*` or `make offline-*` during development. Use `python3 scripts/dev-check.py --area backend|frontend|agent|docs` for relevant checks; run a single test file first (`.venv/bin/python -m pytest backend/tests/test_x.py -q`) and the full area last. `DOTNET_BIN` selects a nonstandard SDK location. `python3 scripts/lab.py` manages only the fixed localhost lab. Do not deploy or contact production infrastructure as part of ordinary tests.

Preserve the central invariants: no 100% score with missing/stale mandatory evidence; no network evidence from agent claims; no managed trust based only on MAC; no shell commands in declarative policy; no automatic disk migration; no verified quarantine claim from a lease or gateway-only rule. New functionality needs accurate validation notes and all three dashboard locales where applicable.

Keep durable developer knowledge in the relevant guide or skill, not duplicated throughout the instruction tree. Update docs when behavior changes; never hide incomplete functionality behind a production-ready label.

## Live-network safety (non-negotiable)

The developer laptop is on an internet LAN (Ethernet) and the live isolated network (Wi-Fi) at once. Never change host routes, interfaces, forwarding, NAT, firewall, VPN or DHCP/DNS; never bridge the networks. Run `python3 scripts/netcheck.py --target ROUTER_IP` (read-only) before any router work. Server writes are governed by `OPERATION_MODE` (`read_only`, `dry_run`, `controlled_test`, `production`; see `backend/app/services/safety.py` and the [dual-network guide](docs/development/dual-network-setup.md)). New router or endpoint write paths must go through that module. Tests use fakes only; never contact or change real routers, APs or endpoints without the user's explicit approval for that specific action, and never remove existing access-list entries.

## Context hygiene

Do not read `node_modules/`, `dist/`, `.venv/`, `data/`, lock files or build output. Search with `grep -n`/`rg` and read line ranges of the large files (`frontend/src/App.tsx`, `pages/SuroPages.tsx`, `api/infrastructure.py`, `api/deployments.py`). Pipe long test/build output through `tail`. For long sessions keep a short done/remaining list instead of re-reading files.


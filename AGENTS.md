# Lantern repository context

This is a local-only Windows/MikroTik management system. Production runs through `compose.yaml`; agents are native Windows Services. Existing router and endpoint configurations must be preserved during development.

Read [progress](docs/progress.md) first for implemented versus unverified behavior. Then use the smallest relevant section of the [code map](docs/developers/code-map.md). Avoid loading all guides for a small change.

Repository skills:

- [lantern-development](.agents/skills/lantern-development/SKILL.md): backend, policy/compliance, dashboard and docs.
- [lantern-windows](.agents/skills/lantern-windows/SKILL.md): .NET Service, signatures, PowerShell and MSI.
- [lantern-infrastructure](.agents/skills/lantern-infrastructure/SKILL.md): Compose, recovery, RouterOS and isolated labs.

Use `python3 scripts/dev-check.py --area backend|frontend|agent|docs` for relevant checks. `DOTNET_BIN` selects a nonstandard SDK location. `python3 scripts/lab.py` manages only the fixed localhost lab. Do not deploy or contact production infrastructure as part of ordinary tests.

Preserve the central invariants: no 100% score with missing/stale mandatory evidence; no network evidence from agent claims; no managed trust based only on MAC; no shell commands in declarative policy; no automatic disk migration; no verified quarantine claim from a lease or gateway-only rule. New functionality needs accurate validation notes and all three dashboard locales where applicable.

Keep durable developer knowledge in the relevant guide or skill, not duplicated throughout the instruction tree. Update docs when behavior changes; never hide incomplete functionality behind a production-ready label.

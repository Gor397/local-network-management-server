---
name: lantern-windows
description: Implement or diagnose Lantern's .NET 10 Windows Service, enrollment, fixed PowerShell operations, offline installers, or signed MSI/update workflow.
---

Read the Windows rows of [the code map](../../../docs/developers/code-map.md) and the relevant [privileged-operation section](../../../docs/developers/privileged-operations.md). Work from the repository root.

Use `Program.cs` and `Service/PolicyWorker.cs` under `agent/src/` to trace service behavior. The paths for enrollment, request signing, inspection, remediation, maintenance and deployments are separate. Ordinary policy must never gain a script/command payload.

Cross-language contracts are fragile: verify exact decoded payload bytes before JSON parsing; request signatures bind method, path/query, Unix seconds, nonce and exact body hash. Keep Python and C# schema/operation allowlists synchronized. An authorized rollback is a new version/revision, not permission to accept an old signed envelope.

Preserve existing accounts, profiles, hidden/recovery partitions and manual firewall rules. Storage execution is currently unavailable; do not implement destructive partition work through onboarding. Firewall maintenance retains its backup/recovery task until management HTTPS is verified. Do not set language preferences as SYSTEM when the intended target is the interactive standard user.

Installers require SHA-256, trusted Authenticode publisher, build/architecture checks and durable task-attempt records. An interrupted privileged operation becomes unknown rather than an automatic replay. Do not block heartbeats for a long-running installation. Standard-user protection uses documented ACL/SCM boundaries; local-admin resistance is not promised.

Run `python3 scripts/dev-check.py --area agent` (or set `DOTNET_BIN`). Build/sign MSI on Windows with `agent/installer/Build-Installer.ps1`; never insert a token or signing secret into command arguments or logs. Use the relevant [Windows VM matrix](../../../docs/developers/testing.md) for behavioral validation. Cross-compilation and crypto tests do not establish service, ACL, firewall, driver or disk correctness. Record this distinction in [progress](../../../docs/progress.md).

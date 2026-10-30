# Suro — local device and network management

Suro is an audit-first management server for Windows endpoints and MikroTik infrastructure. The server uses Docker Compose, FastAPI, PostgreSQL and a React dashboard. The agent is a native .NET 10 Windows Service.

**Current release: development / lab validation.** Enrollment, policy delivery, measured compliance, RouterOS discovery and change previews, package deployment orchestration, and an SSH broker have executable implementations. Complete VLAN quarantine, independent isolation/internet verification, destructive storage migration, and several Windows effectiveness checks are not complete. See the [implementation ledger](docs/progress.md) before enabling enforcement.

## Start here

- **Install the server:** [Linux and Docker setup](docs/installation.md).
- **Understand the code:** [developer guide](docs/developers/README.md).
- **Follow a device through the system:** [worked example](docs/developers/walkthrough.md).
- **Connect routers:** [MikroTik integration](docs/mikrotik-integration.md).
- **Install the Windows Service:** [enrollment](docs/enrollment.md).
- **Understand security boundaries:** [threat model](docs/security.md) and [protocol specification](docs/developers/protocols.md).
- **Contribute or use Codex:** [development workflow](docs/developers/contributing.md) and [project skills](docs/developers/codex-skills.md).

## Run the server

`make help` lists every command. Production in short: `make prod-bootstrap LAN_IP=192.168.88.10`, `make prod-build`, `make prod-up`, `make prod-admin`. Development in short: `make install`, `make check`, `make lab`. On a dual-homed laptop, read [dual-network setup](docs/development/dual-network-setup.md) first.

On a Linux host with Docker Engine, a recent Docker Compose plugin, and OpenSSL:

```sh
# Use this host's actual static LAN address. Generates secrets and certificates once.
sudo scripts/bootstrap.sh 192.168.88.10 management.local

# Connected build host; an offline server imports prebuilt images instead.
docker compose build
docker compose up -d

# Interactive password prompt; there is no default production password.
docker compose exec backend python -m app.cli create-admin --username admin
```

Trust the generated TLS certificate, open `https://192.168.88.10`, and sign in with username/password. Optional TOTP is available in Settings. Router writes, software deployment, SSH, and automatic recovery are disabled in the generated configuration. Existing endpoints start in Audit Mode. [Full setup and offline procedure](docs/installation.md).

## Build and test

```sh
uv venv .venv
uv pip install --python .venv/bin/python -r backend/requirements.txt pytest pytest-asyncio
.venv/bin/python -m pytest backend/tests -q

cd frontend
npm ci
npm test
npm run build
cd ..

dotnet build agent/src/NetworkPolicyClient.csproj -c Release
dotnet build agent/ui/Suro.Identity.UI.csproj -c Release
dotnet run --project agent/tests/AgentContractTests.csproj -c Release
```

Build a signed installer on Windows with a code-signing certificate:

```powershell
pwsh -File agent/installer/Build-Installer.ps1 -SigningCertificateThumbprint YOUR_CERTIFICATE_THUMBPRINT
```

After dependencies are installed, `python3 scripts/dev-check.py --area backend` and the corresponding `frontend`, `agent`, or `docs` area run focused checks. `--area all` runs the complete local set. They never deploy, enroll endpoints, or contact routers.

## Repository map

```text
backend/app/        API, authentication, data models, policy/compliance engines
backend/migrations/ Alembic schema history
backend/tests/      Server, protocol, migration and simulated RouterOS tests
agent/src/          Windows Service and bundled, allowlisted PowerShell operations
agent/ui/           Separate Armenian-first user-session identification helper
agent/installer/    WiX MSI project, signing and installation tooling
agent/tests/        Cross-platform cryptographic contract tests
frontend/src/       React dashboard and English/Armenian/Russian catalogs
infrastructure/     Docker images, HTTPS proxy and isolated lab overrides
scripts/            Setup, offline images, recovery and developer tooling
docs/               Operator runbooks and detailed developer explanations
.agents/skills/     Small repository-specific Codex workflows
```

MAC addresses map network interfaces; certificates authenticate managed endpoints. A DHCP reservation does not grant access. A router API readback does not prove endpoint isolation. Unknown checks never count as passing.

## Suro platform extension

Armenian is the initial dashboard and identity-helper language; English and Russian are selectable immediately. Start with [the illustrated Suro developer guide](docs/developers/suro-expansion.md), [the administrator workflow](docs/suro-operations.md), and [optional MFA in three languages](docs/authentication.md). Read [progress](docs/progress.md) for verified scope. Existing database/Compose/Windows identity names are preserved for upgrade compatibility.

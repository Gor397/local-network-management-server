# Install the Linux management server

These instructions deploy the server locally with Docker Compose. They do not configure production routers or Windows endpoints automatically. Start with read-only discovery and one Windows test machine.

## 1. Prepare a fresh Linux host

Use a supported Ubuntu LTS release, a static LAN IP, reliable time, and storage sized for uploaded packages and backups. A practical starting point is 2 CPU cores and at least 2 GiB RAM; measure your workload before increasing device count. Image builds can need more memory than the running application.

On a fresh Ubuntu host, install Docker from its official repository. Review the [current Docker Ubuntu instructions](https://docs.docker.com/engine/install/ubuntu/) if existing Docker/container packages are already installed; do not remove a working installation blindly.

```sh
sudo apt update
sudo apt install -y ca-certificates curl openssl python3 age
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

. /etc/os-release
printf 'Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: /etc/apt/keyrings/docker.asc\n' \
  "${UBUNTU_CODENAME:-$VERSION_CODENAME}" "$(dpkg --print-architecture)" | \
  sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker compose version
```

Run Docker commands as root or through an authorized Docker group account. Docker daemon access is effectively administrator access to the host. The examples below assume that access is already configured.

## 2. Obtain the checkout and initialize once

Place the source in a dedicated directory, for example `/opt/lantern`, and run all following commands there. Use the actual host LAN IP:

```sh
sudo scripts/bootstrap.sh 192.168.88.10 management.local
```

This creates `.env`, separate device-CA and policy-signing keys, a TLS certificate, and persistent data directories with container ownership. Existing keys/configuration are preserved. The `.env` is mode 600; when called through sudo it is owned by the invoking account so that account can run Compose.

Review these values before startup:

| Setting | Example | Purpose |
|---|---|---|
| `LAN_BIND_IP` | `192.168.88.10` | Host interface on which HTTPS listens |
| `PUBLIC_ORIGIN` | `https://192.168.88.10` | Exact browser origin, including nondefault port if used |
| `TRUSTED_HOSTS` | `192.168.88.10,management.local,localhost,127.0.0.1` | Accepted HTTP hostnames |
| `MANAGEMENT_ADDRESS` | `192.168.88.10` | Suro server LAN IPv4 that computers under the [client requirement](developers/client-admission.md) can always reach; defaults to the IP in `PUBLIC_ORIGIN` |
| `ONBOARDING_HTTP_BIND` | `127.0.0.1:8080` | Plain-HTTP onboarding page; set to `<LAN IP>:80` only when piloting the client requirement |
| `TRUSTED_PROXY_NETWORKS` | `127.0.0.1/32,172.16.0.0/12` | Proxies allowed to state the browser address for `/onboard/status` |
| `ROUTER_ALLOWED_NETWORKS` | `192.168.88.0/24` | Permitted management destinations |
| `SSH_ALLOWED_NETWORKS` | `192.168.88.0/24` | Permitted endpoint SSH destinations |
| `OPERATION_MODE` | `read_only` | Server-enforced safety mode: `read_only`, `dry_run`, `controlled_test`, `production` |
| `TEST_ROUTERS` / `TEST_DEVICES` | empty | Only targets in `controlled_test` mode (IDs, names/hostnames, router management IPs) |
| `ROUTER_WRITES_ENABLED` | `false` | Legacy global write gate; used only when `OPERATION_MODE` is unset |
| `DEPLOYMENT_ENABLED` | `false` | Keep false until signed package tests pass |
| `SSH_ENABLED` | `false` | Keep false until host keys and management paths are ready |

Bootstrap writes `OPERATION_MODE=read_only` and sets the router/SSH allowed networks to the `/24` around `LAN_IP`. For other or multiple subnets, run it as `sudo ROUTER_NETWORKS=10.20.0.0/24,10.21.0.0/24 scripts/bootstrap.sh LAN_IP`. An `.env` created earlier keeps its values. Without the setting, the code falls back to all private ranges, so narrow it to the actual management subnets. Compose publishes HTTPS on `127.0.0.1` when `LAN_BIND_IP` is missing. Do not print the complete `.env` in tickets or logs.

## 3. Trust and configure TLS

The generated certificate is a development/bootstrap trust anchor with the LAN IP and DNS name in its SANs. For production, prefer a certificate issued by your organization's local CA, retaining the correct names and addresses.

The paths are:

```text
data/tls/server.crt   certificate / chain
data/tls/server.key   private key, UID 10001 / GID 101, mode 640
```

Distribute only the trusted public CA/certificate through an authenticated administrative channel. Install it in administrator browser trust stores and managed Windows machine trust stores. Never copy the server private key to clients, and never use `verify=False` or permanent certificate bypasses.

For a Windows lab, an elevated administrator can import the independently verified bootstrap certificate:

```powershell
Import-Certificate -FilePath .\server.crt -CertStoreLocation Cert:\LocalMachine\Root
```

If a DNS name is used in the browser, set `PUBLIC_ORIGIN` to that exact origin. A certificate containing both IP and DNS names does not make two different browser origins interchangeable for CSRF.

## 4. Build or import images, then start

On a connected build host:

```sh
docker compose build
docker compose up -d
docker compose ps
```

The first startup creates PostgreSQL storage and runs migrations before starting the API, worker and HTTPS dashboard. Subsequent normal starts use the same command:

```sh
docker compose up -d
```

Only HTTPS is published to the LAN. Restrict that port to authorized administrative and agent networks using your host/router firewall. Do not expose the database, backend port, RouterOS API or endpoint SSH to the public internet. Docker-published ports require Docker-aware host firewall rules; verify the actual packet path rather than assuming a generic host firewall setting covers it.

## 5. Create the first administrator

```sh
docker compose exec backend python -m app.cli create-admin --username admin
```

Enter a unique password of at least 16 characters at the interactive prompts. No default password exists. Open `https://192.168.88.10`, sign in with username and password. Optional TOTP remains available in Settings; it is not required by default. See [multilingual MFA instructions](authentication.md). Keep the local-console recovery procedure available before enabling enforcement.

Create a baseline policy, register a test device and assign the policy. Register routers with read-only credentials and verify discovery before allowing writes.

## 6. Persistent storage and updates

| Data | Location | Survives container recreation? |
|---|---|---|
| PostgreSQL | Named volume `lantern_postgres_data` for default project name | Yes, unless explicitly deleted |
| Packages, recordings, keys, trust | `./data` bind mount | Yes |
| Runtime environment/secrets | `./.env` | Yes |
| TLS certificate/key | `./data/tls` | Yes |
| Application source | Checkout | Yes |

Changing the Compose project name changes named-volume identity. Use a fixed project name for production. Do not run `down -v`, remove `data`, or rotate `ENCRYPTION_KEY` during an ordinary update.

Container limits are configurable through `.env`; see [monitoring](monitoring.md). Use [backup and recovery](recovery.md) before updates.

## Make shortcuts

Run these in the server checkout. They wrap the commands in this guide; `make help` lists every target.

| Task | Command |
|---|---|
| First install | `make prod-bootstrap LAN_IP=192.168.88.10 [ROUTER_NETWORKS=192.168.88.0/24]` |
| Build / start / status / logs | `make prod-build`, `make prod-up`, `make prod-status`, `make prod-logs SERVICE=backend` |
| First administrator | `make prod-admin USERNAME=admin` |
| Show safety mode and network scope | `make prod-mode` (prints no secrets) |
| Apply an `.env` change such as `OPERATION_MODE` | `make prod-restart` |
| Stop (data kept) | `make prod-down` |
| Backup / update | `make prod-backup BACKUP=/backups/suro.age RECIPIENT=age1...`, `make prod-update TAG=0.2.0 BACKUP=... RECIPIENT=...` |
| Restore / rollback (replace all data) | `make prod-restore BACKUP=... IDENTITY=... CONFIRM=replace-data`, `make prod-rollback ...` |
| Air-gapped transfer | `make offline-export OUT=/tmp/lantern-offline` (connected host), then `make offline-import BUNDLE=...` and `make prod-up-offline` (offline server) |

## Offline production installation

The disconnected host still needs Docker Engine/Compose and their OS dependencies installed from matching offline OS packages. Prepare these separately for the host's exact distribution and CPU architecture using Docker's official package procedure.

On a connected build host of the target architecture:

```sh
scripts/export-offline.sh /tmp/lantern-offline
```

The bundle contains prebuilt application/database images, source and checksums. Authenticate the checksum manifest through a separate trusted channel. Images may contain third-party packages and should be reviewed/scanned on the build host before transfer.

On the offline host:

```sh
mkdir -p /opt/lantern
tar -xzf /media/transfer/lantern-offline/source.tar.gz -C /opt/lantern
cd /opt/lantern
scripts/import-offline.sh /media/transfer/lantern-offline
sudo scripts/bootstrap.sh 192.168.88.10 management.local
# Review .env and establish local TLS trust.
docker compose up -d --pull never --no-build
docker compose exec backend python -m app.cli create-admin --username admin
```

Normal operation uses local APIs, local PostgreSQL, uploaded software and local router/Windows management. No npm, pip, NuGet, certificate authority cloud API or container registry is required after the matching images and endpoint packages are transferred. Offline certificate revocation/publisher trust dependencies still need a deliberate Windows trust policy.

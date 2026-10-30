# Monitoring and Low Resource Mode

Use the built-in dashboard and container/process metrics first. No external metrics stack is required.

```sh
docker compose ps
docker compose logs --tail 80 backend worker web
docker stats --no-stream
```

The authenticated `/api/v1/system/resources` endpoint reports the backend's maximum RSS, cgroup memory/quota information, filesystem free space, logical repository size and running-deployment count. It is not a complete host-monitoring agent.

## Defaults and configuration

| Control | Default | Location |
|---|---|---|
| API process count | 1 | Backend image command |
| Worker process count | 1 | Compose service |
| Agent configured poll | 120 s | Provisioning/configuration |
| Worker delay in Low Resource Mode | 60 s after work finishes | `LOW_RESOURCE_MODE=true` |
| Server suggested poll | 120 s low-resource / 60 s normal | Settings property; full agent adoption is pending |
| Deployment concurrency | 2 | `DEPLOYMENT_CONCURRENCY` |
| Download rate per response | 2 MiB/s | `TRANSFER_BYTES_PER_SECOND` |
| Upload chunk maximum | 4 MiB | `UPLOAD_CHUNK_BYTES` |
| Health retention | 7 days | `HEALTH_RETENTION_DAYS` |
| Compliance report retention | 30 days | Current worker constant |
| Audit log automatic deletion | Disabled | Worker excludes audit records |

Low Resource Mode currently reduces worker cadence and suggested agent polling. It does not automatically change every concurrency setting. Set `DEPLOYMENT_CONCURRENCY=1` and an appropriate transfer rate explicitly on a particularly small host. Changing settings requires recreating the relevant containers; language switching does not.

## Container ceilings

```text
DB_MEMORY=256m         DB_CPUS=0.50
BACKEND_MEMORY=384m    BACKEND_CPUS=0.75
WORKER_MEMORY=192m     WORKER_CPUS=0.35
WEB_MEMORY=64m         WEB_CPUS=0.25
```

These are limits, not measured consumption. Docker, Linux, filesystem cache, backups and image builds consume additional resources. Increasing a limit is not a substitute for finding a leak, unbounded response or unnecessary query.

A single local smoke run on 2026-10-29 observed approximately 92 MiB backend, 65 MiB worker, 14 MiB web and 31 MiB PostgreSQL after requests settled. This roughly 202 MiB container snapshot is not a fleet/load benchmark, excludes host overhead, and does not describe authentication/build/backup peaks.

## What to watch

- **Missing heartbeats with connected clients:** distinguish server/proxy saturation from a stopped agent before changing network access.
- **Worker health:** `data/worker.heartbeat` advances after a successful tick. A long failed router discovery can delay it.
- **Unknown deployment tasks:** investigate endpoint state and its durable ledger before approving retries.
- **Disk headroom:** uploads, package objects, terminal recordings and execution logs are not all automatically cleaned up yet.
- **Router unavailable / plan error:** inspect the saved partial operation list; do not assume no writes occurred.
- **Database growth:** health/compliance retention is bounded, but audit history and package metadata persist.

Nginx and application rate limits are distinct. The current application does not trust forwarded client IPs, so requests arriving through the proxy share the proxy's application-level bucket. Capacity and brute-force behavior need load testing before a large fleet; do not claim support for an arbitrary number of devices from the default limits alone.

Keep security audit history outside ephemeral container logs. The current database audit table is operational history, not protection against a compromised database administrator.

## Suro infrastructure telemetry

The worker now runs bounded asynchronous network polling separately from the infrastructure-operation task. Defaults are health every 60 seconds, full inventory every 900 seconds, concurrency two, and seven-day network/client telemetry retention. Low Resource Mode uses a 60-second worker cadence and 120-second agent policy interval. Expensive data is not included in every health poll. Unavailable routers receive a slower retry cadence. Settings → Monitoring Settings persists approved budgets in PostgreSQL; the worker reads them each cycle.

Newly seen log entries are deduplicated with a bounded cursor. Client diagnostics are bounded on disk and uploaded after reconnection. The incident center merges common failures and keeps facts separate from hypotheses. Health, incidents and operation outcomes contribute small SSE revision markers; SSE does not hold a database connection between polls or stream complete telemetry.

See [Suro operations](suro-operations.md) for incident maintenance, recovery gates and topology interpretation. Automatic recovery is disabled globally/per AP and supports corroborated sustained critical CPU/RAM and separately approved restoration of an unexpectedly disabled radio. The radio must explicitly be enabled in approved desired state; unknown and intentionally disabled interfaces are never automatically changed. It is not a universal fault-repair engine. Measure actual memory, storage and latency under your deployment workload; the idle lab sample in [progress](progress.md) is not a sizing guarantee.

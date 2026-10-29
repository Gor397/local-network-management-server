# Troubleshooting by symptom

| Symptom | Check first | Next action |
|---|---|---|
| HTTPS cannot open | Host LAN IP, port binding, TLS SAN/trust and web health | `docker compose ps`, then web/backend logs |
| Login returns origin/CSRF error | Browser origin exactly matches `PUBLIC_ORIGIN`, including port | Correct environment and recreate application containers; use shared API client |
| Host rejected | `TRUSTED_HOSTS` contains the exact host name/IP | Keep localhost/127.0.0.1 for health probes |
| MFA-protected action rejected | TOTP configured and verified within ten minutes | Reauthenticate with a fresh unused code |
| Device waits for enrollment | Token not expired, MAC binding correct, CSR approved | Retry the same CSR; never reuse the token with a replacement key |
| Device signs but gets 401 | Certificate expiry/revocation, machine time, path/query/body bytes | Compare test protocol fields; do not disable TLS/signature checks |
| No inventory after enrollment | A policy version is actually assigned | Assign policy; request sync; inspect service logs |
| Healthy-looking device stays unverified | Individual unknown/stale/wrong-version checks | Implement/collect sufficient evidence; never force score to 100 |
| Device appears connected but agent missing | Fresh AP observation versus heartbeat timestamp | Distinguish stopped service, server/proxy saturation and sleeping machine |
| Router discovery fails | Verified CA/IP SAN, management subnet allowlist, account permissions | Test read-only REST from the server; review installed RouterOS menus |
| Router preview cannot apply | Both write gates, preview age, generation and baseline hash | Rediscover and create a new reviewed preview |
| Plan says ERROR | Partial `applied` list and actual router configuration | Reconcile through recovery access before retrying |
| Reservation created but no Wi-Fi access | Addressing and authorization are separate | Review the AP's supported admission mechanism and existing credentials |
| Software task remains pending | Feature gate, mode, schedule, package approval, concurrency and network state | Check each eligibility condition before editing the queue |
| Install exits zero but state unknown | Application-specific detection is absent or incomplete | Verify actual installed state; add a supported detector |
| Upload offset conflict | Committed upload offset differs from client expectation | Query upload status and resume from the returned offset |
| SSH cannot connect | Eligibility, verified reservation, host-key pin, public key, OpenSSH service and management path | Do not disable host-key validation or bypass quarantine |
| Language change pending | Matching offline resources installed and intended user has logged on | Verify that user's settings after logon; SYSTEM preferences are unrelated |
| Worker unhealthy | Last successful tick and router request delays | Inspect worker logs and database access; keep writes disabled while diagnosing |

## Safe diagnostics

```sh
docker compose ps
docker compose logs --tail 80 backend worker web
docker compose exec backend python -c "from app.config import Settings; print(Settings().public_origin)"
```

On Windows, inspect `LocalNetworkPolicyAgent`, the Windows Event Log and the bounded JSON log in `%ProgramData%\Lantern`. Diagnostic data can include operational usernames, addresses, keys' public fingerprints and terminal output; review it before sharing. Never attach `.env`, enrollment tokens, SSH private keys, full provisioning files or decrypted router snapshots.

Read [the protocol guide](developers/protocols.md) for signature issues and [recovery](recovery.md) for administrative lockouts. Complete test logs from a mock are not evidence of physical network isolation.

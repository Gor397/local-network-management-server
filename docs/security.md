# Threat model

| Threat | Controls | Residual risk |
|---|---|---|
| LAN attacker / stolen MAC | TLS, enrolled certificate challenge signatures, expiring single-use enrollment, approval | MAC-only developer admission remains spoofable; use isolated developer VLAN or 802.1X/RADIUS |
| Malicious standard user | SYSTEM service, protected ACLs, standard account, signed policy, server-side catalog | Windows build/edition and actual effective policy require VM verification |
| Compromised agent | independent network observations, evidence freshness, quarantine gates | A valid certificate does not prove OS integrity; agent evidence can lie |
| Stolen device key | nonexportable Windows machine certificate, revocation, replay protection | SYSTEM compromise can use the key until revocation |
| Compromised admin | Argon2, RBAC, optional enforceable MFA, explicit approvals, immutable policy versions, audit | Username/password is the requested default; a deployment/SSH administrator can execute privileged code; separation of duties is recommended |
| Router API failure | verified TLS, bounded timeouts, no blind overwrite, durable preview and readback | Network changes can partially apply; keep out-of-band access |
| Server outage | last-known-good policy, no autonomous destructive router changes | Continuous assessment pauses; existing segmentation must enforce restrictions |
| Uploaded malware | content hash, publisher pinning, explicit approval, signed instructions, limited concurrency | Approval is a trust decision, not malware detection |
| Forged owner report | Separate owner/self-report tables; authenticated pipe derives real SID; helper verifies SCM PID; administrator review/history | A self-reported name or rank is not verified identity; local administrators can alter the endpoint |
| Shared network outage | Cross-source incidents, upstream suppression, declared independent paths, sequential batches, recovery off by default, cooldown/attempt budgets | Incomplete physical topology cannot prove recovery access; retain a tested console/WinBox path |
| Sensitive operational data | RBAC, audit, redacted/encrypted snapshots, bounded diagnostic metadata, authorized CSV export | Names/ranks and terminal/log data need organizational retention/access policies |

Production secrets are generated on first run, never defaults. TLS private keys, encryption keys, signing keys and database backups must be protected separately. Do not expose PostgreSQL, RouterOS management, endpoint SSH or the API directly to the public internet.

Terminal recordings can contain sensitive information and terminal control sequences; they are not a complete forensic record of commands, subprocesses, transfers or actions outside the session. Retain them under strict access controls.

# Backup, restore and administrative recovery

## What must be recoverable

The database and filesystem must agree. Back up the database together with `.env`, device-CA/policy-signing keys, TLS material, trust certificates, package objects and recordings. Losing `ENCRYPTION_KEY` makes encrypted router credentials and recordings unreadable. Losing the policy public/private key relationship can break clients' trust in new policies.

Keep recovery identities, backup decryption identity and out-of-band router/Windows access outside the managed access path they may need to repair.

## Encrypted backup

Install `age` on the administrative host. Keep the private decryption identity separately; the backup command needs only a public recipient.

```sh
# Run with filesystem privileges needed to read data/.
sudo scripts/backup.sh /secure-backups/lantern-2026-10-29.age age1YOUR_PUBLIC_RECIPIENT
```

The script stops web/worker/backend to freeze application writes, dumps PostgreSQL in custom format, archives matching state, encrypts the stream and restarts the application on exit. PostgreSQL remains running. This introduces a maintenance outage; it is not a zero-downtime backup.

Keep the matching source and image tags as well. A backup is not verified until it has been restored on an isolated host and its key functions tested.

## Restore

Restore is intentionally destructive to the selected deployment's database and state. First verify the Compose project and host, retain a current backup and ensure the original services are stopped.

```sh
sudo scripts/restore.sh /secure-backups/lantern-2026-10-29.age /secure/age-identity.txt --confirm-replace-data
```

The script decrypts and checks archive paths, stops the application, preserves the current `data` directory under a timestamped name, restores configuration/files, waits for PostgreSQL and restores the database. Application containers are recreated afterward so their bind mounts refer to the restored directory. Required images must already be available offline.

**Current recovery limitations:** a database password change can require separate PostgreSQL role/volume reconciliation; restore assumes compatible database credentials. Test restore before production use. Restoring changed passwords into an existing volume does not change its PostgreSQL role password merely because `POSTGRES_PASSWORD` changed in `.env`.

After restore, verify login/MFA, policy signatures, device identities, repository hashes, worker health and read-only router discovery. Do not enable network writes as the first verification step.

## Update and rollback

Load reviewed new images before updating. Use a unique release tag, preserve the previous images and take an encrypted backup:

```sh
sudo scripts/update.sh NEW_TAG /secure-backups/pre-update.age age1YOUR_PUBLIC_RECIPIENT
```

The script checks that the new application images exist, changes the image tag and waits for Compose health. A schema change can make a code-only downgrade unsafe. Rollback restores the matching pre-update data and keys:

```sh
sudo scripts/rollback.sh /secure-backups/pre-update.age /secure/age-identity.txt --confirm-replace-data
```

Rollback does not undo physical changes already made to endpoints or routers. Their operation records and before-state backups must be reviewed independently.

## Dashboard administrator recovery

With authorized local-console access:

```sh
docker compose exec backend python -m app.cli recover-admin --username admin
```

The CLI prompts for a replacement password, clears that administrator's TOTP requirement, enables the account, invalidates its existing sessions and records a local-console recovery audit entry. Reconfigure TOTP immediately. This path is intentionally unavailable through an unauthenticated web endpoint.

## Router management lockout

Use the separately tested WinBox/console/management path. Review the plan's encrypted before-state and persisted `applied` operations, then compare actual RouterOS state. Do not restore the entire snapshot over unrelated manual changes.

If a write failed halfway through, some operations may still be active. The current system records this as `ERROR` and does not perform a blind automatic snapshot restore. A complete automated inverse-plan recovery tool is not implemented yet.

## Windows break-glass

Retain an approved local administrator credential through a secure external process. Standard-user protection must not prevent an authorized administrator from stopping/removing the service or using Windows recovery.

For a firewall maintenance failure, the out-of-process scheduled recovery task should restore the exported firewall. Test that task on each supported Windows build and keep console access if it fails. Disk/data migration requires separate verified backups and recovery instructions; there is no automatic disk executor in this release.

#!/bin/sh
set -eu
umask 077
cd "$(dirname "$0")/.."
if [ "$#" -ne 3 ] || [ "$3" != '--confirm-replace-data' ]; then
  echo 'Usage: sudo scripts/restore.sh BACKUP.age AGE_IDENTITY_FILE --confirm-replace-data'; exit 2
fi
lantern_temp=$(mktemp -d /tmp/lantern-restore.XXXXXXXX)
trap 'rm -rf "$lantern_temp"' EXIT INT TERM
age --decrypt -i "$2" -o "$lantern_temp/backup.tar" "$1"
python3 - "$lantern_temp/backup.tar" <<'PY'
import sys, tarfile
from pathlib import PurePosixPath
with tarfile.open(sys.argv[1]) as archive:
    for member in archive:
        p = PurePosixPath(member.name)
        if p.is_absolute() or '..' in p.parts or member.issym() or member.islnk():
            raise SystemExit('Unsafe backup member')
PY
docker compose stop web worker backend
if [ -d data ]; then mv data "data.before-restore.$(date +%Y%m%d%H%M%S)"; fi
if [ -f .env ]; then cp .env "$lantern_temp/previous.env"; fi
tar -xf "$lantern_temp/backup.tar" -C "$lantern_temp"
cp "$lantern_temp/.env" .env
mv "$lantern_temp/data" data
docker compose up -d db
docker compose exec -T db sh -c 'pg_restore --clean --if-exists --no-owner -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < "$lantern_temp/database.dump"
docker compose up -d --pull never --no-build
echo 'Restored. Verify login, certificates, package hashes, policy signatures, and router read-only discovery.'

#!/bin/sh
set -eu
umask 077
cd "$(dirname "$0")/.."
if [ "$#" -ne 2 ]; then echo 'Usage: scripts/backup.sh OUTPUT.age AGE_PUBLIC_RECIPIENT'; exit 2; fi
command -v age >/dev/null
lantern_output=$1
lantern_recipient=$2
lantern_temp=$(mktemp -d /tmp/lantern-backup.XXXXXXXX)
trap 'docker compose start backend worker web >/dev/null 2>&1 || true; rm -rf "$lantern_temp"' EXIT INT TERM
# Freeze app writes so DB references and package objects describe the same point in time.
docker compose stop web worker backend
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "$lantern_temp/database.dump"
docker compose config --images | sort -u > "$lantern_temp/images.txt"
tar -cf - .env data -C "$lantern_temp" database.dump images.txt | age -r "$lantern_recipient" -o "$lantern_output"
echo "Encrypted backup saved: $lantern_output. Perform a restore test on an isolated host."

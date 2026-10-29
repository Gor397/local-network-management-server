#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ "$#" -ne 3 ]; then echo 'Usage: scripts/update.sh NEW_TAG BACKUP.age AGE_RECIPIENT'; exit 2; fi
case "$1" in *[!a-zA-Z0-9._-]*) exit 2;; esac
scripts/backup.sh "$2" "$3"
cp .env .env.before-update
sed "s/^LANTERN_TAG=.*/LANTERN_TAG=$1/" .env.before-update > .env
chmod 600 .env
docker image inspect "lantern-backend:$1" >/dev/null
docker image inspect "lantern-web:$1" >/dev/null
docker compose up -d --pull never --no-build --wait --wait-timeout 180
echo 'Update complete. Keep prior images and encrypted backup until acceptance testing passes.'

#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ "$#" -ne 3 ] || [ "$3" != '--confirm-replace-data' ]; then echo 'Usage: sudo scripts/rollback.sh PRE_UPDATE_BACKUP.age AGE_IDENTITY --confirm-replace-data'; exit 2; fi
# A code downgrade alone is unsafe after schema or policy changes. Restore the matching database and keys.
scripts/restore.sh "$1" "$2" "$3"

#!/bin/sh
set -eu
if [ "$#" -ne 1 ]; then echo 'Usage: scripts/import-offline.sh BUNDLE_DIRECTORY'; exit 2; fi
cd "$1"
sha256sum -c SHA256SUMS
gzip -dc images.tar.gz | docker image load
echo 'Images imported. Initialize the extracted source, then: docker compose up -d --pull never --no-build'

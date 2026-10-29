#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
lantern_output=${1:-/tmp/lantern-offline}
mkdir -p "$lantern_output"
docker compose build --pull
docker compose pull db
docker compose config --images | sort -u > "$lantern_output/images.txt"
docker image save $(cat "$lantern_output/images.txt") | gzip > "$lantern_output/images.tar.gz"
tar --exclude=.git --exclude=.venv --exclude=data --exclude=.env --exclude=node_modules --exclude=dist --exclude=bin --exclude=obj \
    -czf "$lantern_output/source.tar.gz" backend frontend agent infrastructure scripts docs .agents AGENTS.md compose.yaml .env.example README.md .dockerignore
(cd "$lantern_output" && sha256sum images.tar.gz source.tar.gz images.txt > SHA256SUMS)
echo "Offline bundle: $lantern_output. Authenticate SHA256SUMS separately before transfer."

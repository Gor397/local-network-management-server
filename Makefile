# Suro task runner. `make` or `make help` lists targets.
# Development targets use only the isolated localhost lab (project lantern-lab, 127.0.0.1:18443)
# and fake routers. Production targets run on the server in its checkout and use the plain
# `lantern` Compose project with ./.env. Nothing here changes host networking.

SHELL := /bin/bash
.DEFAULT_GOAL := help
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
LAB_COMPOSE := docker compose -p lantern-lab --env-file /tmp/lantern-lab.env -f compose.yaml -f infrastructure/docker/compose.lab.yaml
COMPOSE := docker compose
USERNAME ?= admin
DNS_NAME ?= management.local
OUT ?= /tmp/lantern-offline

require = $(if $($(1)),,$(error Set $(1)=... (see `make help`)))
require_env = @test -f .env || { echo "No .env here. Run 'make prod-bootstrap LAN_IP=...' on the server first."; exit 2; }

.PHONY: help
help: ## List targets
	@awk 'BEGIN {FS = ":.*## "} /^##@/ {printf "\n\033[1m%s\033[0m\n", substr($$0, 5)} /^[a-zA-Z0-9_-]+:.*## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

##@ Development: setup and checks

.PHONY: install install-backend install-frontend skills
install: install-backend install-frontend ## Create .venv and install backend + dashboard dependencies
install-backend:
	@if command -v uv >/dev/null; then uv venv .venv && uv pip install --python .venv/bin/python -r backend/requirements.txt pytest pytest-asyncio; \
	else python3 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt pytest pytest-asyncio; fi
install-frontend:
	cd frontend && npm ci
skills: ## Link the repository skills into ~/.codex/skills
	$(PYTHON) scripts/install-project-skills.py

.PHONY: test test-backend test-frontend build-frontend check-docs check-agent check
test: ## Run one test file: make test T=backend/tests/test_safety_modes.py
	$(call require,T)
	$(PYTHON) -m pytest $(T) -q
test-backend: ## Backend suite (fake routers only)
	$(PYTHON) scripts/dev-check.py --area backend
test-frontend: ## Dashboard tests and production build
	$(PYTHON) scripts/dev-check.py --area frontend
check-docs: ## Documentation links and skill entry points
	$(PYTHON) scripts/dev-check.py --area docs
check-agent: ## Windows agent cross-build and crypto contracts (needs .NET 10 or DOTNET_BIN)
	$(PYTHON) scripts/dev-check.py --area agent
check: test-backend test-frontend check-docs ## Backend + dashboard + docs (agent excluded)

##@ Development: network safety

.PHONY: netcheck
netcheck: ## Read-only dual-network check: make netcheck TARGET=192.168.88.1
	$(PYTHON) scripts/netcheck.py $(if $(TARGET),--target $(TARGET))

##@ Development: isolated lab (https://localhost:18443)

.PHONY: lab lab-prepare lab-build lab-up lab-smoke lab-down lab-logs lab-admin lab-mode lab-use-wifi
lab: lab-prepare lab-build lab-up ## Prepare, build and start the lab
lab-prepare: ## Create test-only keys/config in /tmp (refuses to overwrite retained lab data)
	$(PYTHON) scripts/lab.py prepare
lab-build: ## Build lab images
	$(PYTHON) scripts/lab.py build
lab-up: ## Start the lab on 127.0.0.1:18443
	$(PYTHON) scripts/lab.py up
lab-smoke: ## HTTPS/PostgreSQL smoke test against the lab
	$(PYTHON) scripts/lab.py smoke
lab-down: ## Stop the lab (keeps its volume)
	$(PYTHON) scripts/lab.py down
lab-logs: ## Show lab logs
	$(PYTHON) scripts/lab.py logs
lab-admin: ## Create a lab administrator: make lab-admin USERNAME=admin
	$(LAB_COMPOSE) exec backend python -m app.cli create-admin --username $(USERNAME)
lab-use-wifi: ## After joining the MikroTik Wi-Fi: detect its subnet, allow only that in the lab, check routing
	@test -f /tmp/lantern-lab.env || { echo "Run 'make lab-prepare' first."; exit 2; }
	@found=$$($(PYTHON) scripts/netcheck.py --detect-wifi) || exit 2; \
	nets=$$(echo "$$found" | $(PYTHON) -c 'import json,sys; print(",".join(sorted({f["network"] for f in json.load(sys.stdin)})))'); \
	gw=$$(echo "$$found" | $(PYTHON) -c 'import json,sys; print(next((f["gateway"] for f in json.load(sys.stdin) if f["gateway"]), ""))'); \
	sed -i "s|^ROUTER_ALLOWED_NETWORKS=.*|ROUTER_ALLOWED_NETWORKS=$$nets|" /tmp/lantern-lab.env; \
	echo "Wi-Fi: $$found"; echo "Lab now allows only: $$nets"; \
	if [ -n "$$gw" ]; then $(PYTHON) scripts/netcheck.py --env /tmp/lantern-lab.env --target $$gw; else echo "No Wi-Fi gateway found; run 'make netcheck TARGET=<router IP>'."; fi
lab-mode: ## Show the lab safety mode and allowed router networks
	@grep -E '^(OPERATION_MODE|TEST_ROUTERS|TEST_DEVICES|ROUTER_ALLOWED_NETWORKS)=' /tmp/lantern-lab.env

##@ Production: install and run (on the server, in its checkout)

.PHONY: prod-bootstrap prod-build prod-up prod-up-offline prod-down prod-restart prod-status prod-logs prod-admin prod-mode
prod-bootstrap: ## First install: make prod-bootstrap LAN_IP=192.168.88.10 [DNS_NAME=..] [ROUTER_NETWORKS=a/24,b/24]
	$(call require,LAN_IP)
	sudo $(if $(ROUTER_NETWORKS),env ROUTER_NETWORKS=$(ROUTER_NETWORKS)) scripts/bootstrap.sh $(LAN_IP) $(DNS_NAME)
prod-build: ## Build images (connected build host)
	$(require_env)
	$(COMPOSE) build
prod-up: ## Start or update the stack (runs migrations first)
	$(require_env)
	$(COMPOSE) up -d
prod-up-offline: ## Start from imported images only, no registry or build
	$(require_env)
	$(COMPOSE) up -d --pull never --no-build
prod-down: ## Stop the stack (database volume and data/ are kept)
	$(require_env)
	$(COMPOSE) down
prod-restart: ## Restart backend and worker, e.g. after editing OPERATION_MODE in .env
	$(require_env)
	$(COMPOSE) up -d --force-recreate backend worker
prod-status: ## Container state and health
	$(require_env)
	$(COMPOSE) ps
prod-logs: ## Follow logs: make prod-logs [SERVICE=backend]
	$(require_env)
	$(COMPOSE) logs -f --tail 200 $(SERVICE)
prod-admin: ## Create an administrator: make prod-admin USERNAME=admin
	$(require_env)
	$(COMPOSE) exec backend python -m app.cli create-admin --username $(USERNAME)
prod-mode: ## Show the safety mode and network scope (no secrets printed)
	$(require_env)
	@grep -E '^(OPERATION_MODE|TEST_ROUTERS|TEST_DEVICES|ROUTER_WRITES_ENABLED|ROUTER_ALLOWED_NETWORKS|LAN_BIND_IP|DEPLOYMENT_ENABLED|RECOVERY_ENABLED)=' .env

##@ Production: backup, update, recovery

.PHONY: prod-backup prod-update prod-restore prod-rollback
prod-backup: ## Encrypted backup: make prod-backup BACKUP=/backups/suro.age RECIPIENT=age1...
	$(call require,BACKUP)
	$(call require,RECIPIENT)
	scripts/backup.sh $(BACKUP) $(RECIPIENT)
prod-update: ## Backup, then update: make prod-update TAG=0.2.0 BACKUP=/backups/pre.age RECIPIENT=age1...
	$(call require,TAG)
	$(call require,BACKUP)
	$(call require,RECIPIENT)
	scripts/update.sh $(TAG) $(BACKUP) $(RECIPIENT)
prod-restore: ## REPLACES data: make prod-restore BACKUP=.. IDENTITY=.. CONFIRM=replace-data
	$(call require,BACKUP)
	$(call require,IDENTITY)
	@test "$(CONFIRM)" = replace-data || { echo "Restore replaces all current data. Add CONFIRM=replace-data."; exit 2; }
	sudo scripts/restore.sh $(BACKUP) $(IDENTITY) --confirm-replace-data
prod-rollback: ## REPLACES data with a pre-update backup: make prod-rollback BACKUP=.. IDENTITY=.. CONFIRM=replace-data
	$(call require,BACKUP)
	$(call require,IDENTITY)
	@test "$(CONFIRM)" = replace-data || { echo "Rollback replaces all current data. Add CONFIRM=replace-data."; exit 2; }
	sudo scripts/rollback.sh $(BACKUP) $(IDENTITY) --confirm-replace-data

##@ Production: offline (air-gapped) transfer

.PHONY: offline-export offline-import
offline-export: ## On a connected build host: make offline-export [OUT=/tmp/lantern-offline]
	scripts/export-offline.sh $(OUT)
offline-import: ## On the offline server: make offline-import BUNDLE=/media/transfer/lantern-offline
	$(call require,BUNDLE)
	scripts/import-offline.sh $(BUNDLE)

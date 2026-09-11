# Curator developer entry points (system_design.md §11).

COMPOSE  := docker compose
ENV_FILE := api/.env
ENV_LINK := .env

.DEFAULT_GOAL := help
.PHONY: help up down reset seed seed-offline eval logs shell-api psql

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-10s %s\n", $$1, $$2}'

up: $(ENV_FILE) $(ENV_LINK) ## Build and start db, api, web; returns once all three are healthy
	$(COMPOSE) up --build --detach --renew-anon-volumes --wait
	@echo ""
	@echo "  web   http://localhost:5173"
	@echo "  api   http://localhost:8000/health"

down: ## Stop and remove containers (database volume is kept)
	$(COMPOSE) down

reset: $(ENV_FILE) $(ENV_LINK) ## Stop, DELETE the database volume, start again (re-runs db/init)
	$(COMPOSE) down --volumes
	@$(MAKE) --no-print-directory up

seed: ## Load ATT&CK techniques, then the apt29 events and ground truth
	$(COMPOSE) exec curator-api python -m curator.attack.load_attack
	$(COMPOSE) exec curator-api python -m curator.ingest.seed apt29

seed-offline: ## Same as seed, in a container with no route to the internet
	$(COMPOSE) --profile offline run --rm curator-seed-offline

eval: ## Run the accuracy harness (Step 6)
	@echo "not implemented yet"

logs: ## Follow logs from all services
	$(COMPOSE) logs --follow --tail=100

shell-api: ## Bash shell inside curator-api
	$(COMPOSE) exec curator-api bash

psql: ## psql inside curator-db, using the container's own credentials
	$(COMPOSE) exec curator-db sh -c 'exec psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"'

# First run only: create api/.env from the template with a random database password.
$(ENV_FILE):
	@cp .env.example $@
	@chmod 600 $@
	@sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$$(openssl rand -hex 24)/" $@
	@echo "Created $@ from .env.example with a random POSTGRES_PASSWORD."

# Compose interpolates curator-db's POSTGRES_* from ./.env; point it at the one real file.
$(ENV_LINK): | $(ENV_FILE)
	@ln -s $(ENV_FILE) $@
	@echo "Linked ./.env -> $(ENV_FILE)."

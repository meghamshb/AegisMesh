.PHONY: up up-pilot up-fleet down down-fleet test smoke smoke-fleet docker-check ui-build ui-dev test-integration register-agent

docker-check:
	@docker info >/dev/null 2>&1 || { \
	  echo "Docker is not running. Start Docker Desktop, wait for it to finish booting, then retry."; \
	  echo "  open -a Docker"; \
	  exit 1; \
	}

ui-build:
	cd services/approval-ui && npm ci && npm run build

ui-dev:
	cd services/approval-ui && npm run dev

up: docker-check
	docker compose up --build

up-pilot: docker-check
	docker compose -f docker-compose.yml -f docker-compose.pilot.yml up --build

down:
	docker compose down

down-pilot:
	docker compose -f docker-compose.yml -f docker-compose.pilot.yml down

test: ui-build
	cd services/policy-gateway && go test ./...

test-integration: ui-build docker-check
	cd services/policy-gateway && go test -tags=integration ./internal/store/...

smoke: docker-check
	./scripts/smoke-phase0.sh

# Phase 5.10: one control plane, two separate enforcement gateways. Brings the
# fleet up itself (gateways cannot start before they have a credential), so do
# not run `up-fleet` first.
smoke-fleet: ui-build docker-check
	./scripts/smoke-phase510-fleet.sh

up-fleet: docker-check
	docker compose -f docker-compose.fleet.yml up -d --build postgres control-plane

down-fleet:
	docker compose -f docker-compose.fleet.yml down -v

register-agent:
	./scripts/register-agent.sh $(OWNER_USER_ID) $(AGENT_NAME) $(CONTAINER_ID)

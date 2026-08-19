.PHONY: up up-pilot down test smoke docker-check ui-build ui-dev test-integration

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

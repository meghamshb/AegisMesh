.PHONY: up down test smoke docker-check

docker-check:
	@docker info >/dev/null 2>&1 || { \
	  echo "Docker is not running. Start Docker Desktop, wait for it to finish booting, then retry."; \
	  echo "  open -a Docker"; \
	  exit 1; \
	}

up: docker-check
	docker compose up --build

down:
	docker compose down

test:
	cd services/policy-gateway && go test ./...

smoke: docker-check
	./scripts/smoke-phase0.sh

# ACP for Hermes Agents

Hermes Policy Gateway — an egress policy gateway and approval web UI so Hermes agents in Docker cannot reach the internet without logging, human approval, and optional org-scoped allow rules.

- **Repo:** [meghamshb2006/ACP-For-Hermes-Agents](https://github.com/meghamshb2006/ACP-For-Hermes-Agents)
- **Spec:** [`docs/specs/hermes-policy-gateway.md`](docs/specs/hermes-policy-gateway.md)

## Phase 0 status

Scaffold only:

- `docker compose up --build` runs Postgres, policy-gateway stub, and Hermes stub
- Gateway exposes `/health` and read-only control-plane list endpoints
- HTTP(S) proxy, approval workflow, and network lockdown arrive in phases 1–4

## Architecture

```
Developer ──► Hermes (Docker) ──HTTP_PROXY──► Policy Gateway ──► Internet APIs
                    │                              │
                    │                              ├──► Postgres
                    │                              └──► Approval UI (phase 2+)
```

Hermes attaches only to the `agent` network. Postgres lives on the `data` network. The gateway joins `data`, `agent`, and `egress`, so Hermes can reach the gateway but not the database or public internet directly.

## Quick start

```bash
docker compose up --build
```

Verify health:

```bash
curl http://localhost:8080/health
curl http://localhost:8080/api/v1/requests?status=pending
curl http://localhost:8080/api/v1/rules
```

## Services

| Service | Path | Responsibility |
|---------|------|----------------|
| `policy-gateway` | `services/policy-gateway/` | Control plane API (proxy in phase 1) |
| `hermes` | `services/hermes/` | Agent runtime stub (real Hermes image in phase 4) |
| `postgres` | `deploy/postgres/init/` | Schema bootstrap |

## Branch workflow

| Branch | Purpose |
|--------|---------|
| `main` | Default |
| `feat/*` | Features |
| `docs/*` | Documentation |
| `chore/*` | Tooling and scaffold |

## MVP phases

See the spec for acceptance criteria. Current target: **Phase 0 complete**, next **Phase 1** (proxy + Postgres logging + default deny).

## Development

```bash
make up      # docker compose up --build
make smoke   # network isolation checks (requires running stack)
make test    # go test ./... in policy-gateway
```

Environment variables are documented in [`.env.example`](.env.example).

## Layout

```
services/policy-gateway/internal/
  api/      control-plane HTTP handlers
  app/      wiring + proxy/api dispatch
  config/   env configuration
  domain/   shared types
  policy/   evaluation engine (stub)
  proxy/    data-plane handler (stub)
  service/  orchestration between API and store
  store/    postgres persistence
```

# ACP for Hermes Agents

Hermes Policy Gateway — an egress policy gateway and approval web UI so Hermes agents in Docker cannot reach the internet without logging, human approval, and optional org-scoped allow rules.

- **Repo:** [meghamshb2006/ACP-For-Hermes-Agents](https://github.com/meghamshb2006/ACP-For-Hermes-Agents)
- **Spec:** [`docs/specs/hermes-policy-gateway.md`](docs/specs/hermes-policy-gateway.md)

## Phase status

- **Phase 0:** Scaffold complete
- **Phase 1:** HTTP(S) proxy with default deny + pending persistence
- **Phase 2:** Approval web UI at `/ui`, approve-once/deny API, one-time grant on retry
- **Phase 2.75:** Pending-first inbox hardening, minimal admin protection, reviewer attribution, safer approve/deny flow

## Architecture

```
Developer ──► Hermes (Docker) ──HTTP_PROXY──► Policy Gateway ──► Internet APIs
                    │                              │
                    │                              ├──► Postgres
                    │                              └──► Approval UI (`/ui`)
```

Hermes attaches only to the `agent` network. Postgres lives on the `data` network. The gateway joins `data`, `agent`, and `egress`, so Hermes can reach the gateway but not the database or public internet directly.

## Quick start

```bash
docker compose down -v   # reset DB when init SQL changes
docker compose up --build
make smoke
```

If Postgres was already initialized before Phase 1 seed data was added, recreate the volume with `docker compose down -v` before `up`.

Verify health:

```bash
curl http://localhost:8080/health
curl http://localhost:8080/api/v1/requests?status=pending
curl http://localhost:8080/api/v1/rules
open http://localhost:8080/ui
```

If you set `GATEWAY_ADMIN_TOKEN`, the UI/API require that token and an approver identifier for review actions.

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

See the spec for acceptance criteria. **Phase 2.75 complete:** the inbox defaults to pending rows, refreshes automatically, confirms CONNECT approvals, and can be token-gated for internal pilots. Next: **Phase 3** org rules (`remember: true`).

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
  policy/   evaluation engine
  proxy/    data-plane handler
  service/  orchestration between API and store
  store/    postgres persistence
  ui/       embedded approval inbox
```

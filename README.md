# ACP for Hermes Agents

Hermes Policy Gateway — an egress policy gateway and approval web UI so Hermes agents in Docker cannot reach the internet without logging, human approval, and optional org-scoped allow rules.

- **Repo:** [meghamshb2006/ACP-For-Hermes-Agents](https://github.com/meghamshb2006/ACP-For-Hermes-Agents)
- **Spec:** [`docs/specs/hermes-policy-gateway.md`](docs/specs/hermes-policy-gateway.md)

## Phase status

| Phase | Status | Notes |
|-------|--------|-------|
| 0 Scaffold | **Done** | Compose, Makefile, this README |
| 1 Gateway core | **Done** | HTTP(S) proxy, default deny, Postgres logging |
| 2 Approval UI | **Done** | `/ui`, approve-once, deny, consumable retry grant |
| 2.5 Team inbox | **Done** | React + Vite inbox; master-detail, tabs, filters |
| 2.75 Pilot hardening | **Done** | Admin token, polling, modals, CONNECT warnings |
| 3 Org rules | **Done** | Approve + remember for org; auto-approve with `rule_id` |
| 3.5 Policy hardening | **Done** | POST rules, expires_at, cross-agent identity headers |
| 3.6 UI polish | **Done** | Utilitarian React console (internal-system wireframe style) |
| 4 Hermes + lockdown | **Done** | Real Hermes agent; terminal-tool egress smoke (REST approve in CI) |
| 5 Hardening | **Not started** | SSO, TLS, export |

Full acceptance criteria: [`docs/specs/hermes-policy-gateway.md`](docs/specs/hermes-policy-gateway.md).

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
| `policy-gateway` | `services/policy-gateway/` | HTTP(S) proxy, REST API, embedded approval UI at `/ui` |
| `hermes` | `services/hermes/` | Hermes Agent runtime (NousResearch); tool egress via gateway |
| `postgres` | `deploy/postgres/init/` | Schema bootstrap |

## Branch workflow

| Branch | Purpose |
|--------|---------|
| `main` | Default |
| `feat/*` | Features |
| `docs/*` | Documentation |
| `chore/*` | Tooling and scaffold |

## MVP phases

See the spec for full acceptance criteria and open items.

**Next priority:** Phase 5 — SSO, TLS, audit export, multi-tenant hardening.

## Development

```bash
make ui-build   # build React inbox into gateway embed dir
make ui-dev     # Vite dev server (proxies API to :8080)
make up         # docker compose up --build
make smoke      # network isolation checks (requires running stack)
make test       # ui-build + go test ./... in policy-gateway
```

Environment variables are documented in [`.env.example`](.env.example).

## Layout

```
services/approval-ui/          React approval inbox (Vite)
services/policy-gateway/internal/
  api/      control-plane HTTP handlers
  app/      wiring + proxy/api dispatch
  config/   env configuration
  domain/   shared types
  policy/   evaluation engine
  proxy/    data-plane handler
  service/  orchestration between API and store
  store/    postgres persistence
  ui/       embedded React build (dist/)
```

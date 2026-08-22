# Clearance

**Outbound policy for AI agents.**

Run [Hermes](https://github.com/NousResearch/hermes-agent) in Docker. Every tool call that hits the web goes through an egress gateway. Unknown destinations are blocked until a human approves — or auto-approved when they match an org rule. Everything is logged.

```
                    Clearance Control Plane
         users │ agents │ rules │ audit │ approvals │ gateways
                              │
                          Postgres
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
         Gateway A                       Gateway B
              │                               │
          Hermes A                        Hermes B
           (Alice)                          (Bob)
              │                               │
              └───────── gated internet ──────┘
```

One control plane holds policy, identity, and the audit trail. Gateways
enforce it — each fetching a versioned policy snapshot, so a rule created once
reaches every gateway without restarting anything. Agents can only reach the
internet through their own gateway.

Runs as a single container too (`CLEARANCE_MODE=all`, the default) — the fleet
is what it scales into, not what it requires.

---

## Why

Agents call APIs, fetch URLs, and run shell commands. On a corporate laptop, that traffic is often invisible — and hard to gate.

Clearance is the missing layer: **default deny**, **human-in-the-loop approval**, **org-wide allow rules**, and a full **audit trail**. Model inference stays on a separate egress path; tool traffic is what you control.

---

## Features

| | |
|---|---|
| **Default deny** | Unknown hosts return 403 until approved |
| **Approval console** | Inbox, rules registry, audit log — embedded at `/ui` |
| **Approve once** | One-time grant; agent retries and succeeds |
| **Remember for org** | Teammates auto-approve matching patterns |
| **Network lockdown** | Hermes cannot bypass the proxy (Docker + iptables) |
| **SSRF guard** | Internal upstreams and the control plane hard-denied (no approval queue) |
| **Rate limiting** | Auth failures and privileged mutations throttled; reads and agent traffic are not |
| **SSO-ready** | OIDC sign-in for operators (Entra, Google, Auth0, Keycloak); roles stay in Clearance |
| **Real Hermes runtime** | Terminal + web toolsets; Codex OAuth in pilot profile |

---

## Screenshots

### Approval inbox

Pending egress requests with approve-once, org rule, and deny actions.

<p align="center">
  <img src="docs/assets/inbox.png" alt="Clearance approval inbox" width="900">
</p>

### Org rules

Persistent allow rules by host, method, and path prefix.

<p align="center">
  <img src="docs/assets/rules.png" alt="Clearance policy rules" width="900">
</p>

### Audit log

Every decision logged — pending, approved, denied, auto-approved.

<p align="center">
  <img src="docs/assets/audit.png" alt="Clearance audit log" width="900">
</p>

### Agent + gateway (end-to-end)

Hermes chat triggers a terminal `curl` → blocked → approve in UI → retry succeeds.

<p align="center">
  <img src="docs/assets/agent-chat.png" alt="Hermes agent blocked then approved egress" width="900">
</p>

---

## Quick start

**Requirements:** Docker Desktop, Make

```bash
git clone https://github.com/meghamshb2006/Clearance.git
cd Clearance
cp .env.example .env
make up
```

Open the console: [http://localhost:8080/ui](http://localhost:8080/ui)

| Field | Dev default |
|-------|-------------|
| Admin token | `dev-local-admin-token` |
| Approver ID | `11111111-1111-1111-1111-111111111002` |

Verify:

```bash
make smoke
curl http://localhost:8080/health
```

---

## Demo: one policy change, two gateways

The end-to-end story, automated:

```bash
make smoke-fleet
```

What it does, and what to watch for:

| Step | | Expected |
|---|---|---|
| 1 | Start control plane + two gateways | Each logs `policy snapshot loaded` |
| 2 | Register Alice and Bob, an agent each, a gateway each | Tokens shown once |
| 3 | Alice's agent requests `example.com` | **Blocked** — default deny |
| 4 | Bob's agent requests the same | **Blocked**, independently |
| 5 | Create one org allow rule | A single action, in one place |
| 6 | Wait one refresh interval | `policy_version` advances on both gateways |
| 7 | Alice retries | **Allowed** |
| 8 | Bob retries | **Allowed** — same rule, different gateway |
| 9 | Revoke the rule centrally | |
| 10 | Both retry | **Blocked** again, both |

No container is restarted at any point. Steps 6–8 are the claim: the only path
a rule can take to a gateway is the versioned snapshot fetch, so the wait is
real propagation rather than a shared database read.

Walk it manually with [`docs/runbooks/phase5-fleet-demo.md`](docs/runbooks/phase5-fleet-demo.md),
or see per-user scopes and role behaviour in
[`docs/runbooks/phase5-multi-user-demo.md`](docs/runbooks/phase5-multi-user-demo.md).

---

## Pilot profile (LLM + gated tools)

For Hermes chat with Codex or API keys — model egress on a separate network, tools still gated:

```bash
make up-pilot
```

Then inside the container:

```bash
docker compose -f docker-compose.yml -f docker-compose.pilot.yml exec -it hermes bash
hermes auth add openai-codex   # or set OPENAI_API_KEY in .env
hermes model
hermes
```

Full walkthrough: [`docs/runbooks/phase41-pilot-demo.md`](docs/runbooks/phase41-pilot-demo.md)

**Demo tip:** use `example.com` for inbox demos. Avoid `httpbin.org` after `make smoke` — the deny test leaves a standing block for that host.

---

## Development

```bash
make ui-build      # embed React console into gateway
make ui-dev        # Vite dev server → :8080
make test          # go test ./...
make smoke         # E2E proxy + lockdown checks (stack must be running)
make smoke-fleet   # multi-gateway fleet demo (manages its own stack)
make down-pilot    # tear down pilot stack
```

### Multi-gateway fleet

`make smoke-fleet` stands up a control plane plus two independent gateway
containers, each with its own agent on its own isolated network, and proves that
a single policy change made once centrally reaches both gateways — and is then
withdrawn from both — without restarting either container.

Environment variables: [`.env.example`](.env.example)

### Documentation

| | |
|---|---|
| [Architecture](docs/architecture/control-plane.md) | Planes, identities, policy precedence, failure behaviour, the CONNECT limitation |
| [Threat model](docs/security/threat-model.md) | Assets, threats, and what is explicitly *not* defended |
| [Egress bypass evaluation](docs/security/egress-bypass-evaluation.md) | Measured results, regenerated by the harness |
| [Spec](docs/specs/hermes-policy-gateway.md) | Full specification and phase history |
| [Runbooks](docs/runbooks/) | Fleet demo, multi-user demo, agent registration, credential rotation |

---

## Stack

| Component | Path |
|-----------|------|
| Policy gateway (Go) | `services/policy-gateway/` |
| Approval UI (React) | `services/approval-ui/` |
| Hermes runtime | `services/hermes/` |
| Postgres schema | `deploy/postgres/init/` |

Built for [Hermes Agent](https://github.com/NousResearch/hermes-agent). Does not require NemoHermes, OpenShell, or a LAP fork.

---

## Status

**`v0.9.0` — multi-user control-plane preview.**

Deliberately not 1.0. TLS, OIDC, and a measured security evaluation all exist,
but each carries a real caveat: the OIDC seam has never been exercised against
a live identity provider, TLS is a listener option with no certificate
lifecycle around it, and the evaluation documents its own gaps. "Preview" is
the honest label.

Phases 0–4.1 complete (gateway, inbox, org rules, Hermes lockdown, pilot profile).

Phases 5.2–5.10 complete: multi-user schema, agent credentials, authenticated
proxy identity, scoped policy semantics, control-plane management APIs, admin
UI, control/data-plane split, gateway registration with versioned policy
snapshots, and a multi-gateway fleet in which one central policy change
controls several independent enforcement gateways without restarting them.
A hardening pass org-scoped every tenant-owned query and added cross-org test
suites — see "Tenant isolation (locked contract)" and "Phase 5.10" in
[docs/specs/hermes-policy-gateway.md](docs/specs/hermes-policy-gateway.md).

Run `make smoke` for the single-node path and `make smoke-fleet` for the
multi-gateway demo.

Phase 5.11 (security hardening) closed an SSRF gap where proxied agent traffic
could reach the control plane, and added rate limiting on authentication
failures and privileged mutations, credential-hygiene tests against real
Postgres, and the cross-tenant test matrix. Phase 5.12 added a reproducible
egress security evaluation (see Security below).

Still open: SSO / per-caller admin auth, TLS termination, CSV audit export.

---

## Authentication

Two modes, selected by `CLEARANCE_AUTH_MODE`:

| Mode | Use | Notes |
|---|---|---|
| `dev-token` | Local development | Shared static token. Cannot attribute an action to a person, so the gateway warns at startup and the console shows a `DEV-TOKEN MODE` badge. |
| `oidc` | Production | Operators sign in through your identity provider. Provider-neutral — Entra ID, Google, Auth0, Keycloak, Okta. |

```bash
CLEARANCE_AUTH_MODE=oidc
OIDC_ISSUER_URL=https://login.microsoftonline.com/<tenant>/v2.0
OIDC_CLIENT_ID=<application-id>
```

The identity provider proves **who** you are. Clearance decides **what** you
may do: roles live in its own directory and are never read from a token claim.
A verified identity with no Clearance account is refused rather than
auto-provisioned, so granting access stays a deliberate act.

Agent credentials (`clr_agent_...`) are a separate trust domain and are
unaffected. Clearance stores no passwords and has no login database.

---

## Security

Measured, not asserted:

> **41/41 evaluated egress bypass cases were blocked or mediated in the tested
> Docker Compose configuration.**

That number is generated by `./scripts/security/run-evaluation.sh`, which runs
every case against a live fleet stack and regenerates
[`docs/security/egress-bypass-evaluation.md`](docs/security/egress-bypass-evaluation.md).
The report lists each attempt, its expected and actual outcome, the exact
configuration tested, and the known gaps -- including what the suite *cannot*
observe.

This is **not** a claim that Clearance prevents all network bypasses. Read the
report's "Known gaps" section before relying on any of it.

```bash
./scripts/security/run-evaluation.sh
```

---

## License

MIT — see [LICENSE](LICENSE).

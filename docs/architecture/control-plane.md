# Clearance architecture

How the system is put together, and — more usefully — why each boundary is
where it is. Read this before changing anything that touches identity, policy,
or the network topology.

Version: `0.9.0-multi-user-preview`.

---

## The two planes

Clearance is one binary that can run as either half, or both.

```
                        Clearance Control Plane
             users | agents | rules | audit | approvals | gateways
                                  │
                              Postgres
                                  │
              ┌───────────────────┴───────────────────┐
              │                                       │
              ▼                                       ▼
         Gateway A                               Gateway B
      (data plane)                            (data plane)
              │                                       │
          Hermes A                                Hermes B
           (Alice)                                  (Bob)
              │                                       │
              └────────── gated internet ─────────────┘
```

| | Control plane | Data plane (gateway) |
|---|---|---|
| Serves | Admin API, approval console | HTTP/CONNECT egress proxy |
| Authenticates | Humans (OIDC or dev token) | Agents (credential) |
| Decides | *Who may manage what* | *Whether this request goes out* |
| `CLEARANCE_MODE` | `control` | `gateway` |

`CLEARANCE_MODE=all` runs both on one listener and is the default — the
single-host deployment from Phases 0–4, unchanged.

The split exists so the surface an agent can reach is not the surface an
administrator uses. A gateway's listener serves the proxy and `GET /health`,
and nothing else: no user management, no rules API, no console. That is
structural, not a permission check.

---

## Three identities, three trust domains

The most important thing to understand about Clearance is that these never
mix.

### Agent identity

```
clr_agent_<random>  ──sha256──▶  agent_credentials.token_hash
                                          │
                                          ▼
                                  agent → owner → org
```

Derived from a bearer credential in `Proxy-Authorization`. Produces an org, a
user, and an agent. Only the SHA-256 hash is stored; the plaintext is shown
once at issue and never again.

In `token` mode, identity comes *only* from the credential. The
`X-Gateway-Agent-Id` override header is ignored entirely — otherwise a valid
Agent A token could claim to be Agent B.

### Gateway identity

```
clr_gateway_<random>  ──sha256──▶  gateways.credential_hash  ──▶  org + gateway
```

Authenticates a gateway *process* to the control plane, for policy sync,
heartbeats, and remote agent-identity lookup. It is not an agent credential
and cannot be used as one: the two are stored in different tables and each
lookup only consults its own.

### Human identity

```
OIDC token ──▶ (issuer, subject) ──▶ "<issuer>#<subject>"
                                              │
                                    actors.external_subject
                                              │
                                              ▼
                                      actor → role, org
```

The identity provider proves **who**. Clearance decides **what**: the role
comes from `actors.role`, never from a token claim. `auth.Claims` deliberately
has no `Role` field, so the code cannot accidentally trust one.

The issuer is part of the stored key because a bare subject is only unique
*within* an issuer — otherwise a second, attacker-controlled issuer could mint
a token with the same subject and inherit the account.

---

## Policy

### Precedence

Evaluation is deterministic and contains no LLM. For a request
`(org, user, agent, host, port, method, path)`:

1. Collect every rule in the caller's org matching host, port, method
   (exact or `*`), and path prefix on a segment boundary, that has not expired,
   and whose scope points at this org, this user, or this agent.
2. **Any matching `deny` wins**, at any scope. Deny is not outranked by a more
   specific allow — a narrower rule must not be able to re-permit something an
   administrator explicitly forbade.
3. Otherwise, a standing denial for this exact agent+destination (from a
   previous human "deny") also blocks.
4. Otherwise, the **most specific `allow`** applies: agent > user > org. This
   only decides which `rule_id` is attributed; any of them would allow.
5. Otherwise, a one-time approval grant is consumed, if one exists.
6. Otherwise the request is **pending**: blocked, queued for a human.

Default is deny. Nothing reaches the internet because it was not mentioned.

### Path matching

A rule's `path_prefix` matches only on a segment boundary, so `/api` does not
authorize `/apikeys`. A prefix already ending in `/` is on a boundary by
construction — which is what makes the default prefix `/` mean "this whole
host" rather than "only the literal path `/`".

### Snapshots

A gateway configured with `CLEARANCE_CONTROL_URL` does not query Postgres for
policy. It fetches a versioned, org-scoped snapshot and evaluates locally:

```
control plane ──GET /api/internal/v1/policies/snapshot──▶ gateway cache
                     (version bumps on every rule mutation)
```

`organization_policy_versions.version` increments inside the same transaction
as any rule create or revoke, so a version change and a policy change cannot
disagree.

The snapshot deliberately excludes request-history state — standing denials and
approve-once grants — because that is mutable per-request state, not policy.

**Parity matters here.** The snapshot matcher re-expresses the SQL `WHERE`
clause in Go. Two implementations of one predicate is a standing hazard: if
they drift, the same request gets one verdict centrally and another at the
edge. `internal/store/policy_parity_integration_test.go` runs a matrix of
requests through both against real Postgres and asserts identical results.
Change one side, mirror it in the other, or that test fails.

---

## Failure behaviour

Everything degrades toward *refusing traffic*, never toward allowing it.

| Condition | Behaviour |
|---|---|
| Gateway cannot load a snapshot at startup | Process exits. It must never proxy against unknown policy. |
| Control plane unreachable, snapshot fresh | Keeps enforcing last-known-good policy. An outage is not an outage of enforcement. |
| Snapshot older than `CLEARANCE_POLICY_MAX_STALE` | Evaluation refuses. No silent fallback to SQL — that would defeat the guarantee. |
| Agent identity cache expired, control plane down | Refuses with 503 "cannot verify agent identity". |
| Destination name will not resolve | Refused. An unresolvable host cannot be proven external. |
| Postgres write of `last_used_at` fails | Logged, request proceeds. Display-only bookkeeping must not take agents offline. |

The last row is the one exception, and it is deliberate: those columns feed the
console, not a decision.

There is an availability cost. A long control-plane outage eventually stops
egress entirely, once identity caches expire. That is the intended direction to
fail, but it is a cost, not a free property.

---

## Network boundary

The proxy is not the only thing standing between an agent and the internet, and
it must not be.

```
gateway-a-net  (internal: true)   hermes-a  ◀──▶  gateway-a
gateway-b-net  (internal: true)   hermes-b  ◀──▶  gateway-b
control-net                       postgres, control-plane, gateways
egress         (bridge)           gateways only
```

Each agent sits alone with its gateway on a network with no route out. Unset
`HTTP_PROXY`, set `NO_PROXY=*`, open a raw socket — none of it reaches the
internet, because there is no path. The proxy mediates; Docker enforces.

### SSRF, and the control plane specifically

Proxied agent traffic is refused for loopback, RFC1918, link-local (including
`169.254.169.254`), IPv6 loopback/ULA/link-local, `.local`/`.internal`, the
database, and **the configured control plane by name**.

That last one is the subtle case. A gateway legitimately talks to the control
plane constantly; proxied agent traffic must never reach it, even though both
leave the same process. Relying on the control plane resolving to a private
address is not enough — in a split deployment it is publicly addressable.

These destinations are **hard-denied**, never queued. Nobody can approve their
way to the metadata service.

Resolution and connection are a single step: the guard resolves once, refuses
if *any* returned address is internal, and dials an address it validated rather
than the name. Validating and then dialling separately is DNS rebinding.

---

## The HTTPS CONNECT limitation

This is the most important thing to understand about what Clearance cannot do.

For plain HTTP, the gateway sees method, host, port, and path, and evaluates all
of them.

For HTTPS, the client issues `CONNECT host:443` and everything after is an
encrypted tunnel. Clearance sees **the hostname and nothing else**:

- No path. A rule for `/safe` cannot be enforced over a tunnel.
- No visibility into redirects, uploads, or what is actually transferred.
- No way to notice a permitted host being used as a relay.

Consequences, all deliberate:

- Approving a CONNECT request grants **host-level** access for that agent.
- "Remember this rule" is **refused outright** for CONNECT. A remembered
  host-level allow would silently over-authorize at every scope, and the
  console says so at the point of decision.
- The path recorded for a CONNECT request is `/` — a placeholder, not an
  observation.

Seeing inside would require terminating TLS and presenting a forged
certificate to the agent. That is a different product with different trust
properties, and Clearance does not do it.

---

## Data model

Nine tables. `actors` covers both humans and the agent-owner relationship;
there is deliberately no separate `users` table.

```
organizations ──┬── actors ──── agents ──── agent_credentials
                ├── gateways
                ├── policy_rules
                ├── egress_requests ──── audit_events
                └── organization_policy_versions
```

Every tenant-owned row carries `org_id`, and every query filters on it — see
"Tenant isolation (locked contract)" in the spec for the full rule, including
the four lookups that are deliberately *not* org-scoped because they are the
hop that *produces* the org.

Two deliberate departures from the schema sketched in the phase spec:

- **`audit_events.org_id`** was added. The sketch omitted it, which left the
  audit log with nothing to filter on — every organization's trail visible to
  any admin.
- **`gateways.policy_version` / `active_agents`** were added to back the
  Gateways tab, rather than burying them in `metadata_json` where they could
  not be ordered or indexed.

---

## Where to look in the code

| Concern | Package |
|---|---|
| Policy evaluation, precedence, snapshot matcher | `internal/policy` |
| SQL, tenancy contract | `internal/store` |
| Agent + gateway credentials | `internal/identity` |
| Human authentication (OIDC seam) | `internal/auth` |
| Proxy, SSRF guard, CONNECT | `internal/proxy` |
| Snapshot cache, refresh, staleness | `internal/policycache` |
| Heartbeat / fleet reporting | `internal/fleet` |
| Control-plane HTTP surface | `internal/api` |

---

## Related documents

- [`docs/specs/hermes-policy-gateway.md`](../specs/hermes-policy-gateway.md) — full spec and phase history
- [`docs/security/threat-model.md`](../security/threat-model.md) — assets, threats, and what is not defended
- [`docs/security/egress-bypass-evaluation.md`](../security/egress-bypass-evaluation.md) — measured bypass results

# Threat model

What Clearance protects, what it protects against, and — the part that matters
most — what it does not.

Version: `0.9.0-multi-user-preview`. Companion to
[`egress-bypass-evaluation.md`](egress-bypass-evaluation.md), which measures
some of these claims rather than asserting them.

---

## Scope

Clearance mediates **outbound tool traffic from AI agents**. The adversary
model assumes the agent itself may be acting against you — because that is the
realistic case. An agent following instructions from a web page it fetched, or
from a poisoned document, is an attacker with your agent's credentials and your
agent's network position.

Clearance does **not** attempt to make the agent trustworthy. It assumes the
agent is not, and constrains what it can reach.

---

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Agent credentials | `agent_credentials.token_hash` (SHA-256 only) | Bearer access to egress as a specific agent |
| Gateway credentials | `gateways.credential_hash` (SHA-256 only) | Fetch an org's policy; resolve agent identity |
| Organization policy | `policy_rules` | Decides what leaves the network |
| Audit events | `audit_events` | The record of who approved what, and when |
| Approval authority | `actors.role` | The power to permit egress |
| Agent workspace | Hermes container | Source data an agent can exfiltrate |
| Admin/OIDC session | Browser, identity provider | Full control-plane authority |

No plaintext credential is ever stored. Human passwords do not exist: there is
no registration, reset, or credential table for people.

---

## Threats

Index, for looking up a specific one:

| Threat | Section |
|---|---|
| Agent attempts direct egress | [Bypass the proxy](#the-agent-tries-to-bypass-the-proxy) |
| Agent impersonates another agent | [Become someone else](#the-agent-tries-to-become-someone-else) |
| Agent accesses another org | [Cross-tenant](#cross-tenant) |
| Stolen agent credential | [Stolen credentials](#stolen-credentials) |
| Stolen gateway credential | [Stolen credentials](#stolen-credentials) |
| Admin credential compromise | [Stolen credentials](#stolen-credentials) |
| Malicious redirect | [Malicious redirects](#malicious-redirects) |
| SSRF | [Internal infrastructure](#the-agent-tries-to-reach-internal-infrastructure) |
| Stale policy | [Availability and stale policy](#availability-and-stale-policy) |
| Control plane outage | [Availability and stale policy](#availability-and-stale-policy) |

Each row below states the defence and links to the evidence. `EGR-*`, `SSRF-*`,
`ID-*`, `FLEET-*`, `API-*` are case IDs in the evaluation report.

### The agent tries to bypass the proxy

| Threat | Defence | Evidence |
|---|---|---|
| Direct connection, proxy env unset | The agent's network has no route out. Docker enforces this, not the proxy. | `EGR-08` |
| `NO_PROXY=*` to skip the proxy | Same — removing the proxy removes egress, it does not grant it. | `EGR-10` |
| Raw socket, bypassing HTTP libraries | Same. | `EGR-07` |
| A library that ignores proxy settings | Same. This is why network lockdown exists rather than trusting `HTTP_PROXY`. | `EGR-07`–`EGR-10` |
| Alternate env-var casing | Enforcement does not depend on which variable the client read. | `EGR-09` |

**The proxy is not the boundary. The network is.** The proxy decides; the
network makes deciding unavoidable.

### The agent tries to become someone else

| Threat | Defence | Evidence |
|---|---|---|
| No credential | Refused in `token` mode. | `ID-01` |
| Forged or guessed credential | Opaque 256-bit token, matched by hash. | `ID-02` |
| Revoked credential | Revocation is immediate; negative results are never cached. | `ID-03` |
| Spoofed `X-Gateway-Agent-Id` header | Ignored entirely in `token` mode. Attribution follows the credential. | `ID-04`, `ID-05` |
| Another org's agent credential | The gateway's org must equal the agent's org; a mismatch reads as an unknown token. | `ID-06` |
| Credential guessing at volume | Authentication failures are rate-limited per source. | `internal/ratelimit` |

### The agent tries to reach internal infrastructure

| Threat | Defence | Evidence |
|---|---|---|
| Loopback, RFC1918, link-local | Hard-denied. | `SSRF-01`–`SSRF-06` |
| Cloud metadata (`169.254.169.254`) | Hard-denied — the classic credential-theft target. | `SSRF-06` |
| IPv6 loopback / ULA / link-local | Hard-denied, including bracketed literals with no port. | `SSRF-07`–`SSRF-09` |
| The database by service name | Hard-denied. | `SSRF-10` |
| **The control plane** | Blocked **by name**, not just by address — a production control plane is publicly addressable, so the private-range check alone would miss it. | `SSRF-11` |
| A hostname resolving to a private IP | Resolved and checked. | `SSRF-13` |
| **DNS rebinding** | The guard resolves once and dials the address it validated. Validating and dialling separately is the bug. | `SSRF-16` |
| Unresolvable name | Refused — it cannot be proven external. | `SSRF-15` |
| Approving your way in | These are **hard denials**; they never enter the approval queue. | `SSRF-14` |

### Stolen credentials

| Threat | Blast radius | Mitigation |
|---|---|---|
| Stolen **agent** credential | Egress as that agent, subject to its org's policy. Cannot read the control plane, cannot reach another org. | Rotate (`POST /agents/{id}/credentials/rotate`) or revoke; both take effect immediately. |
| Stolen **gateway** credential | Read that org's policy snapshot; resolve agent identity *within that org*. Cannot approve, cannot mutate, cannot act as an agent. | Heartbeat rejects a credential/gateway-id mismatch. Revoke the gateway. |
| Stolen **admin** credential | Full authority over that org: approve egress, create rules, mint agent credentials. | This is the top of the tree. Use `CLEARANCE_AUTH_MODE=oidc` so access follows your identity provider — offboarding there revokes here. Privileged mutations are rate-limited, and every one is audited. |

A stolen admin credential is not survivable by design; it is the authority
being modelled. The realistic defence is not sharing one — which is exactly
why `dev-token` mode warns at startup and shows a badge in the console.

### Cross-tenant

| Threat | Defence |
|---|---|
| Reading another org's users, agents, rules, requests, audit | Every tenant-owned query filters on `org_id`, sourced from the authenticated caller and never from request input. |
| Mutating another org's data by id | Same. A row in another org returns **404, not 403** — a distinct error would confirm it exists. |
| Minting a credential for another org's agent | Refused before anything is issued. |
| Creating a rule scoped to another org's user or agent | `scope_ref_id` must resolve inside the caller's org. |
| An org-B gateway resolving an org-A agent | Rejected as an unknown token. |

Covered by `internal/api/crossorg_test.go` and
`internal/store/crossorg_integration_test.go` (the latter against real
Postgres, so the SQL itself is proven to carry the predicate).

### Malicious redirects

An approved host returns `302` to `169.254.169.254`.

The gateway **never follows redirects**. The response is handed back to the
client, whose next request is proxied and evaluated on its own merits — where
the SSRF guard refuses it. Every hop is a fresh decision.
(`internal/proxy/redirect_test.go`.)

### Availability and stale policy

| Threat | Behaviour |
|---|---|
| Control plane down, snapshot fresh | Last-known-good policy still enforced (`FLEET-02`). |
| Control plane down, unapproved host | Still gated (`FLEET-03`). |
| Snapshot stale past ceiling | Evaluation refuses; no fallback to SQL (`FLEET-05`/`06`). |
| Gateway cannot load policy at boot | Process exits rather than proxying blind (`FLEET-04`). |
| Attacker induces an outage to open the gate | The gate closes, not opens. |

The trade-off is explicit: a long control-plane outage becomes an egress
outage.

### Tampering with the record

Audit events have no delete endpoint, and none should be added. Retention, if
ever needed, belongs in an explicit archival policy — not a `DELETE` route.
Approvals record the deciding actor; in `oidc` mode that is a real person, and
in `dev-token` mode it is a shared identity, which is the reason that mode is
not for production.

---

## What Clearance does *not* defend against

Stated plainly. Anything below is outside the boundary, and treating it as
covered is the mistake this section exists to prevent.

1. **What happens inside an approved connection.** Allowing `example.com`
   allows everything that host serves and everything sent to it. Clearance
   gates destinations, not content — it will not notice a secret in a POST body
   to a permitted host.

2. **HTTPS payloads and paths.** A CONNECT tunnel is opaque: hostname only. A
   path-scoped rule cannot be enforced over TLS. See the architecture doc.

3. **Exfiltration through an approved destination.** If an agent may reach
   GitHub, it may push data to GitHub. Approving a destination is trusting it.

4. **A compromised agent's local behaviour.** Reading files, running commands,
   corrupting its own workspace — Clearance sees none of it. It is an egress
   control, not a sandbox. The container is the sandbox.

5. **Prompt injection.** Clearance does not inspect model input or output. It
   reduces the *consequences* — an injected instruction still cannot reach an
   unapproved host — but it does not detect the injection.

6. **A malicious operator.** Anyone who can approve can approve wrongly. Audit
   records it; nothing prevents it.

7. **Host or Docker compromise.** All isolation here rests on the container
   boundary and Docker networking. Escape either and the model does not hold.

8. **Denial of service.** Rate limits target credential guessing and privileged
   mutations, not traffic volume. Clearance is not a DoS control.

9. **Supply chain.** A malicious dependency in the agent image, or in
   Clearance, is out of scope.

---

## Deployment assumptions

The model above holds only if these are true. They are worth checking, because
each has a failure mode that looks fine until it isn't.

- **Agents cannot reach the internet except through their gateway.** Verify it;
  do not assume `HTTP_PROXY` is obeyed.
- **`GATEWAY_AGENT_AUTH_MODE=token`.** In `static` mode identity comes from
  configuration and the override headers may be honoured — fine for local
  development, not a boundary.
- **`CLEARANCE_AUTH_MODE=oidc` in production.** A shared static token cannot
  attribute an action to a person, which makes the audit trail far less useful
  than it looks.
- **TLS in front of the control plane.** Admin tokens, OIDC bearer tokens, and
  freshly minted agent credentials all cross it.
- **Postgres is not reachable by agents.** It holds every credential hash and
  the whole audit trail.

The default `docker-compose.yml` deliberately violates several of these for
local convenience — identity override is on, auth is `static`, everything is
plaintext. It is a development stack, not a security boundary, and the
evaluation report says so where it reports which configuration it measured.

---

## Reporting

Found something? Open an issue with reproduction steps. If it demonstrates a
bypass the evaluation suite does not cover, a failing case added to
`scripts/security/run-evaluation.sh` is the most useful possible bug report —
it turns a claim into a measurement.

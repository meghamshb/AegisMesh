# Egress bypass evaluation

<!--
  GENERATED FILE - do not edit by hand.
  Regenerate with: ./scripts/security/run-evaluation.sh
  Every number below is computed from measured test results.
-->

- **Generated:** 2026-08-21 19:07 UTC
- **Commit:** `9e8832a`
- **Gateway version:** `dev`
- **Harness:** `scripts/security/run-evaluation.sh`

## Measured result

> **39/39 evaluated egress bypass cases were blocked or mediated in the tested Docker Compose configuration.**

Across 42 total cases (39 bypass attempts plus 3 positive controls), 42 matched their expected outcome and 0 did not.

### What this does *not* claim

This is not a claim that Clearance prevents all network bypasses. It is a record of what a specific set of attempts did against a specific configuration on a specific commit. Cases outside this list are untested, and the known gaps below are unaddressed.

## Configuration under test

The evaluation runs against `docker-compose.fleet.yml`, not the default single-node stack, because that is the production-like posture:

| Setting | Value under test | Why it matters |
|---|---|---|
| `GATEWAY_AGENT_AUTH_MODE` | `token` | Identity comes from a credential, so the identity cases are meaningful |
| `GATEWAY_ALLOW_IDENTITY_OVERRIDE` | unset (off) | Spoof headers are ignored |
| Control plane | separate process | SSRF-11 tests a real cross-process boundary |
| Agent network | `internal: true` | No direct egress; proxy is the only path out |

**The default `docker-compose.yml` is deliberately more permissive**: it sets `GATEWAY_ALLOW_IDENTITY_OVERRIDE=true` and leaves auth in `static` mode for local development convenience. Cases ID-01 through ID-06 would not hold there, and that configuration should not be treated as a security boundary.

## Outcome vocabulary

| Outcome | Meaning |
|---|---|
| `blocked` | Hard-denied. No approval could permit it; it never reaches the queue. |
| `mediated` | Reached policy evaluation and was gated. A human could approve it. |
| `allowed` | Traffic reached the destination. Correct only where policy permits it. |
| `unreachable` | The network refused before any Clearance code ran (Docker lockdown). |
| `fail-closed` | A component refused to serve rather than serve unsafely. |

`blocked` versus `mediated` is the distinction the suite exists to test. Both surface as HTTP 403; only the response body separates a hard SSRF denial from a request parked in the approval queue. A target that is merely *mediated* when it should be *blocked* would mean an operator could approve their way to it.

## Results

### Egress path and proxy evasion

| ID | Attempt | Expected | Actual | Result | Notes |
|---|---|---|---|---|---|
| EGR-01 | curl HTTP via proxy | `mediated` | `mediated` | PASS | real agent container |
| EGR-02 | curl HTTPS (CONNECT) via proxy | `mediated` | `mediated` | PASS | CONNECT tunnel gated on host |
| EGR-03 | Python requests via proxy | `mediated` | `mediated` | PASS | third-party HTTP client |
| EGR-04 | Python urllib via proxy | `mediated` | `mediated` | PASS | stdlib HTTP client |
| EGR-05 | Node http via proxy | `mediated` | `mediated` | PASS | node stdlib client |
| EGR-06 | wget via proxy | `mediated` | `mediated` | PASS | busybox wget; not present in the Hermes image |
| EGR-07 | Raw socket to public host, no proxy | `unreachable` | `unreachable` | PASS | Docker network lockdown, not the proxy |
| EGR-08 | Direct HTTP with proxy env unset | `unreachable` | `unreachable` | PASS | agent net is internal:true |
| EGR-09 | Lowercase proxy env variant | `mediated` | `mediated` | PASS | casing does not change enforcement |
| EGR-10 | NO_PROXY=* to escape the proxy | `unreachable` | `unreachable` | PASS | NO_PROXY only removes the proxy; egress is still blocked |
| EGR-11 | Gateway follows a redirect to a private target | `blocked` | `blocked` | PASS | verified by internal/proxy/redirect_test.go, not a live probe |
| EGR-12 | Redirect target escapes the SSRF guard on the second hop | `blocked` | `blocked` | PASS | verified by internal/proxy/redirect_test.go, not a live probe |

### Server-side request forgery targets

| ID | Attempt | Expected | Actual | Result | Notes |
|---|---|---|---|---|---|
| SSRF-01 | Proxy to localhost | `blocked` | `blocked` | PASS |  |
| SSRF-02 | Proxy to 127.0.0.1 | `blocked` | `blocked` | PASS |  |
| SSRF-03 | Proxy to RFC1918 10.0.0.0/8 | `blocked` | `blocked` | PASS |  |
| SSRF-04 | Proxy to RFC1918 172.16/12 | `blocked` | `blocked` | PASS |  |
| SSRF-05 | Proxy to RFC1918 192.168/16 | `blocked` | `blocked` | PASS |  |
| SSRF-06 | Proxy to link-local metadata | `blocked` | `blocked` | PASS | cloud credential theft target |
| SSRF-07 | Proxy to IPv6 loopback | `blocked` | `blocked` | PASS |  |
| SSRF-08 | Proxy to IPv6 link-local | `blocked` | `blocked` | PASS |  |
| SSRF-09 | Proxy to IPv6 ULA | `blocked` | `blocked` | PASS |  |
| SSRF-10 | Proxy to postgres by name | `blocked` | `blocked` | PASS | database service |
| SSRF-11 | Proxy to control plane by name | `blocked` | `blocked` | PASS | Phase 5.11.7 |
| SSRF-12 | Proxy to peer gateway | `blocked` | `blocked` | PASS |  |
| SSRF-13 | DNS name resolving to private IP | `blocked` | `blocked` | PASS | localtest.me resolves to 127.0.0.1 |
| SSRF-14 | Hard-denied targets never enter the approval queue | `blocked` | `blocked` | PASS | nobody can approve their way to the metadata service |

### Agent identity and credentials

| ID | Attempt | Expected | Actual | Result | Notes |
|---|---|---|---|---|---|
| ID-01 | No agent credential | `blocked` | `blocked` | PASS | token auth mode requires a credential |
| ID-02 | Invalid agent credential | `blocked` | `blocked` | PASS |  |
| ID-03 | Revoked agent credential | `blocked` | `blocked` | PASS | revocation takes effect without restart |
| ID-04 | Identity spoof via X-Gateway-Agent-Id header | `mediated` | `mediated` | PASS | header ignored in token mode; see ID-05 |
| ID-05 | Spoof header did not change recorded identity | `blocked` | `blocked` | PASS | attribution follows the credential, not the header |
| ID-06 | Cross-org agent credential at this gateway | `blocked` | `blocked` | PASS | gateway org must equal agent org (Phase 5.11.6) |

### Fleet resilience

| ID | Attempt | Expected | Actual | Result | Notes |
|---|---|---|---|---|---|
| FLEET-01 | Approved host allowed while control plane is healthy | `allowed` | `allowed` | PASS | baseline for FLEET-02 |
| FLEET-02 | Control plane down (cache warm): approved host still allowed | `allowed` | `allowed` | PASS | last-known-good policy; outage is not an outage of enforcement |
| FLEET-03 | Control plane down (cache warm): unapproved host still gated | `mediated` | `mediated` | PASS | outage does not become an allow-all |
| FLEET-05 | Control plane down (cache expired): approved host now refused | `fail-closed` | `fail-closed` | PASS | cannot verify identity, so egress stops - see Known gaps |
| FLEET-06 | Control plane down (cache expired): unapproved host refused | `fail-closed` | `fail-closed` | PASS | degrades closed, never open |
| FLEET-04 | Cold start with no reachable control plane | `fail-closed` | `fail-closed` | PASS | process exits rather than proxying against unknown policy |

### Control-plane API surface

| ID | Attempt | Expected | Actual | Result | Notes |
|---|---|---|---|---|---|
| API-01 | Internal API with no credential | `blocked` | `blocked` | PASS | a private network is not authentication |
| API-02 | Internal API with admin token instead of gateway credential | `blocked` | `blocked` | PASS | separate trust domains |
| API-03 | Admin API with no token | `blocked` | `blocked` | PASS |  |
| API-04 | Gateway credential valid for its own org snapshot | `allowed` | `allowed` | PASS | positive control: the guard is not a blanket denial |

## Known gaps

Stated explicitly so the table above is not mistaken for full coverage.

- **DNS rebinding.** The SSRF guard resolves a hostname to check it, then the transport resolves again when dialling. A name that returns a public address on the first lookup and a private one on the second would pass the check. Closing this needs the guard to pin the resolved address and dial that address directly.
- **CONNECT tunnels are host-level only.** Once a tunnel is established, Clearance sees bytes, not requests: it cannot evaluate paths, inspect redirects, or notice that a permitted host is being used as a relay. This is why remembering a CONNECT rule is refused outright.
- **A permitted host is trusted for everything it serves.** Allowing `example.com` allows whatever that host returns, including content that instructs the agent to do something else.
- **The evaluation covers Docker Compose only.** Bare-metal or Kubernetes deployments have different network lockdown properties, and the EGR-07 through EGR-10 results do not transfer to them.
- **Long control-plane outages stop traffic entirely.** FLEET-02/03 show a gateway continuing to enforce cached policy during a brief outage; FLEET-05/06 show that once the agent-identity cache expires (`CLEARANCE_AGENT_IDENTITY_CACHE_TTL`) it can no longer verify callers and refuses everything. That is the intended direction to fail, but it is an availability cost, not a free property: a long control-plane outage is an egress outage.
- **What this suite cannot observe.** Blocking the control plane *by name* only changes behaviour when the control plane is publicly addressable. In this Compose topology it resolves to a private address, so the IP-range check would catch it anyway - removing the name check does not fail any case here. That protection is covered by `TestSSRFBlocksConfiguredControlPlaneByName` instead, which uses a public hostname. Verified by deliberately regressing each check and confirming which cases move.

## Reproducing

```bash
./scripts/security/run-evaluation.sh
```

The script builds the fleet stack, seeds two organizations, runs every case, regenerates this document, and exits non-zero if any case fails. It needs Docker and outbound network access; it does not need any paid or external API.


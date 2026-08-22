# Runbook: multi-gateway fleet demo

The claim this demo exists to prove:

> **One policy change, made once, controls two physically separate gateway
> containers — without restarting either of them.**

**Time:** ~5 minutes automated, ~15 manual. **Requires:** Docker, outbound
network access.

---

## The fast path

```bash
make smoke-fleet
```

Stands up the fleet, runs all twelve steps, prints a pass/fail line per step,
and tears down. Exits non-zero if anything fails.

The rest of this document is the same thing by hand, for when you want to watch
it happen.

---

## Topology

```
              control-plane (:8080)
                      │
                  Postgres
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
   gateway-a (:8081)          gateway-b (:8081)
        │                           │
    hermes-a                    hermes-b
     (Alice)                      (Bob)
```

Each agent sits alone with its gateway on an `internal: true` network. Neither
can reach the internet, Postgres, or the other agent's network. Only the
gateways have egress.

**The gateways do not read policy from Postgres.** They fetch a versioned
snapshot from the control plane. That is what makes this demo mean something —
if they shared a database, a new rule would appear instantly for both and prove
nothing about distribution.

---

## 1. Start the control plane

Gateways cannot start before they have a credential, so the control plane comes
up first.

```bash
COMPOSE="docker compose -p fleet -f docker-compose.fleet.yml"
$COMPOSE up -d --build postgres control-plane

CTRL=http://control-plane:8080
NET=fleet_control-net
api() { docker run --rm --network $NET curlimages/curl:8.10.1 \
          -sS -H "X-Admin-Token: dev-local-admin-token" "$@"; }

api "$CTRL/health"
```

> Everything talks over the compose network rather than a published port —
> that is how the components find each other anyway, and it avoids
> host port-publishing quirks.

## 2. Seed users, agents, gateways

```bash
ALICE=$(api -X POST "$CTRL/api/v1/users" -H 'Content-Type: application/json' \
  -d '{"display_name":"Alice","role":"member"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')

api -X POST "$CTRL/api/v1/agents" -H 'Content-Type: application/json' \
  -d "{\"owner_user_id\":\"$ALICE\",\"name\":\"agent-a\"}"
# ... repeat for Bob / agent-b

api -X POST "$CTRL/api/v1/gateways" -H 'Content-Type: application/json' -d '{"name":"gateway-a"}'
api -X POST "$CTRL/api/v1/gateways" -H 'Content-Type: application/json' -d '{"name":"gateway-b"}'
```

Keep all four tokens.

## 3. Start the gateways

```bash
export GATEWAY_A_TOKEN=clr_gateway_...
export GATEWAY_B_TOKEN=clr_gateway_...
$COMPOSE up -d --build gateway-a gateway-b hermes-a hermes-b

$COMPOSE logs gateway-a | grep "policy snapshot loaded"
```

If that line never appears, the gateway refused to start — by design. A gateway
that cannot load policy must not proxy traffic.

Open **Gateways** in the console: both appear, `ONLINE`, with their policy
version and agents-recently-seen.

---

## 4. Both agents request the same URL → both blocked

```bash
probe() {  # probe <net> <gateway> <token>
  docker run --rm --network "fleet_$1" curlimages/curl:8.10.1 \
    -s -o /dev/null -w '%{http_code}\n' --max-time 15 \
    -x "http://$2:8081" -H "Proxy-Authorization: Bearer $3" \
    http://example.com/fleet-test
}

probe gateway-a-net gateway-a "$AGENT_A_TOKEN"   # 403
probe gateway-b-net gateway-b "$AGENT_B_TOKEN"   # 403
```

Two pending requests in the Inbox, from two different gateways.

## 5. One rule, created once

```bash
RULE=$(api -X POST "$CTRL/api/v1/rules" -H 'Content-Type: application/json' \
  -d '{"scope":"org","scope_ref_id":"11111111-1111-1111-1111-111111111010",
       "effect":"allow","host":"example.com","port":80,"method":"*","path_prefix":"/"}' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
```

Or click **Allow for organization** in the console. Either way: one action.

## 6. Wait for propagation

```bash
sleep 12   # refresh interval is 3s in this compose file
api "$CTRL/api/v1/gateways"
```

`policy_version` on both gateways has advanced. **This wait is the demo.** It
is real propagation — the only path the rule can take to a gateway is the
snapshot fetch.

## 7. Both agents retry → both allowed

```bash
probe gateway-a-net gateway-a "$AGENT_A_TOKEN"   # 404 from example.com
probe gateway-b-net gateway-b "$AGENT_B_TOKEN"   # 404 from example.com
```

`404` is success: the request reached `example.com`, which has no `/fleet-test`.
A `403` would mean Clearance blocked it.

**No container was restarted.**

## 8. Revoke centrally

```bash
api -X DELETE "$CTRL/api/v1/rules/$RULE"
sleep 12
probe gateway-a-net gateway-a "$AGENT_A_TOKEN"   # 403 again
probe gateway-b-net gateway-b "$AGENT_B_TOKEN"   # 403 again
```

Withdrawal propagates the same way.

---

## Worth also demonstrating

**Central audit.** Every decision from both gateways is in one place:

```bash
api "$CTRL/api/v1/audit?limit=50"
```

**Bypass prevention still holds:**

```bash
docker run --rm --network fleet_gateway-a-net curlimages/curl:8.10.1 \
  -fsS --max-time 5 http://example.com/   # fails: no route
```

**An agent cannot reach the control plane through its own gateway**, even
though the gateway talks to it constantly:

```bash
docker run --rm --network fleet_gateway-a-net curlimages/curl:8.10.1 \
  -s -o /dev/null -w '%{http_code}\n' \
  -x http://gateway-a:8081 -H "Proxy-Authorization: Bearer $AGENT_A_TOKEN" \
  http://control-plane:8080/api/v1/users   # 403, hard-denied
```

**Degrade closed.** Stop the control plane and retry: approved traffic keeps
working from the cached snapshot (availability of the control plane is not a
precondition for enforcement). Wait past the identity-cache TTL and everything
is refused — the intended direction to fail, and a real availability cost.

```bash
$COMPOSE stop control-plane
```

---

## Teardown

```bash
docker compose -p fleet -f docker-compose.fleet.yml down -v
```

## Troubleshooting

| Symptom | Cause |
|---|---|
| Gateway exits at startup | Bad `CLEARANCE_GATEWAY_TOKEN`, or control plane unreachable. This is fail-closed working. |
| Still `403` after step 6 | Not enough propagation time, or the rule's host/port/path does not match. Check `policy_version` advanced. |
| `407` instead of `403` | Agent credential wrong or revoked. |
| Gateway `OFFLINE` in the console | Heartbeats not arriving. Reporting only — it may still be enforcing correctly. |

## Related

- [Architecture](../architecture/control-plane.md) — snapshots, precedence, failure behaviour
- [Multi-user demo](phase5-multi-user-demo.md)

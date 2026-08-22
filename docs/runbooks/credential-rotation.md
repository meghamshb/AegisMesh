# Runbook: rotate or revoke an agent credential

Two different operations, often confused:

| | Rotate | Revoke |
|---|---|---|
| Old credential | Stops working immediately | Stops working immediately |
| New credential | Issued | **Not** issued |
| Agent | Keeps working, once updated | Permanently disabled |
| Use when | Suspected leak, scheduled hygiene | Decommissioned, compromised host, offboarding |

Both take effect **immediately** — there is no cache that keeps a dead
credential alive. (In a fleet, a gateway may hold an identity cache for up to
`CLEARANCE_AGENT_IDENTITY_CACHE_TTL`, 10s by default; failures are never
cached, so revocation is not delayed by it.)

---

## Rotate

**Expect downtime for that agent** between rotation and updating its
configuration. The old credential dies the moment the new one is issued.

```bash
export ADMIN_TOKEN=dev-local-admin-token
export CLEARANCE_URL=http://localhost:8080

curl -sS -X POST "$CLEARANCE_URL/api/v1/agents/<AGENT_ID>/credentials/rotate" \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

```json
{
  "agent_id": "...",
  "credential": { "token": "clr_agent_NEW...", "token_prefix": "clr_agent_NEWX" }
}
```

Then:

1. Update the agent's `Proxy-Authorization`.
2. Restart or reload it.
3. Verify: a proxied request should return `403` (queued) rather than `407`
   (rejected).

In the console: **Agents → Rotate credential**. The new token is shown once, in
a modal, and cannot be retrieved afterwards.

### Suspected leak

Order matters:

1. **Rotate first.** This kills the leaked credential immediately.
2. Then check the audit trail for what it did:

```bash
curl -sS "$CLEARANCE_URL/api/v1/requests?agent_id=<AGENT_ID>&limit=200" \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

3. Review any rules created by remembering an approval from that agent —
   revoking the credential does **not** revoke rules it caused:

```bash
curl -sS "$CLEARANCE_URL/api/v1/rules?scope=agent&scope_ref_id=<AGENT_ID>" \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

That third step is the one people miss. A leaked credential whose traffic was
approved-and-remembered leaves a standing allow rule behind, and rotating the
credential does nothing about it.

---

## Revoke

```bash
curl -sS -X POST "$CLEARANCE_URL/api/v1/agents/<AGENT_ID>/revoke" \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

Revokes the agent **and all of its active credentials** in one transaction.
The response shows `"status": "revoked"`.

This is not reversible through the API. To bring the workload back, register a
new agent.

Its history is preserved deliberately — egress requests and audit events
remain, so the record of what it did survives the revocation.

---

## Rotating a gateway credential

Gateway credentials are a separate trust domain and have **no rotate
endpoint**. Register a replacement gateway and retire the old one:

```bash
curl -sS -X POST "$CLEARANCE_URL/api/v1/gateways" \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"gateway-a-replacement"}'
```

Restart the gateway process with the new `CLEARANCE_GATEWAY_TOKEN`. It will
fail closed at startup if the credential is not accepted, which is the intended
signal that something is wrong — it will not start and serve unfiltered
traffic.

---

## Who may do this

| Role | Rotate / revoke |
|---|---|
| `admin` | Any agent in the org |
| `approver` | Any agent in the org |
| `member` | Their own agents only |

A `member` attempting someone else's agent gets `403`. An agent id from another
organization gets `404` — never `403`, since a distinct error would confirm the
agent exists.

---

## Verification

After either operation, confirm the old credential is dead:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -x http://gateway-a:8081 \
  -H "Proxy-Authorization: Bearer $OLD_TOKEN" \
  http://example.com/
```

`407` is what you want. `403` means it still authenticated — check you rotated
the agent you meant to.

---

## Related

- [Agent registration](agent-registration.md)
- [Threat model](../security/threat-model.md) — stolen-credential blast radius

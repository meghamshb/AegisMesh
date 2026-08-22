# Runbook: register an agent

Give a Hermes container an identity so its traffic is attributable and
policy applies to it.

**Time:** 2 minutes. **Requires:** a running stack and admin access.

---

## Before you start

An agent belongs to a **user**, who belongs to an **organization**. Create the
user first if they do not exist — Clearance will not auto-create one, because
that would mean deciding someone's role on their behalf.

```bash
export ADMIN_TOKEN=dev-local-admin-token
export CLEARANCE_URL=http://localhost:8080
```

In `oidc` mode use `-H "Authorization: Bearer $YOUR_OIDC_TOKEN"` instead of
`X-Admin-Token`.

---

## 1. Create the owner (skip if they exist)

```bash
curl -sS -X POST "$CLEARANCE_URL/api/v1/users" \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"display_name":"Alice","email":"alice@example.com","role":"member"}'
```

Roles: `member` (own agents only), `approver` (may approve egress and manage
others' agents), `admin` (everything, including user management).

Note the returned `id`.

---

## 2. Register the agent

```bash
curl -sS -X POST "$CLEARANCE_URL/api/v1/agents" \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"owner_user_id":"<USER_ID>","name":"alice-macbook-hermes"}'
```

Response:

```json
{
  "agent": { "id": "...", "org_id": "...", "status": "active" },
  "credential": {
    "token": "clr_agent_XXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "token_prefix": "clr_agent_XXXX"
  }
}
```

> **The `token` is shown once and never again.** Only its SHA-256 hash is
> stored, so it cannot be recovered — if you lose it, rotate rather than
> hunting for it. The `token_prefix` is a display aid for identifying the
> credential later; it is not enough to authenticate with.

There is also a helper that does both steps:

```bash
make register-agent OWNER_USER_ID=<USER_ID> AGENT_NAME=alice-macbook-hermes
```

---

## 3. Give the credential to the agent

The container needs the proxy and the credential:

```yaml
environment:
  HTTP_PROXY: http://gateway-a:8081
  HTTPS_PROXY: http://gateway-a:8081
  NO_PROXY: localhost,127.0.0.1,gateway-a
```

The credential travels in `Proxy-Authorization: Bearer clr_agent_...`.

> Do **not** embed the credential in the proxy URL
> (`http://token@gateway:8081`). Anything that can read the process
> environment or a command line can read it there.

Verify:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -x http://gateway-a:8081 \
  -H "Proxy-Authorization: Bearer $AGENT_TOKEN" \
  http://example.com/
```

`403` is success — the agent authenticated, and the request is queued for
approval. `407` means the credential was not accepted.

---

## 4. Confirm it appears

```bash
curl -sS "$CLEARANCE_URL/api/v1/agents" -H "X-Admin-Token: $ADMIN_TOKEN"
```

Or open the **Agents** tab in the console.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `407` with "valid agent credential required" | Wrong, malformed, or revoked credential. |
| `403` "agent revoked" | The agent was revoked. Register a new one — revocation is not reversible through the API. |
| `400` "owner_user_id does not reference a known user" | The user does not exist, or belongs to a different organization. |
| `403` "not authorized to register an agent for this owner" | You are a `member` creating an agent for someone else. Needs `approver` or `admin`. |
| Requests succeed without any credential | The gateway is in `static` auth mode. Set `GATEWAY_AGENT_AUTH_MODE=token`. |

---

## Related

- [Credential rotation](credential-rotation.md)
- [Multi-user demo](phase5-multi-user-demo.md)

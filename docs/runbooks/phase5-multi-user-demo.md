# Runbook: multi-user demo

Two people, two agents, one organization — showing that identity is real,
scoped rules behave differently per scope, and attribution survives.

**Time:** ~10 minutes. **Requires:** Docker.

---

## Setup

```bash
docker compose up -d --build
export ADMIN_TOKEN=dev-local-admin-token
export CLEARANCE_URL=http://localhost:8080
api() { curl -sS -H "X-Admin-Token: $ADMIN_TOKEN" "$@"; }
```

Open the console at <http://localhost:8080/ui> and enter the admin token under
**Session / credentials**. You will see a `DEV-TOKEN MODE` badge — that is
correct here, and the reason this stack is not a security boundary.

---

## 1. Create Alice and Bob

```bash
api -X POST "$CLEARANCE_URL/api/v1/users" -H 'Content-Type: application/json' \
  -d '{"display_name":"Alice","email":"alice@example.com","role":"member"}'

api -X POST "$CLEARANCE_URL/api/v1/users" -H 'Content-Type: application/json' \
  -d '{"display_name":"Bob","email":"bob@example.com","role":"member"}'
```

Note both ids. **Users** tab shows them.

## 2. Give each an agent

```bash
api -X POST "$CLEARANCE_URL/api/v1/agents" -H 'Content-Type: application/json' \
  -d '{"owner_user_id":"<ALICE_ID>","name":"alice-hermes"}'

api -X POST "$CLEARANCE_URL/api/v1/agents" -H 'Content-Type: application/json' \
  -d '{"owner_user_id":"<BOB_ID>","name":"bob-hermes"}'
```

Save both `credential.token` values — shown once each.

**Agents** tab now lists both, each with its owner.

---

## 3. Alice makes a request → blocked

```bash
docker compose exec -T hermes sh -c \
  "curl -s -o /dev/null -w '%{http_code}\n' --max-time 10 \
     -x http://policy-gateway:8080 \
     -H 'Proxy-Authorization: Bearer $ALICE_TOKEN' \
     http://example.com/reports"
```

`403`. Nothing was configured to allow it, and the default is deny.

**Inbox** shows one pending request, attributed to **Alice**. That attribution
comes from the credential, not from anything the client claimed.

---

## 4. Approve once — and watch the scope

Approve it in the console with **Approve once**, then have Alice retry: it
succeeds. Retry a *second* time and it is blocked again — a one-time grant is
consumed on use.

Now have Bob request the same URL. Still blocked: Alice's approval was for
Alice.

---

## 5. Scoped rules

The interesting part. Approve Alice's request again, this time with **Allow for
this user**. Then:

- Alice retries → allowed.
- **Bob retries → still blocked.** A user-scoped rule follows the user.

Now create an org-scoped rule:

```bash
api -X POST "$CLEARANCE_URL/api/v1/rules" -H 'Content-Type: application/json' \
  -d '{"scope":"org","scope_ref_id":"11111111-1111-1111-1111-111111111010",
       "effect":"allow","host":"example.com","port":80,"method":"*","path_prefix":"/"}'
```

Both Alice and Bob now succeed. **Rules** tab shows scope and who created it.

## 6. Deny beats allow

```bash
api -X POST "$CLEARANCE_URL/api/v1/rules" -H 'Content-Type: application/json' \
  -d '{"scope":"agent","scope_ref_id":"<ALICE_AGENT_ID>",
       "effect":"deny","host":"example.com","port":80,"method":"*","path_prefix":"/"}'
```

Alice is blocked again; Bob still works. A deny wins over a matching allow at
*any* scope — a narrower rule must not be able to re-permit what was explicitly
forbidden.

---

## 7. Disable a user

```bash
api -X PATCH "$CLEARANCE_URL/api/v1/users/<BOB_ID>" \
  -H 'Content-Type: application/json' -d '{"status":"disabled"}'
```

Bob's agent stops authenticating immediately — `407`, not `403`. Disabling a
person disables their agents, without touching any rule.

Re-enable with `{"status":"active"}`.

---

## 8. The audit trail

```bash
api "$CLEARANCE_URL/api/v1/audit?limit=50"
```

Every decision is recorded: who requested, what was decided, by whom, and which
rule applied.

Note what is *absent*: no request bodies, no headers, and no query strings —
`?token=...` never reaches storage.

> In `dev-token` mode every approval is attributed to the same shared
> administrator, which is exactly what makes it unsuitable for production. With
> `CLEARANCE_AUTH_MODE=oidc`, approvals carry the real person.

---

## Teardown

```bash
docker compose down -v
```

## Next

- [Fleet demo](phase5-fleet-demo.md) — the same policy controlling two separate gateways
- [Agent registration](agent-registration.md)

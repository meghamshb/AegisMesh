# Phase 4.1 — Pilot demo (LLM + gated tool egress)

Run the stack with **Option B model egress** so Hermes can reach LLM APIs directly while tool traffic still goes through the policy gateway.

## Start pilot stack

```bash
cp .env.example .env   # optional: add OPENAI_API_KEY or ANTHROPIC_API_KEY
make up-pilot
```

This merges `docker-compose.pilot.yml`, which:

- Attaches Hermes to `model-egress` (internet for allowlisted model hosts only)
- Applies an **iptables egress firewall** in the Hermes container (`NET_ADMIN`)
- Sets `NO_PROXY` for model API hostnames

Default `make up` / `make smoke` **do not** use the pilot profile — CI lockdown tests stay unchanged.

## Configure a model provider

Inside the Hermes container:

```bash
docker compose -f docker-compose.yml -f docker-compose.pilot.yml exec -it hermes bash
export OPENAI_API_KEY=sk-...   # or set in .env before up-pilot
hermes model openai/gpt-4o-mini
hermes doctor
```

Or use Anthropic / OpenRouter with the matching env var from `.env`.

## UI-driven tool egress demo

1. Open http://localhost:8080/ui — credentials:
   - Admin token: `dev-local-admin-token`
   - Approver: `11111111-1111-1111-1111-111111111002`

2. In another terminal, ask Hermes to fetch a **new** URL (pick one you have not approved yet):

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.pilot.yml exec hermes \
     python /app/scripts/hermes-terminal-fetch.py https://ifconfig.me
   ```

3. In the UI → **Inbox** → pending row → **Approve once**

4. Re-run the fetch command → should succeed with `http_code=200`

## Full agent chat (manual)

```bash
docker compose -f docker-compose.yml -f docker-compose.pilot.yml exec -it hermes hermes
```

Ask something that triggers a web/terminal fetch to an unknown host, then approve in the UI.

## Verify lockdown under pilot profile

Direct curl to a non-allowlisted host should still fail (iptables):

```bash
docker compose -f docker-compose.yml -f docker-compose.pilot.yml exec hermes \
  curl -fsS --max-time 5 https://example.com
```

Tool egress via proxy still creates pending rows as in Phase 4.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `MODEL_EGRESS_ALLOW_HOSTS` | Comma-separated hostnames allowed on :443 (default: OpenAI, Anthropic, OpenRouter, Codex OAuth hosts) |
| `OPENAI_API_KEY` | OpenAI provider |
| `ANTHROPIC_API_KEY` | Anthropic provider |
| `OPENROUTER_API_KEY` | OpenRouter provider |

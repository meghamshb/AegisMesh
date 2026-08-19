# Hermes runtime (Phase 4)

Real [Hermes Agent](https://github.com/NousResearch/hermes-agent) container based on the [LAP Hermes template](https://github.com/LiteLLM-Labs/litellm-agent-control-plane/tree/main/templates/hermes) pattern.

## Behavior

- Waits for `policy-gateway` health before staying up
- Exports `HTTP_PROXY` / `HTTPS_PROXY` toward the gateway (tool egress is policy-gated)
- Mounts `./workspace` read-only at `/work`
- Persists Hermes state under `/data` (Compose volume)

## Tool egress smoke path

Phase 4 smoke uses the **terminal tool** (Hermes-native, not raw container curl):

```bash
docker compose exec hermes python /app/scripts/hermes-terminal-fetch.py https://example.com/
```

That invokes `tools.terminal_tool.terminal_tool`, which spawns `curl` with the container proxy env.

## Interactive use

```bash
docker compose exec -it hermes bash
hermes doctor
```

Model provider setup requires the **pilot profile** (`make up-pilot`) — see [docs/runbooks/phase41-pilot-demo.md](../../docs/runbooks/phase41-pilot-demo.md). Default Compose only allows tool egress through the policy gateway.

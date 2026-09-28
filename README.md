# AegisMesh

> A human checkpoint between an AI agent and the internet.

AegisMesh (called **Clearance** in the app and configuration) is an outbound policy gateway for AI agents. It lets an agent do useful work without giving every tool call unrestricted network access. New destinations are blocked by default; an operator can approve a single request or create a reusable rule, and the decision is recorded for later review.

The current integration runs [Hermes Agent](https://github.com/NousResearch/hermes-agent) in Docker. Model inference uses a separate path; AegisMesh governs the agent's web-facing tool traffic.

## What happens when an agent reaches the web?

1. The agent makes a request through its gateway.
2. AegisMesh checks the destination against policy. An unknown destination is held for review; internal and otherwise unsafe upstreams are denied outright.
3. An operator can deny it, allow it once, or add an organization rule. The agent can then retry.
4. The decision appears in the audit trail.

For a single agent, the control plane and gateway can run together. For a fleet, one control plane distributes versioned policy snapshots to multiple gateways, so a rule or revocation can reach them without restarting the agents.

## Why I built it

Agent tools can fetch URLs, call APIs, and run shell commands. Those actions are easy to miss when the agent is running on someone's machine or inside a larger workflow. AegisMesh makes outbound access visible and gives people a deliberate point of control before a new destination is used.

The interesting part is the separation: centralized policy and audit, but enforcement close to each agent. The repository includes an approval console, agent credentials, organization-scoped rules, a multi-gateway demo, and tests for cross-tenant behavior and egress bypasses.

## See it locally

You need Docker Desktop and Make. The local demo uses development credentials from [`.env.example`](.env.example); don't use those defaults outside a local environment.

```bash
git clone https://github.com/meghamshb/AegisMesh.git
cd AegisMesh
cp .env.example .env
make up
```

Open the approval console at [localhost:8080/ui](http://localhost:8080/ui). The development admin token and approver ID are listed in [`.env.example`](.env.example). `make smoke` exercises the single-gateway flow; `make smoke-fleet` demonstrates one policy change propagating to two independent gateways. The [fleet walkthrough](docs/runbooks/phase5-fleet-demo.md) explains what to look for at each step.

## Design and limits

- The gateway is written in Go, the console in React, and policy/audit data lives in Postgres.
- Docker network isolation and proxy enforcement are part of the tested setup; the protection is not a property of the UI alone.
- This is a **preview**, not a claim of complete network containment. The [security evaluation](docs/security/egress-bypass-evaluation.md) reports the tested bypass cases *and* what the tests could not establish. The [threat model](docs/security/threat-model.md) describes the trust boundaries.
- OIDC and TLS support have deployment caveats. Read the [architecture](docs/architecture/control-plane.md) before using the system beyond a local demo.

More detail: [specification](docs/specs/hermes-policy-gateway.md) · [runbooks](docs/runbooks/) · [environment settings](.env.example)

## License

MIT — see [LICENSE](LICENSE).

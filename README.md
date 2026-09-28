# AegisMesh

Agents are good at finding their way around the internet. Sometimes *too* good.

AegisMesh puts a human checkpoint on an agent's outbound tool traffic. New destinations are blocked by default. An operator can approve a request once, allow it by rule, or deny it — with an audit trail either way.

It started with a simple question: **what if an agent had to ask before calling a new host?** The answer grew into a Go gateway, a React approval console, and a control plane that can send one policy change to multiple gateways. The current integration runs with [Hermes Agent](https://github.com/NousResearch/hermes-agent) in Docker. In the code and UI, the project is also called **Clearance**.

To explore it locally, copy [`.env.example`](.env.example) to `.env` and run `make up`; the console opens at [localhost:8080/ui](http://localhost:8080/ui). `make smoke-fleet` shows one rule reaching two gateways.

This is a security **preview**, not a promise of perfect containment. The [threat model](docs/security/threat-model.md) and [measured bypass evaluation](docs/security/egress-bypass-evaluation.md) explain both the results and the gaps.

[architecture ↗](docs/architecture/control-plane.md) · [fleet walkthrough ↗](docs/runbooks/phase5-fleet-demo.md) · [license ↗](LICENSE)

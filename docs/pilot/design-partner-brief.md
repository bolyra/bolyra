# Bolyra Design-Partner Pilot — One-Pager

**Verified agent actions for your platform: per-call authorization policy, ES256K-signed receipts, tamper-evident audit — target integration in ~2 weeks, validated during a 90-day pilot.**

## What you get

- **A Bolyra enforcement point integrated into your platform.** Gateway proxy in front of your MCP servers (`npx @bolyra/gateway`) or embedded middleware (`createGatewayMiddleware`): per-tool-call policy, credential binding (unknown, forged, or expired claims denied fail-closed — gateway 0.4.0), replay protection, signed receipts. For stdio servers, `@bolyra/shield` adds policy enforcement and receipts (credential binding is gateway/middleware today).
- **Signed action receipts on every decision** — allow *and* deny, ES256K, independently verifiable offline by your customers or their auditors.
- **A sellable capability** — "verified agent actions" as a line item on *your* enterprise tier, backed by evidence, not log files.
- **Direct access to the founding engineer** — integration support, weekly working sessions, and roadmap influence. Design partners shape what ships next and get first access to the Bolyra ZK privacy upgrade (verification without disclosure across operators) as it productionizes.

## Timeline (90 days)

| Phase | Weeks | Outcome |
|---|---|---|
| Integration | 1-2 | Gateway live in one real workflow in your staging environment |
| Pilot workflow | 3-4 | One production (or production-like) agent workflow enforced + receipted end-to-end |
| Harden & expand | 5-12 | Policy tuning, audit export into your review flow, joint eval against your enterprise-buyer requirements, expansion scoping |

## Success criteria (agreed in week 1, measured in week 12)

1. Every tool call in the pilot workflow is policy-checked and receipted (allow and deny).
2. A receipt produced in week N verifies independently in week N+X with the gateway offline.
3. Your team can articulate the capability to an enterprise prospect without us in the room.

## Terms

- **Fixed fee: $25,000** for the 90-day pilot. Half on signature, half at day 45.
- Design-partner pricing credits toward a first-year license if you continue.
- Open-core stays Apache-2.0 — protocol, SDKs, verifier CLI. The pilot covers integration engineering, the enforcement configuration, support, and design-partner access.

## Who we are

Bolyra (ZKProva Inc.) builds the verification layer for agent actions: the open External Verifier Contract v1, `bolyra verify`, and the gateway/shield enforcement points — 12+ open-source packages on npm/PyPI, current releases published with OIDC provenance. Patent-pending ZK delegation and human-uniqueness proofs power the privacy upgrade tier.

**Next step:** 20-minute technical fit call → we propose the integration point → signature → week 1 starts.

Contact: Viswa Kondoju — kondojuviswanadha@gmail.com — bolyra.ai

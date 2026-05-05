# @bolyra/delegation

> Verifiable delegated authority for agent actions. A human signs a scoped receipt; middleware verifies it before the agent calls a tool.

`@bolyra/delegation` is the lightweight on-ramp into the [Bolyra](https://bolyra.ai) protocol. It ships a tiny, dependency-light package (`jose` only) that lets you wire delegation into LangChain, OpenAI Agents SDK, MCP, or any tool framework in a few lines. Full ZKP-backed delegation (via `@bolyra/sdk` + the Circom `Delegation` circuit) remains the upgrade path when you want privacy and on-chain verifiability.

**Status:** v0.1.0 — EdDSA-signed JWS receipts. SD-JWT (selective disclosure) lands in v0.2. ZKP-wrapped receipts land in v0.3.

## Why

Every agent platform is reinventing delegated authority — Stripe Agent Toolkit, Visa Intelligent Commerce, Skyfire, agent wallets, MCP server permissioning — in incompatible ways. `@bolyra/delegation` defines a portable receipt format with the right semantics: scope-narrowing, cumulative permissions matching the Bolyra circuit, capped invocations, expiry, and audit-friendly receipt IDs.

## Install

```bash
npm install @bolyra/delegation
```

## Quickstart

```ts
import { allow, verify, generateKeyPair, PERM } from "@bolyra/delegation";

// Human (or upstream agent) generates a keypair once and persists it.
const { privateKey, publicKey } = await generateKeyPair();

// Human signs a scoped receipt for an agent.
const receipt = await allow(
  {
    agent: "agent_alice",
    action: "purchase",
    audience: "example.com",
    permission: PERM.FINANCIAL_SMALL,
    maxAmount: { amount: 50, currency: "USD" },
    expiresIn: "1h",
  },
  privateKey,
  publicKey,
);

// Agent presents the receipt to the tool / merchant. The verifier checks it.
const result = await verify(receipt, {
  expectedAgent: "agent_alice",
  expectedAction: "purchase",
  expectedAudience: "example.com",
  trustedIssuers: publicKey,
  invocationAmount: { amount: 25, currency: "USD" },
});

if (!result.valid) throw new Error(`delegation rejected: ${result.reason}`);
// proceed with the call
```

## Permission model

The 8-bit cumulative encoding mirrors `circuits/Delegation.circom` so receipts issued here are upgrade-compatible with full ZKP delegation later.

| Bit | Permission | Notes |
|-----|------------|-------|
| 0 | `READ_DATA` | |
| 1 | `WRITE_DATA` | |
| 2 | `FINANCIAL_SMALL` | < $100 |
| 3 | `FINANCIAL_MEDIUM` | < $10K (implies bit 2) |
| 4 | `FINANCIAL_UNLIMITED` | implies bits 2 + 3 |
| 5 | `SIGN_ON_BEHALF` | |
| 6 | `SUB_DELEGATE` | |
| 7 | `ACCESS_PII` | |

`validateCumulativeBitEncoding(perm)` enforces the implication rules. `narrows(wider, narrower)` confirms one-way scope narrowing for sub-delegation.

## Adapters

Working examples live in `bolyra/integrations/`:

- `integrations/openai-agents/delegation-example.ts` — gates an OpenAI Agents SDK tool
- `integrations/langchain/typescript/delegation-example.ts` — gates a LangChain JS tool
- `integrations/mcp/examples/delegation-example.ts` — gates an MCP server tool call

## Verify failure reasons

| Reason | Meaning |
|--------|---------|
| `invalid_signature` | Receipt was not signed by any trusted issuer key |
| `expired` | Past `exp` |
| `not_yet_valid` | Future-dated `iat` beyond clock tolerance |
| `audience_mismatch` | `aud` does not match `expectedAudience` |
| `agent_mismatch` | `sub` does not match `expectedAgent` |
| `action_mismatch` | `act` does not match `expectedAction` |
| `permission_violation` | Bits violate cumulative encoding or required permission |
| `amount_exceeds_cap` | Caller's `invocationAmount.amount` > `claims.max.amount` |
| `currency_mismatch` | Caller's currency differs from `claims.max.currency` |
| `malformed` | Receipt is not a valid JWS / claims missing |

## Roadmap

- **v0.1** (now): EdDSA-signed JWS receipts. Single trusted-issuer verification.
- **v0.2:** SD-JWT (selective disclosure). Status-list-backed revocation.
- **v0.3:** ZKP-wrapped receipts (via `@bolyra/sdk` + Circom `Delegation` circuit). Privacy-preserving issuer + agent identity.

## License

Apache-2.0. Patent grant per Apache 2.0 §3 (US provisional 64/043,898 filed 2026-04-20). DCO sign-off required for contributions (see `CONTRIBUTING.md` in repo root).

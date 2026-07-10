# Bolyra

Verified agent actions: authorization policy, signed receipts, and tamper-evident audit for AI agent tool calls.

- **Domain:** [bolyra.ai](https://bolyra.ai)
- **Company:** ZKProva Inc.
- **License:** Apache-2.0 (with DCO sign-off — every commit requires `Signed-off-by:`)

## What this is

When an AI agent calls a tool, Bolyra proves who — and what — authorized the action. Put the gateway in front of any MCP server (or embed the verifier in your agent platform) and every tool call gets four checks: credential verification, per-tool policy, replay protection, and a signed audit receipt.

Bolyra ships in two tiers on the same verifier contract:

- **Bolyra Core** — classical crypto, no circuits, no trusted setup: per-tool policy, nonce replay protection, ES256K-signed action receipts, and JWT-based delegation claims ([`@bolyra/delegation`](delegation/)). This is the gateway's `--dev` mode today; packaged `--dev` enforces policy, replay protection, and signed receipts, but credential permission claims are self-asserted and not cryptographically bound.
- **Bolyra ZK** — the privacy upgrade: humans prove uniqueness via a Semaphore v4-style enrollment circuit; AI agents prove EdDSA-signed credentials with cumulative-bit permissions; a delegation circuit narrows scope one-way (permissions can only drop, never widen), with the delegation path hidden from the verifier. A handshake binds the human and agent Groth16 proofs to a shared session nonce, verified atomically on-chain.

Core gets you policy-gated, replay-protected, receipted actions. ZK gets you cryptographically bound verified actions **without disclosure** — the verifier learns that the predicate holds, not your credentials, policies, or delegation graph. You don't need ZK to gate your first MCP server with one command.

**Building an agent platform?** Bolyra plugs in as an external verifier and gives you an enterprise security capability — verified agent actions — without rebuilding auth. See [bolyra.ai](https://bolyra.ai/#platforms).

## Repository layout

```
circuits/        Circom 2 circuits + snarkjs/rapidsnark proving
contracts/       Hardhat — Solidity verifiers + on-chain registry
sdk/             @bolyra/sdk (TypeScript, public API)
sdk-python/      bolyra (Python — pure types + subprocess bridge)
integrations/    langchain, crewai, mcp, openclaw, payment-protocols
spec/            DID method, IETF-style draft, conformance runner
examples/        mcp-demo, provider-mock
docs/            quickstart, OWASP agentic mapping
```

## Quickstart

See [`sdk/QUICKSTART.md`](sdk/QUICKSTART.md) for the TypeScript SDK quickstart.

## Build & test

```sh
npm install
npm run compile:circuits
npm run compile:contracts
npm test                              # circuits fast + contracts
FULL_PROOF=1 npm run test:circuits:slow  # full Groth16/PLONK proving (~2 min)
```

## Protocol Conformance

48 executable test vectors verify the implementation matches the protocol specification.
CI runs them on every PR. See [`spec/CONFORMANCE.md`](spec/CONFORMANCE.md) for the
current generated report.

```bash
npm run conformance          # run vectors
npm run conformance:report   # generate spec/CONFORMANCE.md
```

## Contributing

This project requires a Developer Certificate of Origin (DCO) sign-off on every commit. Use `git commit -s`. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

## License

Apache-2.0. See [`LICENSE`](LICENSE).

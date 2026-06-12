# Bolyra

Unified zero-knowledge proof identity protocol for humans and AI agents.

- **Domain:** [bolyra.ai](https://bolyra.ai)
- **Company:** ZKProva Inc.
- **License:** Apache-2.0 (with DCO sign-off — every commit requires `Signed-off-by:`)

## What this is

Bolyra is a mutual zero-knowledge proof authentication protocol. Humans prove uniqueness via a Semaphore v4-style enrollment circuit; AI agents prove EdDSA-signed credentials with cumulative-bit permissions; a delegation circuit narrows scope one-way. A handshake binds a Groth16 (human) and Groth16 (agent) proof to a shared session nonce, verified atomically on-chain.

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

## Contributing

This project requires a Developer Certificate of Origin (DCO) sign-off on every commit. Use `git commit -s`. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

## License

Apache-2.0. See [`LICENSE`](LICENSE).

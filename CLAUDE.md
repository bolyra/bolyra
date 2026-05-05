# CLAUDE.md

This file provides guidance to Claude Code when working in this repository.

## Project

**Bolyra** — unified ZKP identity protocol for humans and AI agents. Phase 1 (Proof of Enrollment) is the current scope: humans prove uniqueness via Semaphore v4-style enrollment, agents prove EdDSA-signed credentials with cumulative-bit permissions, and a delegation circuit narrows scope one-way.

- **Domain:** bolyra.ai
- **Company:** ZKProva Inc.
- **Repo:** `github.com/bolyra/bolyra` (local dir: `~/Projects/bolyra/`; legacy name `identityos/` retained only inside historical patent artifacts: `drafts/IDENTITYOS-PROV-001-*`)
- **License:** Apache 2.0 (with DCO sign-off — every commit requires `Signed-off-by:`)
- **Patent:** Provisional #64/043,898 filed 2026-04-20. Non-provisional deadline **2027-04-20**.

## Commands

From repo root (`package.json` orchestrates the two test suites):

- **Test all:** `npm test` (circuits fast + contracts)
- **Test circuits (mock proofs):** `npm run test:circuits:fast`
- **Test circuits (real proofs):** `npm run test:circuits:slow` — sets `FULL_PROOF=1`, ~2min
- **Test contracts:** `npm run test:contracts` (Hardhat)
- **Compile circuits:** `npm run compile:circuits` → writes `circuits/build/`
- **Compile contracts:** `npm run compile:contracts`
- **Deploy contracts (local):** `cd contracts && npm run deploy:local`
- **Deploy contracts (Base Sepolia):** `cd contracts && npm run deploy:base-sepolia`
- **TS SDK build/typecheck:** `cd sdk && npm run build` / `npm run typecheck`
- **Python SDK tests:** `cd sdk-python && pytest -v`
- **Sign commits:** `git commit -s -m "..."` (CI rejects unsigned)

## Architecture

```
bolyra/
├── circuits/         # Circom 2 circuits + snarkjs/rapidsnark proving
│   ├── src/          # HumanUniqueness, Delegation, AgentPolicy
│   ├── test/         # Mocha tests (fast: witness-only; slow: full proof)
│   ├── scripts/      # compile.js + 9 benchmarks (groth16/plonk/rapidsnark)
│   └── build/        # .r1cs, .zkey, .vkey, pot16.ptau, rapidsnark_prover
├── contracts/        # Hardhat — Solidity verifiers + on-chain registry
├── sdk/              # @bolyra/sdk v0.2.0 (TypeScript, public API)
├── sdk-python/       # bolyra (Python — pure types + subprocess bridge to JS)
├── integrations/     # langchain/, crewai/, mcp/, openclaw/, payment-protocols/
├── spec/             # DID method, IETF draft, conformance runner, test vectors
├── examples/         # mcp-demo (bolyra-proxy.js — used by .mcp.json)
├── docs/             # quickstart, owasp-agentic-mapping, superpowers/
├── strategy/         # competitive analysis (codex challenge, zk-vs-rfc7662)
├── patents/          # provisional + non-provisional drafts
├── landing/          # bolyra.ai landing page
└── *-autoresearch/   # 4 separate Karpathy-style loops (see below)
```

**Public API (TS SDK):** `createHumanIdentity(secret)`, `createAgentCredential(modelHash, operatorPrivKey, permissions, expiry)`, `proveHandshake(human, agent)`, `verifyHandshake(humanProof, agentProof, nonce)`. Delegation API is v0.3 stub.

## Circuits

| Circuit | Proving system | Notes |
|---|---|---|
| `HumanUniqueness` | Groth16 only | Reuses Semaphore v4 ceremony at depth 20 — no project-specific trusted setup needed. Public outputs: `humanMerkleRoot`, `nullifierHash`, `nonceBinding`. |
| `AgentPolicy` | Groth16 **and** PLONK | Both `.zkey` artifacts ship in `build/`. PLONK avoids per-circuit ceremony. |
| `Delegation` | Groth16 **and** PLONK | Same dual-build rationale as `AgentPolicy`. |

Powers of Tau: `pot16.ptau` (2^16 constraints) is the universal SRS for the project-specific Groth16 keys.

## Autoresearch Loops (4 — keep them separate)

| Loop | Directory | Purpose |
|---|---|---|
| Discovery | `discovery-autoresearch/` | New use cases / market directions |
| Differentiation | `differentiation-autoresearch/` | Competitive moat exploration |
| Patent | `patent-autoresearch/` | Patentable invention disclosures |
| Protocol | `protocol-autoresearch/` | Wire format + cryptographic primitive tuning |

Do not mix winners between loops.

## MCP Server

`.mcp.json` registers `bolyra-fs` (a filesystem proxy that's circuit-aware). Built artifact: `examples/mcp-demo/dist/bolyra-proxy.js`. Requires `BOLYRA_RAPIDSNARK` env pointing at `circuits/build/rapidsnark_prover`.

## Permissions Model

8-bit cumulative encoding — higher tiers imply lower:

| Bit | Permission | |
|---|---|---|
| 0 | `READ_DATA` | |
| 1 | `WRITE_DATA` | |
| 2 | `FINANCIAL_SMALL` | < $100 |
| 3 | `FINANCIAL_MEDIUM` | < $10K (implies bit 2) |
| 4 | `FINANCIAL_UNLIMITED` | implies 2+3 |
| 5 | `SIGN_ON_BEHALF` | |
| 6 | `SUB_DELEGATE` | |
| 7 | `ACCESS_PII` | |

`validateCumulativeBitEncoding()` enforces the implication rules; the `Delegation` circuit enforces them on-chain.

## Key Patterns & Gotchas

- **Test split is intentional** — `test:circuits:fast` runs witness-generation only (mock proofs), `test:circuits:slow` runs full Groth16/PLONK proving. CI defaults to fast; gate slow on a label.
- **rapidsnark vs snarkjs** — production proving uses the native `rapidsnark_prover` binary in `circuits/build/`. snarkjs is dev/test only. Benchmarks in `circuits/scripts/bench_rapidsnark.js` quantify the gap.
- **Python SDK is a thin shell** — `bolyra` (Python) only ships pure-Python types/validation. All proving spawns the Node `@bolyra/sdk` (snarkjs is JS-only). When adding a Python feature that needs proving, expose it through the subprocess bridge, don't reimplement in Python.
- **Scope narrowing is one-way** — delegated credentials can only narrow permissions, never expand. Enforced in `Delegation.circom`, not just in the SDK. Don't add SDK-level shortcuts that bypass the circuit.
- **Handshake nonce binding** — every handshake commits to a fresh `sessionNonce`. Replaying `(humanProof, agentProof)` without rebinding the nonce fails verification by design.
- **Groth16 ceremony reuse** — `HumanUniqueness` reuses the public Semaphore v4 ceremony (depth 20). Don't regenerate it. Project-specific keys (Agent/Delegation) use `pot16.ptau`.
- **Solidity verifiers must match `.zkey`** — when you re-run trusted setup or change a circuit, regenerate the verifier contract from the new `vkey.json`. Tests will pass against the wrong verifier locally if witness signatures happen to match — Hardhat catches this only on `verifyProof` integration tests.
- **DCO required** — every commit needs `Signed-off-by:`. Use `git commit -s`. To fix: `git commit --amend -s --no-edit`.
- **Apache 2.0 patent grant** — contributors implicitly grant a patent license. Be deliberate about external code.
- **License is uniformly Apache-2.0** — SDK READMEs, `package.json` (root + `sdk/`), `sdk-python/pyproject.toml`, and `LICENSE` all match. CONTRIBUTING.md DCO + Apache patent grant remain canonical.

## Environment

- Node 18+ (SDK), Node 20+ recommended
- Python 3.11+ for `sdk-python/`
- Hardhat for contracts; Circom 2 for circuits
- `backend/` and `frontend/` are placeholders — no service yet
- Deploy target chain: Base Sepolia (`baseSepolia` in Hardhat config)

## References

- TS quickstart: `sdk/QUICKSTART.md`
- Formal circuit properties: `circuits/FORMAL-PROPERTIES.md`
- DID method: `spec/did-method-bolyra.md`
- IETF-style draft: `spec/draft-bolyra-mutual-zkp-auth-01.md`
- OWASP agentic threat mapping: `docs/owasp-agentic-mapping.md`
- Differentiation vs RFC 7662: `strategy/zk-vs-rfc7662-differentiation.md`

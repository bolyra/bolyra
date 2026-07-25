# CLAUDE.md

This file provides guidance to Claude Code when working in this repository.

## Project

**Bolyra** — unified ZKP identity protocol for humans and AI agents. The ZKP core (Phase 1, Proof of Enrollment): humans prove uniqueness via Semaphore v4-style enrollment, agents prove EdDSA-signed credentials with cumulative-bit permissions, and a delegation circuit narrows scope one-way. The shipped **product surface** is authorization for AI agent actions — see "Verified Agent Actions (EVC + MPP)" below.

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
├── sdk/              # @bolyra/sdk v0.6.1 (TypeScript, public API)
├── sdk-python/       # bolyra (Python — pure types + subprocess bridge to JS)
├── integrations/     # langchain/, crewai/, openai-agents/ (bolyra-agents on PyPI), mcp/, openclaw/, payment-protocols/, gateway/, shield/, ai/, cli/,
│                     #   receipts/ (@bolyra/receipts), mpp-payments/ (@bolyra/mpp), hosted-verify/ (Cloudflare Worker preview)
├── spec/             # DID method, IETF drafts, External Verifier Contract v1, conformance runner + fixtures, reference-host-rs (Rust host)
├── delegation/ registry/ circuits-package/   # delegation pkg · on-chain registry service · @bolyra/circuits artifacts
├── pilot/            # pilot harness — thin ops layer (runbook, partner scripts, receipt export) over hosted-verify
├── actions/ apps/    # GitHub actions (replay-check) · apps (wallet)
├── examples/         # mcp-demo (bolyra-proxy.js — used by .mcp.json), mandate/stripe/receipt-scoring demos
├── docs/             # quickstart, owasp-agentic-mapping, superpowers/, pilot/, mpp-authorization-companion
├── strategy/         # competitive analysis (codex challenge, zk-vs-rfc7662)
├── patents/          # provisional + non-provisional drafts
├── landing/          # bolyra.ai landing page
└── *-autoresearch/   # 6 separate Karpathy-style loops (see below)
```

**Public API (TS SDK):** `createHumanIdentity(secret)`, `createAgentCredential(modelHash, operatorPrivKey, permissions, expiry)`, `proveHandshake(human, agent)`, `verifyHandshake(humanProof, agentProof, nonce)`. Delegation API is v0.3 stub.

## Verified Agent Actions (EVC + MPP) — the current product surface

Beyond the ZKP core, the shipped wedge is **authorization for AI agent actions** — proving who authorized an action, at what limit, for which payee, before it runs.

- **External Verifier Contract v1** (`spec/external-verifier-contract-v1.md`) — the open host↔verifier contract: one JSON request on stdin, one fail-closed allow/deny verdict on stdout. Verifiers self-describe `kind: classical | zk | external`. Reference hosts: `spec/reference-host-rs` (Rust) + the JS runner (`spec/conformance-runner.js`); hostile-fixture conformance suite in `spec/fixtures/host-conformance/`.
- **@bolyra/mpp** (`integrations/mpp-payments/`) — authorization middleware for the Machine Payments Protocol: `bolyraGate()` verifies an operator-signed spend mandate before a payment proceeds. Mint mandates with `bolyra mandate issue` (`integrations/cli/src/commands/mandate-issue.ts`) — issuance only, not a wallet. Try it: `npx @bolyra/mpp demo`.
- **@bolyra/receipts** (`integrations/receipts/`, v0.9.0) — ES256K-signed, hash-chained decision receipts; verify with `bolyra receipt verify` / `verify-chain`.
- **hosted-verify** (`integrations/hosted-verify/`) — a Cloudflare Worker classical-verify **design-partner preview** (no SLA, not production). `pilot/` is the thin readiness harness over it.

## Circuits

| Circuit | Proving system | Notes |
|---|---|---|
| `HumanUniqueness` | Groth16 only | Reuses Semaphore v4 ceremony at depth 20 — no project-specific trusted setup needed. Public outputs: `humanMerkleRoot`, `nullifierHash`, `nonceBinding`. |
| `AgentPolicy` | Groth16 **and** PLONK | Both `.zkey` artifacts ship in `build/`. PLONK avoids per-circuit ceremony. |
| `Delegation` | Groth16 **and** PLONK | Same dual-build rationale as `AgentPolicy`. |

Powers of Tau: `pot16.ptau` (2^16 constraints) is the universal SRS for the project-specific Groth16 keys.

## Autoresearch Loops (6 — keep them separate)

| Loop | Directory | Purpose |
|---|---|---|
| Discovery | `discovery-autoresearch/` | New use cases / market directions |
| Differentiation | `differentiation-autoresearch/` | Competitive moat exploration |
| Patent | `patent-autoresearch/` | Patentable invention disclosures |
| Protocol | `protocol-autoresearch/` | Wire format + cryptographic primitive tuning |
| Standards | `standards-autoresearch/` | IETF / EVC standardization + draft tracking |
| Theseus | `theseus-autoresearch/` | Theseus Network integration exploration |

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
- **Dependency `overrides` policy** — transitive vulnerabilities are pinned via per-manifest `overrides` blocks. Two patterns matter when adding new ones: (1) **never use a flat `overrides` key that collides with a direct dependency** — npm returns `EOVERRIDE` at install time. The repo's `snarkjs` is the canonical case: several manifests list `snarkjs ^0.7.x` as a direct dep, so the override that pins `snarkjs` inside the dev-only `circom_tester` subtree uses the nested form `"circom_tester": { "snarkjs": "0.7.6" }`, not a flat `"snarkjs": "0.7.6"`. (2) **Overrides are repo-local; they do NOT propagate to downstream consumers.** `@bolyra/mcp` lists `@modelcontextprotocol/sdk` as a peer dep — our overrides clean our lockfile, but consumers must upgrade themselves. Document any such residual in `SECURITY.md` under "Known accepted residual Dependabot alerts" and rely on the `dependency-audit` CI job (`npm audit --omit=dev --audit-level=high` per published package) to gate new runtime advisories.  (3) **Exact override pins go stale** — a pinned version can itself become advisoried later; re-check and bump/drop every override pin during each alert triage. Full triage log: `tasks/dependabot-cleanup-plan.md`.
- **Landing page deploys self-verify** — `landing/deploy.sh` runs `landing/verify.sh` after the CloudFront invalidation completes. `verify.sh` does both string-match (grep the rendered HTML for advertised symbols) AND runtime resolution (`npm install` the published tarball and `require()` each advertised function). The runtime check is non-negotiable: the 2026-05-30 X402 outage stayed live for 14 hours because the old verify.sh only grepped strings. To bypass for emergency redeploys: `BOLYRA_SKIP_VERIFY=1 ./landing/deploy.sh`. (Note: verify.sh's runtime-check version pins `SDK_VERSION`/`PP_VERSION` are hand-maintained and can lag the advertised versions — a known gap, not a blocker.)
- **Binding v2 signs `expiry`** — canonical EVC binding signs exactly `{agent_name, project_key, program, model, capabilities, expiry}` under DST `bolyra.external-verifier.binding.v2`; `@bolyra/mpp` maps CLI/API `agentName`/`audience` to `agent_name`/`project_key`. A five-field v1 binding is denied `unsupported_version` (fail-closed, no compat mode). The MPP gate, `bolyra verify`, and hosted-verify pin the same byte-compatible binding digest/vector — change them together and regenerate conformance goldens. ZK mode binds expiry in-circuit and was never exposed to the v1 re-anchoring gap.
- **Receipt `commerce.intentHash` is BARE 64-hex** (no `0x`) — the `@bolyra/receipts` verify CLI enforces `/^[0-9a-fA-F]{64}$/`; `signature.payloadHash` is separately `0x`-prefixed by design. An emitter that 0x-prefixes `intentHash` fails `receipt verify` even though it verifies programmatically (this bit `@bolyra/mpp` → fixed in 0.3.1).
- **CODEOWNERS gates the crypto/verifier/supply-chain paths** (`.github/CODEOWNERS`) — circuits, verifiers, receipts, delegation, mandate issuance, CI/release, and dependency manifests all require maintainer review. No drive-by merges there; docs/examples/tests are reviewable normally.
- **Pilot = harness, not platform** — `pilot/` makes a first pilot runnable in an afternoon over the hosted-verify *preview*. Do NOT build the hosted control plane / policy engine / audit portal until there's a signed pilot or a named-workflow design-partner commitment. See `pilot/RUNBOOK.md`.

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
- Wiki knowledge base: `wiki/_index.md` (LLM-maintained, see `WIKI.md` for schema)

---
title: Monorepo Layout
visibility: public
sources:
  - CLAUDE.md
  - package.json
last-updated: 2026-06-28
staleness-threshold: 30d
tags: [architecture, monorepo, repository-structure]
---

Bolyra is a unified ZKP identity protocol for humans and AI agents. The repository is a flat monorepo (no workspace manager) orchestrated by a root `package.json` that delegates to per-directory build tools.

## Overview

The repo lives at `github.com/bolyra/bolyra`. It contains Circom circuits, Solidity contracts, a TypeScript SDK, a Python SDK, multiple integration packages, a landing page, spec documents, and several autoresearch loops. There is no npm/yarn/pnpm workspaces configuration; each subdirectory with a `package.json` or `pyproject.toml` manages its own dependencies independently.

## Key Concepts

- **Root `package.json`** is `private: true` (never published). It exists solely to provide top-level `npm test` and `npm run compile:*` scripts that delegate into subdirectories.
- **Per-directory independence.** Each publishable package (`sdk/`, `integrations/*`, `sdk-python/`) has its own lockfile and dependency tree. CI builds local `file://` references when testing integration packages against the unpublished SDK.
- **DCO required.** Every commit needs `Signed-off-by:` (Apache 2.0 + DCO).

## How It Works

### Directory Map

| Directory | What it is | Language / Tooling |
|---|---|---|
| `circuits/` | Circom 2 circuits (HumanUniqueness, AgentPolicy, Delegation) + snarkjs/rapidsnark proving, Mocha tests, 9 benchmarks | Circom, JS |
| `contracts/` | Hardhat project -- Solidity Groth16 verifiers + `IdentityRegistry` on-chain registry | Solidity 0.8.24, Hardhat |
| `sdk/` | `@bolyra/sdk` -- public TypeScript API (`createHumanIdentity`, `createAgentCredential`, `proveHandshake`, `verifyHandshake`) | TypeScript |
| `sdk-python/` | `bolyra` PyPI package -- pure-Python types + subprocess bridge to the JS SDK for proving | Python 3.11+ |
| `integrations/` | Published integration packages: `payment-protocols/`, `mcp/`, `openclaw/`, `receipts/`, `gateway/`, `shield/`, `cli/`, `ai/`, `langchain/`, `crewai/`, `openai-agents/` | TS + Python |
| `circuits-package/` | `@bolyra/circuits` -- publishable subset of circuit artifacts | JS |
| `spec/` | DID method, IETF draft, conformance runner, test vectors | Markdown, JS |
| `landing/` | bolyra.ai static site (S3 + CloudFront) | HTML, JSX |
| `docs/` | Quickstart, OWASP agentic mapping, superpowers | Markdown |
| `strategy/` | Competitive analysis | Markdown |
| `patents/` | Provisional + non-provisional drafts | Markdown |
| `examples/` | MCP demo (bolyra-proxy.js) | JS |
| `demo/` | Audit demo | TS |
| `*-autoresearch/` | 4+ Karpathy-style autoresearch loops (discovery, differentiation, patent, protocol, standards, theseus) | Mixed |
| `wiki/` | LLM-maintained knowledge base | Markdown |
| `tasks/` | Task tracking and lessons learned | Markdown |

### Root Commands

```bash
npm test                     # circuits (fast/mock) + contracts
npm run test:circuits:fast   # witness-only, no full proving
npm run test:circuits:slow   # FULL_PROOF=1, ~2 min
npm run test:contracts       # Hardhat tests
npm run compile:circuits     # writes circuits/build/
npm run compile:contracts    # Hardhat compile
npm run conformance          # run conformance test vectors
npm run conformance:report   # generate spec/CONFORMANCE.md
```

### Per-Directory Commands

```bash
cd sdk && npm run build       # TS SDK build
cd sdk && npm run typecheck   # tsc --noEmit
cd sdk-python && pytest -v    # Python SDK tests
cd contracts && npm run deploy:local         # local Hardhat network
cd contracts && npm run deploy:base-sepolia  # Base Sepolia testnet
```

## Current Status

- Root version: `0.3.0`
- License: Apache-2.0
- Node 20+ recommended, Python 3.11+ for sdk-python
- 10+ npm packages published under the `@bolyra/` scope
- 4 PyPI packages published (`bolyra`, `bolyra-langchain`, `bolyra-agents`, `bolyra-crewai`)

## See Also

- [build-deploy.md](build-deploy.md) -- landing page deploy pipeline
- [contracts.md](contracts.md) -- Solidity verifier contracts
- `sdk/QUICKSTART.md` -- TypeScript quickstart
- `CONTRIBUTING.md` -- DCO and contribution rules

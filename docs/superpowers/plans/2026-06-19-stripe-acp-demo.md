# Plan: Stripe ACP End-to-End Demo

**Pipeline:** pdlc-2026-06-19-stripe-acp-demo
**Spec:** `docs/superpowers/specs/2026-06-19-stripe-acp-demo-design.md`
**Date:** 2026-06-19

## Tasks

### Task 1: Project Scaffolding (S, parallel)

Create `examples/stripe-acp-demo/` with:
- `package.json` — private workspace package, deps on `@bolyra/sdk`, `@bolyra/payment-protocols`, `@bolyra/receipts` via `file:` refs
- `tsconfig.json` — strict mode, ES2020 target, outDir `./dist`
- `.gitignore` — ignore `receipts/`, `dist/`, `node_modules/`

**Input:** existing examples/mcp-demo/ as pattern reference
**Output:** `examples/stripe-acp-demo/package.json`, `tsconfig.json`, `.gitignore`

### Task 2: Utility Modules (S, parallel)

Create:
- `src/colors.ts` — ANSI escape code helpers (green, red, cyan, dim, bold, reset)
- `src/stripe-sim.ts` — `simulatePaymentIntent()` returning mock PI objects

**Input:** spec design doc (terminal output section, stripe-sim section)
**Output:** `examples/stripe-acp-demo/src/colors.ts`, `src/stripe-sim.ts`

### Task 3: Demo Script + README (M, sequential, depends on 1+2)

Create:
- `src/demo.ts` — single-file orchestration of setup + 4 scenarios
  - Setup: create dev identities, build BolyraVerifiedContext, convert to StripeACPContext
  - Scenario 1: $25 authorize (allowed)
  - Scenario 2: $480 authorize (rejected, amount_exceeds_cap)
  - Scenario 3: $25 confirm (rejected, no SIGN_ON_BEHALF)
  - Scenario 4: verify all 3 receipts
- `README.md` — what the demo shows, how to run, what each scenario proves

**Input:** `@bolyra/payment-protocols` stripe-acp.ts API, `@bolyra/receipts` API, `@bolyra/sdk` dev.ts API
**Output:** `examples/stripe-acp-demo/src/demo.ts`, `examples/stripe-acp-demo/README.md`

### Task 4: Integration + Verification (S, sequential, depends on 3)

- Add `"demo:stripe-acp"` script to root `package.json`
- Run `npm install` in the demo directory
- Build with `npx tsc`
- Run with `npx tsx src/demo.ts`
- Verify exit code 0 and all receipt verifications pass

**Input:** all prior task outputs
**Output:** root `package.json` updated, demo runs successfully

## Dependency Graph

```
Task 1 (scaffold) ──┐
                     ├──> Task 3 (demo.ts + README) ──> Task 4 (integrate + verify)
Task 2 (utils)   ───┘
```

Tasks 1 and 2 are parallelizable. Task 3 waits for both. Task 4 is final verification.

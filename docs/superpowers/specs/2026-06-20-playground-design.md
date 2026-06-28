# bolyra.ai/playground -- Interactive Browser Demo

**Date:** 2026-06-20
**Author:** Viswa + Claude Opus 4.6
**Status:** Draft
**Pipeline:** pdlc-2026-06-20-playground

## Overview

A single static HTML page at `landing/playground.html` that lets visitors experience Bolyra's core flows directly in the browser without cloning, installing, or running anything. Pure client-side -- no backend, no network calls, no real ZKP proving.

The playground demonstrates three capabilities:

1. **SD-JWT Delegation Flow** -- human issues a scoped credential, agent presents it, middleware verifies. Interactive allow/deny for different scopes and amounts.
2. **Gateway Simulation** -- a simulated request hitting the gateway 4-step pipeline (credential check, tool policy, replay protection, receipt issuance).
3. **Receipt Inspector** -- paste a signed receipt JSON, verify the signature in-browser, and inspect the payload.

## Motivation

The current landing page has 6 launch videos (passive watching) and a quickstart that requires `npm install` + local setup. There is no way for a visitor to *interact* with Bolyra without leaving the browser. A playground reduces the activation energy from "clone and run" to "click and try."

Target audience: developers evaluating Bolyra at a conference booth, from a tweet link, or after reading the IETF draft. They want to see what the protocol does before committing to a local install.

## Technical Constraints

1. **Same stack as video pages.** React 18 + Babel standalone from unpkg CDN. No build step, no bundler, no node_modules. Single HTML file.
2. **Pure static on S3 + CloudFront.** No server-side logic. Everything runs in the browser.
3. **No real ZKP proving.** Circuits are ~16K constraints -- too heavy for browser. All "proofs" are simulated with pre-computed fixtures or mock data.
4. **Web Crypto API for Ed25519.** The SD-JWT delegation path uses Ed25519 signing and SHA-256 hashing, both available natively in modern browsers via `crypto.subtle`.
5. **Dark theme.** Must match the existing bolyra.ai design system: `--bg: #0a0a0a`, `--accent: #6366f1`, Space Grotesk / JetBrains Mono fonts.
6. **Plausible analytics.** Include the existing `plausible.io` script tag.

## Architecture

### Page Structure

```
landing/playground.html
  |-- Tab 1: Delegation Flow
  |-- Tab 2: Gateway Simulation
  |-- Tab 3: Receipt Inspector
```

Single HTML file with three tabbed panels. React components handle tab switching and per-tab state. No routing -- tabs are purely client-side.

### Tab 1: SD-JWT Delegation Flow

**What it demonstrates:** A human principal issues a scoped delegation credential to an AI agent. The agent then attempts tool calls with different scopes. The middleware checks whether the agent's credential covers the requested scope.

**Interactive elements:**
- **Scope selector:** Checkboxes for the 8 permission bits (READ_DATA through ACCESS_PII). Cumulative-bit rules are enforced visually -- checking FINANCIAL_MEDIUM auto-checks FINANCIAL_SMALL.
- **Amount input:** For financial permissions, an amount field ($1 - $1M). Maps to the permission tier (SMALL < $100, MEDIUM < $10K, UNLIMITED >= $10K).
- **"Issue Credential" button:** Generates an Ed25519 keypair via Web Crypto, creates a mock SD-JWT-style credential with the selected scope, displays the raw credential JSON.
- **"Try Tool Call" section:** Dropdown of sample tools (read_file, write_file, transfer_funds, sign_contract). Each tool has a required permission bitmask. Clicking "Execute" runs the scope check in-browser and shows ALLOW (green) or DENY (red) with the specific reason (e.g., "requires FINANCIAL_MEDIUM (bit 3), credential has only READ_DATA (bit 0)").
- **Delegation chain visualization:** Shows the scope narrowing visually -- parent scope -> delegated scope, with bits highlighted.

**Crypto used:**
- `crypto.subtle.generateKey('Ed25519')` -- keypair generation
- `crypto.subtle.sign('Ed25519')` -- signing the credential
- `crypto.subtle.verify('Ed25519')` -- verifying the credential signature
- `crypto.subtle.digest('SHA-256')` -- hashing for commitment simulation

**No real ZKP:** The "proof" is a mock object with the same shape as `Proof` from `@bolyra/sdk` types but filled with deterministic placeholder values. A note in the UI explains: "In production, this step uses a zero-knowledge proof (Groth16). This demo uses a simulated proof for illustration."

### Tab 2: Gateway Simulation

**What it demonstrates:** The 4-step gateway pipeline that runs on every tool call request.

**Layout:** A vertical pipeline visualization with 4 stages, each expanding to show detail when the simulated request passes through:

1. **Credential Check** -- Is the credential valid? Is it expired? Does the signature verify?
2. **Tool Policy** -- Does the credential's permission bitmask satisfy the tool's required bitmask? Is the chain depth within limits?
3. **Replay Protection** -- Has this nonce been seen before? (Uses an in-memory Set as the nonce store.)
4. **Receipt Issuance** -- If allowed, generate a signed receipt. If denied, generate a denial receipt with reason code.

**Interactive elements:**
- **Preset scenarios dropdown:**
  - "Valid agent, read_file" -- passes all 4 steps, green receipt
  - "Expired credential" -- fails at step 1
  - "Insufficient permissions" -- passes step 1, fails at step 2
  - "Replay attack" -- passes steps 1-2, fails at step 3 (click twice to see it)
  - "Custom" -- lets user edit the credential JSON and tool name
- **"Send Request" button:** Animates through the 4 stages with ~500ms delay between steps. Each step shows pass/fail with the specific check performed.
- **Pipeline visualization:** Each stage is a card that goes green (pass) or red (fail). Failed stage shows the error. Subsequent stages are grayed out (skipped).
- **Receipt output:** On completion, displays the generated receipt JSON (same structure as `SignedReceipt` from `@bolyra/receipts`). Receipt is signed with a demo secp256k1 key generated at page load.

**Crypto used:**
- Receipt signing uses `@noble/secp256k1` loaded from unpkg (same library used by `@bolyra/receipts` in production). This is the one external crypto dependency beyond Web Crypto.
- Alternatively, if bundle size is a concern, use Web Crypto ECDSA with P-256 and note the production system uses secp256k1.

**Decision: Use `@noble/secp256k1` from unpkg.** It is 4KB gzipped, already the production dependency, and produces receipts with the exact same format as the real gateway. Using P-256 would create a confusing mismatch.

### Tab 3: Receipt Inspector

**What it demonstrates:** Given a signed receipt JSON, verify its integrity and display its contents in a human-readable format.

**Interactive elements:**
- **Textarea:** Paste a receipt JSON (pre-populated with a sample receipt from Tab 2, or the user can paste their own).
- **"Verify" button:** Runs verification:
  1. Parse JSON
  2. Recompute payload hash (keccak256 of canonical JSON)
  3. Check hash matches `signature.payloadHash`
  4. Recover public key from ECDSA signature
  5. Derive Ethereum address from recovered key
  6. Check recovered address matches `signature.signer`
- **Results panel:**
  - Signature: VALID / INVALID (with specific failure reason)
  - Signer address: `0x...` (with match/mismatch indicator)
  - Payload breakdown: structured display of subject, decision, proof fields
  - Timeline: issuedAt as human-readable date
  - Permission bits: visual display of the bitmask as named permissions

**Crypto used:**
- `@noble/secp256k1` for signature recovery (same as Tab 2)
- `@noble/hashes` for keccak256 (loaded from unpkg)
- Canonical JSON serialization (port of the 15-line `canonicalize()` from `@bolyra/receipts`)

### Shared Components

- **TabBar** -- horizontal tab selector with underline indicator
- **CodeBlock** -- syntax-highlighted JSON display (using simple regex-based highlighting, no Prism/highlight.js dependency)
- **StatusBadge** -- green/red/yellow pill with icon
- **PermissionBitmap** -- visual 8-bit display with named labels
- **AnimatedPipeline** -- vertical step-through with timed transitions

### External Dependencies (all from unpkg CDN)

| Dependency | Version | Size (gzip) | Purpose |
|-----------|---------|-------------|---------|
| React | 18.3.1 | 42KB | UI framework (same as videos) |
| ReactDOM | 18.3.1 | 130KB | DOM rendering (same as videos) |
| Babel standalone | 7.29.0 | 700KB | JSX transform (same as videos) |
| @noble/secp256k1 | 2.2.3 | 4KB | Receipt signing/verification |
| @noble/hashes | 1.7.2 | 12KB | keccak256 for receipt hashing |

Total new dependencies beyond what video pages already load: ~16KB gzipped (noble/secp256k1 + noble/hashes).

**Note on noble library loading:** The `@noble/*` packages are ESM-only. They will be loaded via `<script type="module">` and their exports will be assigned to `window` globals for use in the Babel-transpiled React code. This is the same pattern used for any ESM-only library in a no-build-step environment.

### Ed25519 Browser Support

Web Crypto Ed25519 support:
- Chrome 113+ (May 2023): full support
- Firefox 130+ (August 2024): full support
- Safari 17+ (September 2023): full support
- Edge 113+ (May 2023): full support

Coverage is sufficient for a developer-facing demo. A fallback message will be shown for unsupported browsers: "Your browser does not support Ed25519 via Web Crypto. Please use Chrome 113+, Firefox 130+, or Safari 17+."

## Navigation Integration

The landing page (`index.html`) needs a link to the playground. Two touch points:

1. **Nav bar:** Add "Playground" link next to the existing "Blog" link.
2. **Hero section or quickstart section:** Add a CTA button: "Try it in your browser" linking to `/playground`.

## URL and Routing

- URL: `https://bolyra.ai/playground` (CloudFront maps `/playground` to `playground.html`)
- No client-side routing needed. Single page, tabs managed by React state.
- CloudFront already serves `*.html` files -- may need a redirect rule for `/playground` -> `/playground.html` if the existing config does not handle extensionless URLs.

## Sample Data

The playground needs realistic-looking sample data:

- **Sample credential:** Pre-generated Ed25519 keypair with a plausible-looking agent credential (modelHash, permissions, expiry in 2027).
- **Sample receipt:** A pre-signed receipt matching the `SignedReceipt` type, using a demo secp256k1 key.
- **Sample tool policies:** 4-5 tools with different permission requirements matching the gateway quickstart examples.

All sample data is generated at page load (not hardcoded) so the crypto is demonstrably real. The Ed25519 keypair is fresh each session. The secp256k1 receipt-signing key is deterministic (derived from a fixed seed) so users can verify receipts across tabs.

## What This Spec Does NOT Cover

- **Real ZKP in browser.** Explicitly out of scope. The playground simulates proofs.
- **WebSocket/SSE connections.** No live data. Everything is client-side.
- **Mobile-first design.** Desktop-first. Responsive enough to not break on mobile, but the primary UX is a wide screen with code blocks.
- **Persistence.** No localStorage, no cookies. State resets on refresh.
- **Backend API.** No server calls. Pure static.

## Risks

1. **Noble ESM loading.** The `@noble/*` packages are ESM-only. Loading ESM modules in a Babel-standalone environment requires careful script ordering. Mitigation: load noble via `<script type="module">`, assign to window globals, then load the Babel script which reads from window.
2. **Ed25519 browser compat.** Older browsers may not support Ed25519 in Web Crypto. Mitigation: feature detection with graceful fallback message. The target audience (developers) overwhelmingly uses modern browsers.
3. **Page weight.** Babel standalone is 700KB. This is acceptable for a demo page (same as video pages) but means first-load is ~900KB. Mitigation: all scripts load with `defer` or `async`, the page shell renders immediately.

## Success Criteria

1. A developer visiting `bolyra.ai/playground` can interact with all three tabs without any local setup.
2. The delegation tab correctly enforces cumulative-bit scope rules.
3. The gateway tab correctly demonstrates all 4 pipeline stages with accurate pass/fail logic.
4. The receipt tab successfully verifies receipts generated by the gateway tab.
5. Cross-tab flow works: generate a receipt in Tab 2, paste it in Tab 3, verify it.
6. Page loads in under 3 seconds on a typical broadband connection.
7. Dark theme matches the rest of bolyra.ai.

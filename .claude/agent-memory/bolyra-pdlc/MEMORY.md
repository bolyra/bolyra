# Bolyra PDLC Orchestrator Memory

## Landing Page Patterns
- Video pages use React 18.3.1 + ReactDOM 18.3.1 + Babel standalone 7.29.0 from unpkg CDN
- Dark theme: `--bg: #0a0a0a`, `--accent: #6366f1`, fonts: Space Grotesk + JetBrains Mono
- Plausible analytics: `<script defer data-domain="bolyra.ai" src="https://plausible.io/js/script.js"></script>`
- Deploy: `landing/deploy.sh` (S3 + CloudFront), verify: `landing/verify.sh`
- All landing pages are single HTML files, no build step

## Receipt Signing
- Uses `@noble/secp256k1` v2 + `@noble/hashes` (keccak256)
- `SignedReceipt` type in `integrations/receipts/src/types.ts`
- `signReceipt()` and `verifyReceipt()` in `integrations/receipts/src/sign.ts`
- Canonical JSON serialization via `canonicalize()` in `integrations/receipts/src/canonical.ts`

## Pipeline State
- State files at `tasks/pdlc/*.json`
- Pre-existing state files found (not created by this orchestrator): circuit-artifacts, credential-cli, gateway-docker, gateway-redis-nonce, langchain-adapter, mcp-auth-gateway, stripe-acp-demo

## SDK Types
- Permission enum in `sdk/src/types.ts` -- 8-bit cumulative encoding (bits 0-7)
- Gateway 4-step pipeline: credential check -> tool policy -> replay protection -> receipt
- Gateway middleware in `integrations/gateway/src/middleware.ts`

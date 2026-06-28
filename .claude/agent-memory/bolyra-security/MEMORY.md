# Bolyra Security Agent Memory

## Audit History
- 2026-06-12: Initial adversarial audit. 6 CRITICAL, 6 HIGH, 3 MEDIUM. 9 fixes shipped (Tier 1-3).
- 2026-06-19: SD-JWT + LangChain adapter audit. 2 CRITICAL, 4 HIGH, 3 MEDIUM, 3 LOW. See [audit_sdjwt_langchain.md](audit_sdjwt_langchain.md).
- 2026-06-20: Vercel AI SDK adapter audit (`@bolyra/ai`). 2 CRITICAL, 3 HIGH, 3 MEDIUM, 3 LOW. See [audit_ai_adapter.md](audit_ai_adapter.md).

## Key Patterns
- LLM tool outputs are part of model context -- never return bearer credentials (proofs, bundles, auth headers, SD-JWT receipts, keys) in tool output dicts. Applies to LangChain, Vercel AI SDK, and any future adapter.
- All adapter tools (LangChain auth/delegate/sd_jwt, Vercel AI authenticate/delegate) lack dev mode guards. MCP has `devMode` flag; adapters should match with NODE_ENV production guard.
- `Math.random()` is NOT cryptographically secure. Every nonce must use `crypto.randomBytes()`. The canonical implementation is `sdk/src/handshake.ts:defaultNonce()`. Adapter code must import it or replicate the CSPRNG pattern, never use `Math.random()`. This is a regression of Tier 3 fix `3e65812`.
- `hmac.compare_digest()` must be used for all security-critical string comparisons in Python. `sd_jwt.py` uses `!=` for nonce, sd_hash, audience.
- `BolyraSession` and `bolyra_delegate` tool do not enforce 3-hop delegation limit client-side (SDK does, but defense-in-depth needed).
- Exception `str(e)` / `err.message` in tool output can leak key material. Always return generic errors to LLM context, log details server-side.
- `decodeBundleFromHeader()` in `@bolyra/ai` does `JSON.parse() as BolyraProofBundle` with no schema validation -- crash/DoS vector.
- Duplicate `buildDevBundle` implementations in middleware.ts and tools.ts -- must be consolidated.

## File Map
- `sdk-python/bolyra/sd_jwt.py` -- pure-Python SD-JWT. Key areas: `_verify_kb_jwt()` (timing), `verify()` (no max_amount check), unused `decode_dss_signature` import.
- `integrations/langchain/bolyra_langchain/sd_jwt_tool.py` -- receipt returned in LLM context (C1), issuer+holder key collapse (C2).
- `integrations/langchain/bolyra_langchain/session.py` -- no hop limit (H2), scope_commitment overridable (M3).
- `integrations/ai/src/utils.ts` -- `generateNonce()` uses Math.random (C1), `decodeBundleFromHeader()` no validation (H2).
- `integrations/ai/src/tools.ts` -- bundle+authHeader in LLM output (C2), error leak (H3), no dev guard (H1).
- `integrations/ai/src/middleware.ts` -- `buildDevBundle()` uses Math.random, shared proof per model call (M3).
- `integrations/ai/src/server-middleware.ts` -- delegates to MCP verifyBundle correctly; no independent issues found.

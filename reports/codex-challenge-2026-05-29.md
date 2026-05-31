# Codex Adversarial Review — 2026-05-29

**Scope:** `92d026a..HEAD` (PRs #12 + #13)
**Mode:** `codex challenge` (model_reasoning_effort=high)
**Started:** 2026-05-29T05:03:56Z

---

## [codex findings]

I’m reviewing this as a diff-only security review, staying inside the repository code shown and not reading the excluded skill/agent paths. I’ll focus on concrete production failure modes and exploit paths rather than restating intent.

## [codex findings]

[P1] `IdentityRegistry.verifyDelegation` accepts stale proofs forever because `pubSignals[5] currentTimestamp` is never checked against `block.timestamp`.

Exploit: wait until a delegator or delegatee credential expires, then generate or replay a delegation proof using a historical `currentTimestamp` that was before expiry. The circuit may prove “valid at timestamp T,” but the registry never proves “T is close to now.” This breaks expiry as an on-chain security boundary. Deferring this is not okay.

[P1] The contract has no domain/version guard for the public signal layout.

Exploit: if the circuit, SDK, or generated verifier changes public signal order while still emitting six signals, the registry will silently interpret one field as another. A swapped `[nullifier, delegateeRoot]` or `[prevScope, newScope]` style mistake can turn into replay bypass, stale-root acceptance, or chain-state corruption. The comment says “MUST match,” but production code does not enforce a layout identifier, circuit hash, verifier version, or regression fixture at the contract boundary.

[P1] The Stripe ACP adapter treats TypeScript structure as a trust boundary.

Exploit: pass JSON like `{ verified: "false", permissionBitmask: -1n, chainDepth: -999, effectiveCommitment: "-1", warnings: [] }`. At runtime, `"false"` is truthy, `-1n` sets every financial bit under BigInt bitwise semantics, and the adapter can produce an unlimited verified ACP context with a bogus DID. TypeScript interfaces do not protect runtime inputs.

[P1] Negative `permissionBitmask` maps to maximum authority.

`bitmaskToStripeSpendingLimits(-1n)` sets `financialSmall`, `financialMedium`, `financialUnlimited`, and `signOnBehalf` to true. If any deserialization, test harness, or custom verifier path can produce a negative bigint, the adapter grants unlimited spend.

[P1] Non-cumulative financial bit patterns are upgraded instead of rejected.

Exploit: provide bit 4 alone, without bits 2 and 3. The adapter returns `tier="unlimited"` even though the comment says cumulative semantics are enforced elsewhere. If the real `verifyBundle` ever passes through malformed bitmasks, or a caller uses a structurally typed context, malformed authority collapses upward.

[P1] `verifyStripeACPSpend` does not enforce `SIGN_ON_BEHALF`, but the README tells integrators to use it to gate PaymentIntents.

Exploit: an agent with `FINANCIAL_SMALL` but without bit 5 can call a `pi.confirm`-style path. `verifyStripeACPSpend` returns `allowed: true`; most integrators will treat that as the ACP authorization decision. If confirmation on behalf of the user needs bit 5, this API should take an operation or expose a separate `verifyStripeACPConfirm` that fails closed.

[P1] `rootCommitment` is caller-supplied and not bound to the verified context.

Exploit: verify a bundle for root A, then call `authContextToStripeACPContext(ctx, allowlistedRootB)`. The adapter emits `rootAgentDid` for B while the acting credential belongs to A’s chain. Any merchant allowlist, risk rule, audit trail, or dispute workflow relying on `rootAgentDid` can be forged.

[P1] Invalid commitments can crash or mint malformed DIDs.

`buildDid` does `BigInt(commitmentDecimal)` with no validation. `"abc"` throws and can take down the request path. `"-1"` creates a DID containing a negative hex representation. Values above the field modulus or above 256 bits are accepted and produce non-canonical DIDs. The adapter needs decimal-string, non-negative, field-element, and width validation.

[P1] The “less than” spend policy is implemented as “less than or equal.”

The comments define bit 2 as `< $100` and bit 3 as `< $10K`, but `verifyStripeACPSpend` allows `amount <= cap`, so exactly `10_000` cents and exactly `1_000_000` cents pass. Exploit: spend the excluded boundary value.

[P1] The narrowing-wedge test can pass while real `verifyBundle` output fails.

The test constructs `BolyraVerifiedContext` by hand with `permissionBitmask: bigint`, `effectiveCommitment: string`, and `warnings: []`. If real MCP output serializes the bitmask as a decimal string or omits warnings, production either throws on BigInt bitwise operations or crashes spreading `ctx.warnings`. The test proves the fake shape, not the adapter’s real boundary.

[P2] The on-chain demo’s 3-leaf LeanIMT proof for `agentB` proves a compressed sibling shape, not true leaf-index semantics.

For leaf 2 it uses `length=1`, `index=1`, `siblings=[rootB]`, which proves membership in `H(rootB, agentB)`. That may match LeanIMT promotion, but it does not test the full 3-leaf index path or any verifier rejection for wrong promotion shape. A broken circuit that accepts arbitrary compressed paths could pass this demo.

[P2] The demo manually builds Merkle proofs instead of using the same proof builder production uses.

Exploit path is integration drift: production SDK emits one index/sibling convention, demo hardcodes another, and both can appear green because only the happy path is tested. Add fixtures for 1-leaf, 2-leaf left/right, 3-leaf promoted leaf, and wrong sibling order.

[P2] Replay testing only proves the chain-state guard, not nullifier replay protection.

Replaying hop 2 fails with `ScopeChainMismatch` before checking `usedDelegationNullifiers`. That does not prove the nullifier mapping works under a matching `prevScope` path. A regression that stops setting or checking nullifiers could still pass this replay test.

[P2] The 4th-hop adversarial test should not be deferred.

`MAX_DELEGATION_HOPS` is a security limit, and the code increments before checking. The only way to catch off-by-one behavior is to test the boundary: max-th hop allowed, max+1 rejected, failed max+1 does not mutate state. A 2-hop demo does not exercise this.

[P2] Currency handling will fail against real Stripe conventions.

Stripe commonly uses lowercase currency strings like `usd`; the adapter defaults to uppercase `USD` and compares case-sensitively. Production integrations can either deny valid charges or accidentally compare against a caller-controlled display currency rather than the actual Stripe amount currency.

[P2] Amounts are accepted as arbitrary JavaScript numbers, not integer minor units.

`9999.5` cents can be authorized even though Stripe amounts must be integers. Values above `Number.MAX_SAFE_INTEGER` can be rounded before comparison. Use safe integers or bigint minor units.

[P2] The adapter leaks more than the README claims.

The ACP context exposes stable root and leaf DIDs, exact delegation depth, exact effective scope as a decimal string, `signOnBehalf`, score, and verifier warnings. That enables cross-merchant correlation and reveals non-financial permission bits, not just the leaf cap.

[P2] `chainDepth`, `score`, `network`, and `warnings` are forwarded without sanity checks.

Exploit: pass `chainDepth=-1`, `score=Infinity`, a network string with extra DID separators, or warning text containing sensitive verifier internals. Downstream risk engines and logs will consume attacker-shaped metadata as if it came from verification.


---

**Tokens used:** 35350


**Finished:** 2026-05-29T05:05:41Z (exit 0)

## stderr
```
Reading additional input from stdin...
```

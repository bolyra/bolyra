# Receipt instance binding — design, v1 (draft for review)

Status: DRAFT. Motivated by a correct external critique on
[x402-foundation/x402#3230](https://github.com/x402-foundation/x402/issues/3230#issuecomment-5393045939):
Bolyra's `commerce.intentHash` is parameter-shaped, so a relying party can
verify a receipt but cannot independently derive **which action instance**
the authorization decision governed.

## 1. The gap, precisely

Today's signed receipt payload carries:

- `commerce.intentHash = sha256(canonicalize({audience, program, capabilities, amountUsd, tier}))`
  — deterministic but **parameter-shaped**: two otherwise identical spend
  intents produce the same hash.
- `proof.nonce` — random 128-bit value; unique per receipt but
  issuer-generated and not known to the counterparty before receipt
  disclosure: it proves distinctness, not identity.

So the receipt answers "who authorized, under what parameters, in what
order" (signature + chain), but not "which specific action instance" in a
way a third party can recompute from the action's own facts.

## 2. Design goals

1. **Instance-shaped and third-party-recomputable**: any party holding the
   preimage fields derives the same reference, with no callback to the
   issuer and no trust in the emitting system.
2. **Additive and backward compatible**: existing receipts remain valid;
   the new field is optional; `intentHash` is unchanged (it remains useful
   as the parameter-level grouping key).
3. **Domain-separated from day one.** The argentum `action_ref` spec
   shipped v1 as bare `SHA-256(JCS(preimage))` and later had to add a
   `v2:` prefix after a cross-protocol collision risk was raised (their
   own changelog documents this). We adopt both defenses at v1: a
   domain-separation tag *inside* the hashed bytes, and a version marker
   *in the reference string syntax* so a verifier never guesses the
   derivation.
4. **Composable with external instance references**, specifically
   argentum's `action_ref` (v1 bare-hex or `v2:`-prefixed), without
   depending on them.

## 3. The construction

New optional block in the signed `ReceiptPayload` (sibling of `commerce`).
**v1 scope: spend decisions only** — receipts of kind `bolyra.commerce`,
where every preimage field below has a real value. Auth-kind receipts have
no amount surface, so rather than defining sentinel semantics for
`amountUsd`, instance binding for `bolyra.auth` is deferred to a v2 of
this design with its own preimage shape (the gap exists there too; a wrong
preimage now would be worse than a narrower v1):

```ts
instance?: {
  /** "birv1:" + lowercase sha256 hex over the domain-tagged canonical preimage. */
  ref: string;
  /** Carried IN FULL so the receipt is self-contained: verify the ES256K
   *  signature, recompute ref from these fields, compare. */
  preimage: {
    audience: string;        // payee / project_key the decision bound to
    program: string;         // binding program discriminator (e.g. "x402", "mpp")
    capabilities: string[];  // capability tokens the decision was evaluated
                             // over, order as presented (the granted set on
                             // allow; on deny, the tokens evaluated against)
    amountUsd: string;       // decimal string, exactly as decided
    decisionAt: string;      // RFC 3339 UTC, 3-digit ms: "2026-08-24T10:00:00.123Z"
    requestNonce?: string;   // in-protocol challenge nonce when one exists (see 3.2)
    actionRef?: string;      // optional external instance ref, verbatim (see 3.3)
  };
}
```

Derivation (separator discipline matches the EVC binding's own
`DST || 0x00 || payload` construction):

```
dsInput = utf8("bolyra.receipt.instance/1") || 0x00 || utf8(canonicalize(preimage))
ref     = "birv1:" + sha256hex(dsInput)
```

- The DST inside the hashed bytes, terminated by an explicit `0x00`
  separator, prevents cross-protocol preimage collision (the failure mode
  argentum's v2 retrofitted against) and forecloses any tag/payload
  boundary ambiguity.
- The `birv1:` string prefix makes the derivation version syntactically
  self-identifying, per the argentum v2 lesson: a verifier reads the
  prefix, applies exactly that derivation, and compares. No guessing.

### 3.1 Canonicalization domain (strings only, by construction)

`canonicalize()` in `@bolyra/receipts` is sorted-key `JSON.stringify`,
which matches RFC 8785 (JCS) output **only** for a restricted input
domain. We therefore constrain the preimage the same way argentum
constrains theirs, instead of pretending general JCS compliance:

- the preimage schema is CLOSED: exactly the members named in §3, fixed
  ASCII member names, no unknown members, no nulls, no nested objects,
  no numbers (this is why `amountUsd` is already a decimal string);
- every value is a string or array of strings whose characters are
  Unicode scalar values in `0x00..0x7F` (ASCII) only; `decisionAt` MUST
  match `YYYY-MM-DDTHH:MM:SS.mmmZ` exactly;
- within that domain, sorted-key `JSON.stringify` is byte-equivalent to
  RFC 8785 (JCS): arrays preserve order, there is no number
  normalization, and JSON string escaping of quotes, backslashes, and
  control characters follows the same rules;
- a verifier encountering a preimage outside this domain MUST reject with
  a distinct error (mirroring `OUT_OF_PROFILE_DOMAIN`) and MUST NOT
  attempt best-effort canonicalization. One pinned behavior, no fallback.

### 3.1.1 Audience identifier syntax

Per the §6 resolution, `audience` is a stable machine identifier, never a
display name. Within the preimage domain it is pinned tighter than the
general ASCII rule:

- `audience` MUST match `^[\x21-\x7E]{1,256}$` — printable ASCII excluding
  space and control characters, 1 to 256 characters.

Rationale: the identifier shapes in actual use (0x addresses, DIDs,
project keys, URLs) contain no spaces; display names essentially always
do. The regex is a **syntactic floor, not semantic proof** — it cannot
prove a value is not a display name, but it rejects the common failure
shape without inventing a grammar that would itself need versioning.

This syntax is part of the §3.1 preimage domain: a verifier MUST reject an
`audience` outside it (`out_of_domain`), and issuance/emission MUST
enforce the same rule earlier in the pipeline (spec §4). One pinned
behavior at every layer; a signed receipt whose audience is
`"Acme Corp"` is not verifier-valid.

### 3.2 Instance discrimination: `decisionAt` + `requestNonce`

Millisecond timestamps alone leave a residual: two identical decisions in
the same millisecond collide (argentum's construction shares this
property). Where the transport already has an in-protocol single-use value
known to BOTH sides before the decision, it goes in `requestNonce`. The
concrete case today is the **x402 EVC profile challenge nonce**: the 402
response issues `x402-evc-nonce` before the retry, so both sides hold it
pre-decision, and for that profile `requestNonce` is **REQUIRED**. (EVC v1
itself has no generic pre-decision challenge nonce in its request shape —
`consume_nonces` is a verdict-side construct — so this field is
transport-supplied, never invented.) Unlike `proof.nonce`
(issuer-generated, unknown to the counterparty until disclosure), the
counterparty already holds `requestNonce` and can recompute the ref. When
no such value exists, `requestNonce` is omitted and `decisionAt` is the
discriminator; the residual is documented, not hidden.

### 3.3 Composition with argentum `action_ref` (and peers)

`preimage.actionRef` carries an external instance reference **verbatim**
(argentum v1 bare-hex or `v2:`-prefixed both fit; the field is opaque to
us). Effects:

- our `instance.ref` then cryptographically binds the Bolyra decision to
  that external action instance — the one correspondence that is a direct
  byte comparison (`action_ref` ↔ `preimage.actionRef`);
- further cross-checks against an argentum `authorization_ref` preimage
  (`decision_ts` vs `decisionAt`, `authorized_scope` vs `capabilities`,
  `policy_id` vs our program/audience identity) are **application-defined
  mappings**, not field identities: scope vocabularies and policy
  identifiers differ between the two systems, so a relying party doing
  this join must define its own mapping and its own tolerance for the two
  timestamps, which are recorded by different actors and need not be
  equal.

We deliberately do NOT adopt their preimage wholesale: our decision fields
(`capabilities`, `amountUsd`, `audience`) are the facts our verifier
actually decided on, and an instance ref that omitted them would let a
receipt claim an instance while silently referencing a different decision
shape.

## 4. What changes where

| Surface | Change |
|---|---|
| `@bolyra/receipts` `types.ts` | add optional `instance` to `ReceiptPayload` (inside the signed payload, so it cannot be rewritten without breaking ES256K) |
| `@bolyra/receipts` new `instance.ts` | `computeInstanceRef(preimage)`, domain validation, `birv1:` parsing |
| `@bolyra/receipts` new public API | `verifyInstanceBinding(receipt)` — the SEMANTIC check: domain-validate the preimage, recompute `ref`, compare; distinct errors for mismatch vs out-of-domain. This is deliberately a public export, not CLI-internal: **`verifyReceipt()` in `sign.ts` checks only payloadHash + ES256K signature**, so a signer-issued receipt with a wrong `instance.ref` passes signature verification — signature validity and instance-binding validity are different claims, and every consumer of the semantic claim must call the semantic API |
| `@bolyra/receipts` `verify-cli.ts` | wire `verifyInstanceBinding` into the golden-corpus verifier: when `instance` present, reject on mismatch or out-of-domain |
| `@bolyra/cli` `receipt-verify.ts` | `bolyra receipt verify` / `verify-chain` currently use only `verifyReceipt()`; they MUST additionally call `verifyInstanceBinding` when the block is present, else the user-facing verifier would bless receipts whose instance claim is false |
| `@bolyra/mpp` `receipts.ts` | add `decisionAt: string` and `requestNonce?: string` to `DecisionFacts` (neither exists there today); compute `decisionAt` once at the decision boundary; populate `instance` in `buildDecisionReceiptInput` |
| `spec/x402-evc-profile-v0.md` | profile receipts MUST carry `instance` with `requestNonce` = the profile's 402 challenge nonce (`x402-evc-nonce`) |
| golden corpus / conformance | new golden receipts with `instance`; negative vectors: tampered preimage, wrong ref, out-of-domain values |

Versioning: `ReceiptPayload.v` **stays `1`**, settled. The verify CLI's
validation checks `payload.v !== 1` and does not reject unknown payload
members (verified against `verify-cli.ts`), so the optional `instance`
block is backward compatible as-is; and because it lives inside the signed
payload, the ES256K signature covers it automatically on receipts that
carry it. New negative vectors (not schema versioning) are what enforce
its correctness.

## 5. Non-goals

- Not a replacement for `intentHash` (parameter-level grouping stays).
- Not payee-risk or outcome attestation (gate 2 / #3234 territory).
- Not an on-chain anchor format; `ref` is anchor-friendly but anchoring is
  out of scope here.

## 6. Open questions — resolved in external review (2026-08-24)

Both questions were reviewed by the argentum `action_ref` author on
[x402#3230](https://github.com/x402-foundation/x402/issues/3230); the
resolutions below are adopted.

1. **Full preimage inline, settled.** A ref a relying party cannot
   recompute without an out-of-band fetch is only
   third-party-verifiable-if-the-issuer-cooperates. Self-contained is the
   default; ref-alone would only be revisited if payload size becomes a
   demonstrated constraint. (argentum reached the same conclusion for
   `action_ref`; see their
   [RFC 002](https://github.com/giskard09/argentum-core/blob/c284f599eb84835446a272d0c8ebb5d95b4d9ff6/docs/rfcs/002-action-ref-v2-domain-separation.md).)
2. **ASCII domain stays; `audience` is pinned, not widened.**
   `audience` MUST be a stable ASCII machine identifier — an address, DID,
   or project key — never a display name. Internationalized merchant
   display names live outside the signed preimage entirely, at the display
   layer that already handles them. Widening `canonicalize()` to Unicode
   would reopen the general-JCS-compliance claim §3.1 explicitly declines
   to make. The concrete syntax is pinned in §3.1.1 and joins the verifier
   domain (an implementation-time tightening beyond this resolution as
   first written; disclosed on the review thread).
   **Honest pipeline note:** today `@bolyra/mpp` documents `audience` as
   the payee/project key and compares it byte-literally, but enforces only
   non-empty (`issue.ts` / `gate.ts`) — a raw merchant string is not
   rejected at issuance. The implementation of this spec MUST therefore
   enforce the ASCII-identifier constraint at mandate issuance and at
   receipt emission (where an out-of-domain preimage already makes
   `computeInstanceRef` throw), not only at verification.

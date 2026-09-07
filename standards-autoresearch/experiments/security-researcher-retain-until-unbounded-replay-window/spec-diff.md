Base-Commit: a4f546f3279706a2b28a0c15569c0040425e84c7
Target-File: spec/external-verifier-contract-v1.md
Finding: security-researcher-retain-until-unbounded-replay-window

## Summary

`retain_until` is the only time value in the contract with no floor. The request-side `now_unix` carries `exclusiveMinimum: 0` and a "positive" prose requirement; the verdict-side `retain_until` is a bare `integer`, and §7.3 tells the host to retain the nonce "until" that value. A verdict with `retain_until` at zero, negative, or at or below the host's own `now_unix` is therefore schema-valid, and a host that implements §7.3 literally may release the reservation the instant it is written. This diff gives `retain_until` the same schema floor `now_unix` has, makes the verifier responsible for emitting a future value, and makes a non-future value a host fail-closed condition rather than a silent early-eviction path. It also states that a reservation is never released while the action it gates is still running. One new host-behavior conformance vector must accompany the diff.

## Diff

Hunks are anchored by context, not by line number: this artifact was produced with no tool access to the checkout, so numeric `@@` ranges are intentionally omitted. Each hunk's context lines are copied verbatim from the pinned text and should match exactly at the base commit. The founder applies the hunks by context (or fills in line numbers and uses `git apply`) per APPLY.md.

```diff
--- a/spec/external-verifier-contract-v1.md
+++ b/spec/external-verifier-contract-v1.md
@@ header block @@
 - **Status:** Stable (v1)
 - **Wire version:** `1` (integer-major; see §11)
-- **Document revision:** 2026-08-26 (registry closure and fail-closed
-  classification precedence made explicit — prose only, wire contract unchanged;
-  see the changelog in §15). Previous: 2026-07-17 (binding format **v2** —
+- **Document revision:** 2026-09-07 (`retain_until` retention floor — the
+  verdict schema now requires a positive value and a host fails closed on a
+  `retain_until` that is not later than its own `now_unix`; see the changelog
+  in §15). Previous: 2026-08-26 (registry closure and fail-closed
+  classification precedence made explicit), 2026-07-17 (binding format **v2** —
   expiry is now signature-bound), 2026-07-11 (§16 Host conformance). The wire
   request/verdict envelope major is unchanged; the **binding** sub-structure is
   versioned separately (v1 → v2, §4).
@@ §3.2 Allow with host-owned nonce consumption @@
   - `issuer_key` (string, **REQUIRED**) — the issuer/operator key that scopes the
     nonce namespace. For host bookkeeping only; the `nonce` is already globally
     unique (§8).
   - `nonce` (string, **REQUIRED**) — the one-time value the host **MUST** record.
-  - `retain_until` (integer, **REQUIRED**) — Unix seconds until which the host
-    **MUST** retain the consumed nonce.
+  - `retain_until` (integer, **REQUIRED**, positive) — Unix seconds until which
+    the host **MUST** retain the consumed nonce. The verifier **MUST** set it
+    strictly greater than the request's `now_unix` (§2.1). A value less than or
+    equal to `now_unix` is a verdict shape this contract does not define, and the
+    host **MUST** fail closed on it (§7.2, §7.3) rather than clamp, ignore, or
+    honour it. A verifier **SHOULD** set `retain_until` no earlier than the
+    effective expiry it evaluated the credential against: after that instant the
+    same proof can no longer verify (`expired`, §9), so retention past it is
+    unnecessary, and retention short of it leaves a window in which the proof
+    still verifies but the nonce may have been evicted.
@@ §3.4 Verdict JSON Schema @@
             "properties": {
               "issuer_key": { "type": "string" },
               "nonce": { "type": "string" },
-              "retain_until": { "type": "integer" }
+              "retain_until": { "type": "integer", "exclusiveMinimum": 0 }
             }
           }
         }
@@ §7.2 Host fail-closed obligations @@
 - a verdict that otherwise fails the §3.4 verdict schema — including an
   unrecognized `kind` value (outside `classical` | `zk` | `external`, §3.5), a
   `code` outside the §9 registry, or any disallowed additional property.
+- in host nonce mode (§8), an `allow` whose `consume_nonces` contains **any**
+  entry with `retain_until` not strictly greater than the `now_unix` the host
+  wrote in the request (§2.1). The schema floor in §3.4 (`exclusiveMinimum: 0`)
+  rejects only zero and negative values; the comparison against `now_unix` is a
+  host obligation because a JSON Schema cannot reference the request. A host
+  that reports why it failed closed (§16.3) **SHOULD** classify this cause as
+  `schema_invalid`: the verdict is one the contract does not define, and no new
+  classification is introduced within wire version 1.
@@ §7.3 Reserve-before-act (host nonce mode) @@
 When the host runs the verifier in **host nonce mode** (§8) and receives
 `allow` with `consume_nonces`, the host **MUST** reserve **every** entry in the
 list **before** performing the privileged action:
 
+Before step 1, the host **MUST** check that **every** `entry.retain_until` is
+strictly greater than the request's `now_unix`. If any entry fails this check
+the host **MUST** deny (§7.2) without inserting any entry and without performing
+the action. The check precedes insertion so that a stale entry can never leave
+a partial reservation behind.
+
 1. For **each** `entry` in `consume_nonces`, atomically insert `entry.nonce` into
    durable storage with a unique-insert / "on conflict reject" semantic,
-   retaining it until `entry.retain_until`.
+   retaining it until `entry.retain_until`. `retain_until` is a **floor** on
+   retention, never a licence to evict early: the host **MUST NOT** release a
+   reservation before the action it gates has completed or been abandoned, even
+   if `entry.retain_until` passes while the action is in progress.
 2. If **all** inserts are **novel**, proceed with the action.
 3. If **any** insert **conflicts** (that nonce was already recorded), the host
    **MUST** reject the action as a replay — even though the verifier returned
    `allow`.
```

## Rationale

### The divergence the pinned text permits

§3.2 at the base commit reads:

> `retain_until` (integer, **REQUIRED**) — Unix seconds until which the host **MUST** retain the consumed nonce.

and §7.3 step 1 reads:

> atomically insert `entry.nonce` into durable storage with a unique-insert / "on conflict reject" semantic, retaining it until `entry.retain_until`.

The obligation is bounded entirely by a verifier-supplied integer. The §3.4 schema types it as `{ "type": "integer" }` with no minimum, whereas the request-side `now_unix` in §2.2 is `{ "type": "integer", "exclusiveMinimum": 0 }` and §2.1 prose adds "positive". Nothing on the verdict side imported that constraint.

Two conforming hosts therefore diverge on a security-relevant edge. Host A treats a `retain_until` of `0` as already elapsed and garbage-collects the row on its next sweep, possibly before the action finishes. Host B keeps rows for a fixed local minimum regardless. Host C clamps to `now_unix + some default`. All three are compliant with the pinned text, and only one of them prevents a second presentation of the same bundle from passing the reserve-before-act insert. The failure mode does not require a hostile host: a verifier that computes `retain_until` from `expiry` with a seconds/milliseconds mix-up, or against its own skewed clock instead of `now_unix`, produces exactly this value. That is the class of failure host nonce mode exists to prevent: the verifier said allow, the host did the bookkeeping, and replay still worked.

No vector in set 0.6.0 exercises it. `host-deny-nonce-entry-wrong-type` checks only that a string is rejected where an integer is required. There is no range vector at all for `retain_until`.

### Why this wording closes it

The diff attacks the gap from three sides so that no single implementation lapse reopens it.

- **Schema floor.** `exclusiveMinimum: 0` on `retain_until` mirrors `now_unix` exactly. A generic schema-validating host now rejects zero and negative values with no bespoke code, and the two schemas stop disagreeing about whether Unix timestamps may be non-positive.
- **Verifier obligation.** A verifier that emits a non-future `retain_until` is now non-conformant, so the reference verifier and any classical or external verifier have an explicit target to test against. The SHOULD tying `retain_until` to the effective expiry gives implementers the one value that is provably sufficient: after `effective_expiry` the proof fails the strict `expired` check in §9, so replay is impossible without the nonce store, and before it the nonce must be present.
- **Host obligation, fail-closed.** The chosen rule is deny, not clamp. Clamping or defaulting would silently rewrite verifier output and hide the verifier bug that produced it, which is the opposite of the contract's fail-closed posture. Deny is also consistent with how §9 already treats an out-of-registry `code`: a malfunctioning verifier is not relayed, it is overridden by the host. Placing the check before step 1 avoids a partial-reservation state, matching the "reserve every entry before acting" structure of §7.3.
- **No early eviction during the action.** Even with a strict `retain_until > now_unix`, a value of `now_unix + 1` could still elapse mid-action on a slow privileged operation. The added sentence in step 1 states what §7.3 always implied but never said: retention is a floor, and the reservation lives at least as long as the action it gates.

### RFC 2119 keyword choices

- **MUST** (verifier sets `retain_until > now_unix`; host checks it; host denies on failure; host does not release before the action completes). These are interoperability and security requirements where a lapse reopens the replay window. Anything weaker would leave the divergence in place.
- **SHOULD** (verifier sets `retain_until` at or after effective expiry). This is the recommended and provably sufficient value, but a verifier may legitimately choose a shorter retention when its own policy bounds proof reuse more tightly, or a longer one for audit reasons. It does not affect correctness of the host's replay check, so SHOULD is the right strength.
- **SHOULD** (host classifies the cause as `schema_invalid`). §16.3 classification is reporting, not enforcement, and the existing §7.2 text uses SHOULD for the precedence rules. Reusing `schema_invalid` avoids adding a value to the §16.3 enum inside wire version 1, which would itself be a registry change. If the founder prefers a dedicated classification, that is a §16.3 enum addition and should be staged as a separate finding.

## Impact

### Published conformance vectors (set 0.6.0, 28 host-behavior vectors)

- **Expected effect on the existing 28: none.** The only vectors that carry a `consume_nonces` entry with a `retain_until` value should already use a far-future timestamp, as the §3.2 example does (`4102444800` against a `now_unix` of `1751990400`). The `host-deny-nonce-entry-wrong-type` vector is unaffected: it fails on type before any range check applies. This was not verified against the fixture files because the artifact was generated without tool access. APPLY.md must re-validate before merge by listing every `retain_until` in `spec/fixtures/host-conformance/` alongside its vector's `now_unix` and confirming each is strictly greater. If any existing vector violates the new floor, that vector's expected outcome must be reconsidered rather than the floor weakened.
- **One vector artifact must accompany this diff:** `host-deny-nonce-retain-until-not-future`. The host under test runs in host nonce mode and receives, at exit 0, `{"verdict":"allow","consume_nonces":[{"issuer_key":"<any>","nonce":"<any>","retain_until":<now_unix>}]}` where `retain_until` equals the request's `now_unix`. The equality boundary is the sharpest case because it passes the new JSON Schema floor and is caught only by the host's comparison. Expected: deny, no action performed, no nonce inserted, failure classification `schema_invalid` as it appears in the fixture enum at the base commit. A second, optional vector `host-deny-nonce-retain-until-nonpositive` with `retain_until: 0` exercises the schema floor on its own and is recommended for hosts that validate via a generic JSON Schema library.
- **Vector set version:** adding a vector changes the published set, so the vector-set version must be bumped from 0.6.0 according to the convention in `spec/CONFORMANCE.md`, and the vector index there must gain the new row. The vendored `@bolyra/evc-conformance` copy is regenerated with `node integrations/evc-conformance/scripts/sync.js`; CI's `sync:check` will fail until that is run.
- **Changelog:** §15 needs a 2026-09-07 entry describing the retention floor. §15 is outside the pinned excerpt this artifact was written from, so no context-anchored hunk is given; the entry follows the format of the 2026-08-26 line already present.

### Wire compatibility

Wire version stays `1`. No field is added, removed, or renamed, and the denial-code registry is untouched. The change narrows the set of valid `allow` verdicts: verdicts with `retain_until` at or below zero are now schema-invalid, and verdicts with `retain_until` at or below `now_unix` are host-rejected. A verifier that previously emitted such values was already producing a verdict that no host could enforce as intended, so the narrowing removes an undefined case rather than a working one. A conforming verifier's output under the new text is a strict subset of what the old schema accepted, so a host still validating against the pre-revision schema continues to accept it. Whether the reference `bolyra verify` and hosted-verify emit `retain_until` derived from the effective expiry against `now_unix` was not verified here and must be confirmed in APPLY.md by inspecting their `retain_until` computation; the Tier 1 judgment recorded that no exploit was established against the correct reference verifier, which is consistent with this diff being a hardening of the contract rather than a fix to the reference.

### -02 relevance

This is -02 material. It closes a normative gap where the request and verdict schemas disagreed on the positivity of a timestamp, adds a MUST that is directly coverable by a conformance vector, and improves the "% of normative MUSTs covered by a vector" component of SPEC HARDNESS. It also strengthens the reserve-before-act section, which is the part of the contract an IETF security reviewer will read most closely, by stating explicitly that the host never evicts a reservation while the gated action is in flight. No IANA-style registry (§9 codes, §16.3 classifications) is modified, so the change carries no registry-closure implications for -02.

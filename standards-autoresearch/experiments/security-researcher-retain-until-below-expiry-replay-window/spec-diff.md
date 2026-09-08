Base-Commit: 9bf754441ab36ab93992ed5936d34c44a4128f92
Target-File: spec/external-verifier-contract-v1.md
Finding: security-researcher-retain-until-below-expiry-replay-window

```diff
--- a/spec/external-verifier-contract-v1.md
+++ b/spec/external-verifier-contract-v1.md
@@ -183,8 +183,14 @@
     nonce namespace. For host bookkeeping only; the `nonce` is already globally
     unique (§8).
   - `nonce` (string, **REQUIRED**) — the one-time value the host **MUST** record.
   - `retain_until` (integer, **REQUIRED**) — Unix seconds until which the host
-    **MUST** retain the consumed nonce.
+    **MUST** retain the consumed nonce. The verifier **MUST** set `retain_until`
+    to a value greater than or equal to the credential's effective expiry (the
+    same `effective_expiry` the §9 `expired` check compares against), so the
+    reservation outlives every instant at which the proof is still acceptable.
+    A verifier **MUST NOT** emit a `retain_until` less than or equal to the
+    request's `now_unix`; a host receiving one **MUST** fail closed (§7.3).
+    `retain_until` is a **positive** integer (§3.4).
 
 ### 3.3 Deny
 
@@ -236,7 +242,7 @@
             "properties": {
               "issuer_key": { "type": "string" },
               "nonce": { "type": "string" },
-              "retain_until": { "type": "integer" }
+              "retain_until": { "type": "integer", "exclusiveMinimum": 0 }
             }
           }
         }
@@ -528,6 +534,17 @@
 3. If **any** insert **conflicts** (that nonce was already recorded), the host
    **MUST** reject the action as a replay — even though the verifier returned
    `allow`.
+
+Before step 1 the host **MUST** check that every `entry.retain_until` is
+**strictly greater** than the `now_unix` it wrote into the request (§2.1). An
+entry whose `retain_until` is less than or equal to `now_unix` describes a
+retention window that has already ended; reserving it is vacuous, and the same
+proof would re-present with a fresh, non-conflicting reservation for the rest
+of the credential's lifetime. The host **MUST** treat such a verdict as failing
+the §3.4 verdict schema and fail closed (§7.2; classification `schema_invalid`,
+§16.3): it **MUST NOT** perform the action and **MUST NOT** rely on the
+verifier's `allow`. The host **MUST NOT** evict a reserved nonce before its
+`retain_until` has passed (§3.2).
 
 "Record after proceeding" is a replay window and is **FORBIDDEN**. The verifier's
 `allow` in host mode is **conditional** on every host insert being novel.
```

## Rationale

**The divergence the pinned text permits.** §3.2 defines the field only as
"`retain_until` (integer, **REQUIRED**) — Unix seconds until which the host
**MUST** retain the consumed nonce." §3.4 constrains it only as
`"retain_until": { "type": "integer" }`. Neither sentence bounds the value
relative to `now_unix` or to the credential's expiry. Meanwhile §9 defines
expiry as "proof-anchored `now_unix >= effective_expiry` — a **strict**
comparison; the equality boundary is rejected," so the proof is live for every
`now_unix < effective_expiry`. §7.3 tells the host to insert the nonce
"retaining it until `entry.retain_until`" and nothing more.

Put together: a verifier that emits `retain_until` earlier than
`effective_expiry` (including `0`, a negative number, or a value already in the
past) is fully conforming today, and a host that evicts the reservation exactly
when the spec says it may is also fully conforming. After eviction the identical
bundle re-presents with the identical `consume_nonces`, every unique-insert is
novel, step 2 of §7.3 says "proceed," and the replay succeeds with no deny
signal anywhere on the wire. Binding v2 (§4.1) closed the presenter's ability to
move `expiry`, so `retain_until` is now the only liveness parameter on the
replay path that is neither signed nor bounded, and it is chosen unilaterally by
the verifier.

**Why this wording closes it.** The fix is two obligations on two parties, each
placed where that party's rules already live.

- **Verifier (§3.2):** `retain_until` **MUST** be `>= effective_expiry`. Because
  the §9 `expired` check is strict, the last instant the proof is acceptable is
  `effective_expiry - 1`; a reservation that lasts through `effective_expiry`
  therefore covers the entire acceptable lifetime with no gap. Equality is
  sufficient and exact, which is why the bound is `>=` rather than `>`. Only the
  verifier can enforce this, since the host cannot see `effective_expiry` inside
  the opaque bundle.
- **Host (§7.3):** the host can only compare against a value it owns, and
  `now_unix` is that value (§2.1: the host "owns the time source"). A
  `retain_until <= now_unix` is a retention window that has ended before it
  began, so the host is told to fail closed before step 1, perform no inserts,
  and perform no action. It is routed through the existing §7.2 "fails the §3.4
  verdict schema" branch and the existing `schema_invalid` classification that
  §9 already names, so no new host classification is introduced. The trailing
  sentence restating no-early-eviction repeats an obligation §3.2 already
  carries, but it is repeated here because §7.3 is the section a host implementer
  reads when writing the storage layer.
- **Schema (§3.4):** `exclusiveMinimum: 0` mirrors the existing `now_unix`
  constraint in §2.2 and makes `0` and negative values schema-invalid, so a
  schema-validating host rejects the degenerate cases before any semantic check
  runs. The semantic `> now_unix` check cannot be expressed in the verdict schema
  because it depends on the request, which is why the §7.3 prose obligation is
  needed in addition.

**RFC 2119 choices.** Both new bounds are **MUST** because each one, if
violated, reopens a replay window with no deny signal: this is a security
invariant, not a quality preference. The host check is **MUST** rather than
**SHOULD** because a host that skips it accepts an `allow` whose reservation is
already void, which is the same class of failure as "record after proceeding,"
which the pinned text already marks **FORBIDDEN**. The verifier's **MUST NOT**
on `retain_until <= now_unix` is technically implied by the `>= effective_expiry`
bound (a live proof has `now_unix < effective_expiry`), but it is stated
explicitly so that the host-side check in §7.3 has a matching verifier-side
obligation to cite. No **SHOULD** or **MAY** is introduced.

Whether the reference `bolyra verify` verifier already emits a `retain_until`
equal to the credential's effective expiry requires maintainer verification
against the `bolyra verify` implementation in `integrations/cli`; the candidate
asserts this, but it is not visible in the pinned spec text and this diff does
not depend on it.

## Impact

**Published vectors.** The verdict envelope and every existing deny code are
untouched, so the existing host-conformance vectors are expected to remain
valid as-is. Two assumptions require maintainer verification against
`spec/fixtures/host-conformance/`: (1) no published allow vector carries a
`consume_nonces` entry with `retain_until` at or below `0`, which the tightened
§3.4 schema would now reject; (2) no published allow vector carries a
`retain_until` at or below the vector's `now_unix`, which the new §7.3 check
would now deny. The pinned §3.2 example uses `4102444800`, which satisfies both,
so the risk is limited to fixtures that chose a small placeholder.

**Accompanying vector artifact.** This diff MUST ship with one new
`host_behavior` vector, `host-deny-retain-until-not-in-future`: a stub verifier
exits `0` with an otherwise well-formed `allow` whose single `consume_nonces`
entry has `retain_until: 1`. That value passes the tightened schema
(`exclusiveMinimum: 0`) but is at or below any realistic `now_unix`, so it
exercises the §7.3 semantic check specifically rather than the schema. Expected
outcome: deny, no action performed, no nonce recorded, host classification
`schema_invalid`. The exact expectation encoding for the new vector requires
maintainer verification against the existing fixture format and §16.3, which
are not in the pinned excerpt. A second, optional vector with `retain_until: 0`
would pin the schema hunk independently and is RECOMMENDED but not required for
this finding. Adding a vector bumps the vector set from 0.7.0 and requires the
published conformance suite to be re-synced and re-released.

**Hunk offsets.** The `@@` line numbers are computed from the pinned text as
quoted; the context lines are the authoritative anchor, and an offset of a few
lines on the second and third hunks is expected if the pinned file's wrapping
differs from the excerpt.

**Wire compatibility.** No field is added, removed, or renamed; the request
envelope, verdict envelope, and §9 registry are unchanged, so wire version `1`
is preserved. The schema change is a tightening on a value that no correct
verifier ever emitted (a non-positive retention time). A verifier already
emitting `retain_until >= effective_expiry` is unaffected. A verifier emitting an
early `retain_until` was silently replayable and becomes visibly denied, which is
the intended fail-closed direction. The §15 changelog should receive a one-line
entry for this revision; §15 is outside the pinned excerpt and its exact format
requires maintainer verification.

**-02 relevance.** This is a direct input to the IETF draft's replay-protection
text: the draft's host-nonce mode inherits the same unbounded `retain_until`
gap, and the two-party bound (verifier ties retention to expiry, host rejects an
already-ended window) is the portable rule to carry into -02 alongside the
strict-expiry comparison it depends on.

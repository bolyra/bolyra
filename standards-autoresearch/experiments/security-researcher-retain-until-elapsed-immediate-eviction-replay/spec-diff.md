Base-Commit: 9bf754441ab36ab93992ed5936d34c44a4128f92
Target-File: spec/external-verifier-contract-v1.md
Finding: security-researcher-retain-until-elapsed-immediate-eviction-replay

```diff
--- a/spec/external-verifier-contract-v1.md
+++ b/spec/external-verifier-contract-v1.md
@@
 - **Status:** Stable (v1)
 - **Wire version:** `1` (integer-major; see §11)
-- **Document revision:** 2026-08-26 (registry closure and fail-closed
-  classification precedence made explicit — prose only, wire contract unchanged;
-  see the changelog in §15). Previous: 2026-07-17 (binding format **v2** —
+- **Document revision:** 2026-09-07 (`retain_until` lower bound — a host
+  rejects a nonce-retention deadline that is non-positive or already elapsed
+  relative to the request's `now_unix`; verdict-schema constraint plus host
+  obligation, envelope unchanged; see the changelog in §15). Previous:
+  2026-08-26 (registry closure and fail-closed classification precedence made
+  explicit), 2026-07-17 (binding format **v2** —
   expiry is now signature-bound), 2026-07-11 (§16 Host conformance). The wire
   request/verdict envelope major is unchanged; the **binding** sub-structure is
   versioned separately (v1 → v2, §4).
@@
   - `nonce` (string, **REQUIRED**) — the one-time value the host **MUST** record.
   - `retain_until` (integer, **REQUIRED**) — Unix seconds until which the host
-    **MUST** retain the consumed nonce.
+    **MUST** retain the consumed nonce. The value **MUST** be a positive integer
+    and **MUST** be strictly greater than the request's `now_unix` (§2.1): a
+    retention deadline that has already elapsed permits eviction at the instant
+    of insertion and therefore protects nothing. A verifier **SHOULD** set it no
+    earlier than the presentation's effective expiry, since a replay after that
+    point is already rejected by the strict-expiry rule (§9, `expired`). A host
+    **MUST** reject an entry whose `retain_until` is not strictly greater than
+    the `now_unix` the host itself wrote to stdin (§7.2, §7.3); it **MUST NOT**
+    treat such an entry as a satisfied reservation and **MUST NOT** repair it by
+    substituting a retention deadline of its own.
@@
             "properties": {
               "issuer_key": { "type": "string" },
               "nonce": { "type": "string" },
-              "retain_until": { "type": "integer" }
+              "retain_until": { "type": "integer", "exclusiveMinimum": 0 }
             }
@@
 - a verdict that otherwise fails the §3.4 verdict schema — including an
   unrecognized `kind` value (outside `classical` | `zk` | `external`, §3.5), a
   `code` outside the §9 registry, or any disallowed additional property.
+- in host nonce mode (§8), an `allow` whose `consume_nonces` contains an entry
+  with `retain_until` not strictly greater than the request's `now_unix`
+  (§3.2). The comparison is against the `now_unix` value the host wrote to
+  stdin, not against a fresh clock read, so the outcome is deterministic for a
+  given request. The host classifies this as its own fail-closed override
+  (`schema_invalid`, §16.3) — the same classification §9 assigns to an
+  out-of-registry `code` — never as a relayed verifier decision.
@@
 When the host runs the verifier in **host nonce mode** (§8) and receives
 `allow` with `consume_nonces`, the host **MUST** reserve **every** entry in the
 list **before** performing the privileged action:
 
+0. **Validate every entry before any insert.** If any `entry.retain_until` is
+   not strictly greater than the request's `now_unix` (§3.2), the host **MUST**
+   deny (§7.2) and **MUST NOT** insert any nonce from that verdict. A single
+   defective entry invalidates the whole verdict; there is no per-entry
+   partial acceptance.
 1. For **each** `entry` in `consume_nonces`, atomically insert `entry.nonce` into
    durable storage with a unique-insert / "on conflict reject" semantic,
    retaining it until `entry.retain_until`.
```

## Rationale

### What the pinned text permits

The verdict schema (§3.4) types the retention deadline with no lower bound:

> `"retain_until": { "type": "integer" }`

This is asymmetric with the request side, where the host's clock carries a bound:

> `"now_unix": { "type": "integer", "exclusiveMinimum": 0 }`

The only prose obligation attached to the field (§3.2) is:

> `retain_until` (integer, **REQUIRED**) — Unix seconds until which the host **MUST** retain the consumed nonce.

Read literally, the obligation ends at the named instant. A verdict such as

```json
{ "verdict": "allow", "kind": "classical",
  "consume_nonces": [ { "issuer_key": "k", "nonce": "n", "retain_until": 1 } ] }
```

passes the §3.4 schema, satisfies every §7.2 bullet, and reaches §7.3. Step 1 of §7.3 inserts the nonce "retaining it until `entry.retain_until`" — a deadline already in the past — so a host that garbage-collects on schedule is *conforming* when it evicts the row before the action completes. A second presentation of the same bundle then inserts the same nonce as novel, step 2 finds every insert novel, and the privileged action runs twice. No key is compromised, no proof is forged, and no vector in set 0.7.0 observes it: `host-deny-nonce-entry-wrong-type`, `host-deny-nonce-entry-extra-property`, and `host-deny-malformed-consume-nonce` all assert entry *shape*, none asserts a *value* bound.

The Tier 1 judgment noted that neither reference store demonstrates immediate eviction. That is true and is not a defense: §7.3 explicitly authorizes eviction at `retain_until`, so a third-party host that honors the contract as written (a TTL index keyed on `retain_until`, for example) is the exposed party. The contract layer is where the gap lives, so the contract layer is where it closes.

### Why this wording closes it

- **Two bounds, two mechanisms.** `exclusiveMinimum: 0` lands in the §3.4 schema because JSON Schema can express it and every schema-validating host picks it up mechanically; it kills the `0` / negative class. The elapsed class (`retain_until <= now_unix`) cannot be expressed in the verdict schema because it references the *request* document, so it is a prose **MUST** in §3.2, listed as a §7.2 fail-closed condition, and placed as step 0 of §7.3 so it runs before any insert.
- **Compared against the request's `now_unix`, not the host clock.** §2.1 already makes the host the time source ("the verifier **MUST** evaluate credential expiry against **this** value"). Reusing the same value for the retention bound keeps one clock in the protocol and makes the check reproducible from the request alone, which is what lets a conformance vector pin it as a golden.
- **Strict inequality.** `retain_until == now_unix` is a zero-length retention window at the exact second the request was stamped; a re-presentation with the same `now_unix` would be inserted as novel. Strictness matches §9's `expired` row, where the equality boundary is likewise rejected.
- **Fail closed, not repair.** A host could plausibly "fix" a defective entry by clamping `retain_until` upward. The diff forbids it. Under §7.2 an out-of-registry `code` is treated as a malfunctioning or hostile verifier whose output the host must not relay; a nonsensical retention deadline is the same signal, and a verifier that cannot produce a sane `retain_until` cannot be trusted to have produced a sane `allow`. Validate-first (step 0) also prevents a half-reserved state.
- **Whole-verdict rejection.** One defective entry among several means the host cannot know which reservations the verifier intended to be load-bearing; rejecting the verdict is the only outcome that does not require the host to reason about the verifier's internals, which §1 forbids.

### RFC 2119 choices

- **MUST** (host rejects `retain_until <= now_unix`; host does not insert; host does not repair): this is a replay-protection invariant, it is observable from the wire alone, and it is testable by a hostile fixture. Anything weaker leaves the fail-open path spec-compliant.
- **MUST** (verifier emits a positive value strictly greater than `now_unix`): the symmetric producer obligation. Without it a verifier emitting an elapsed deadline would be conforming while the host is required to reject its output; stating both sides removes that contradiction. No existing conforming verifier can be harmed because an elapsed deadline was never a meaningful instruction.
- **SHOULD** (verifier sets `retain_until` no earlier than effective expiry): the host cannot verify this (effective expiry is inside the opaque bundle) and the conformance suite cannot pin it, so a MUST would be an untestable normative statement. It is recorded as guidance because it names the natural correct value: the strict-expiry rule already denies any presentation at or after effective expiry, so retention past that point buys nothing and retention short of it reopens a window.
- **MUST NOT** (treat as satisfied reservation; substitute a deadline): both phrased as prohibitions because they name the two specific shortcuts an implementer is most likely to reach for.

## Impact

### Published vectors (set 0.7.0)

**No existing vector changes.** Every published `allow`-with-`consume_nonces` vector uses a far-future retention deadline (the §3.2 example value `4102444800`, year 2100) that is strictly greater than any request `now_unix` in the set, so the new bound is satisfied by all current goldens. The three existing entry-shape vectors are unaffected: they already expect a host deny and the new check is ordered after shape validation.

**Two new host-behavior vectors MUST accompany this diff** in the hostile-fixture host-conformance suite, with regenerated goldens and a vector-set version bump (new host obligations, so minor: 0.7.0 → 0.8.0), mirrored into the vendored `@bolyra/evc-conformance` snapshot:

| Vector | Fixture behavior | Expected host outcome |
|---|---|---|
| `host-deny-retain-until-elapsed` | Exits 0; stdout is a schema-valid `allow` with one `consume_nonces` entry whose `retain_until` equals the request's `now_unix` (the boundary case, which a strict comparison rejects and an off-by-one `>=` implementation wrongly accepts) | deny; classification `schema_invalid`; privileged action not performed; no nonce inserted |
| `host-deny-retain-until-nonpositive` | Exits 0; stdout is an otherwise-valid `allow` with one entry whose `retain_until` is `0` | deny; classification `schema_invalid`; privileged action not performed; no nonce inserted |

Both fixtures are single-run: the host must fail closed on the first presentation, so no second-run replay observation is needed to detect a non-conforming host. A host that passes 0.7.0 today and merely ignores `retain_until` fails both, which is the intended discriminator.

### Wire compatibility

- Request envelope (§2): unchanged.
- Verdict envelope (§3): shape unchanged. The only schema delta is a lower bound on an existing REQUIRED integer field. Wire version stays `1`; this is a host-side validation tightening of the same kind the 2026-08-26 revision made for out-of-registry `code`, not a new field or a renamed one.
- Verifiers: any verifier already emitting a positive, future `retain_until` is unaffected. A verifier emitting a non-positive or elapsed value was already defeating the stated purpose of §3.2 and now receives a deterministic host deny instead of a silent replay window.
- Hosts: a host that validates only against the §3.4 schema picks up the non-positive bound automatically; the elapsed bound requires the one-line comparison added at §7.3 step 0. Reference hosts (`spec/reference-host-rs`, `spec/conformance-runner.js`) and hosted-verify need the same comparison to stay green against the new vectors.

### Companion edits implied by this diff

- A matching §15 changelog line and a §16 coverage-map row for the new §3.2/§7.2 MUSTs (pinned §15/§16 text is not reproduced in this excerpt, so those hunks are not shown here; they carry no normative content beyond what the hunks above introduce).
- `spec/CONFORMANCE.md` vector index entries for the two vectors above.

### -02 relevance

The -02 draft of the IETF-style document should carry `exclusiveMinimum: 0` into its verdict schema and state the elapsed-deadline host obligation alongside reserve-before-act. This diff adds two normative MUSTs that are each covered by a named vector, so it raises spec-hardness coverage rather than adding uncovered normative text, and it removes a CONFIRMED open finding from the security-researcher persona. It is the kind of fail-closed tightening an IETF security-area reviewer would otherwise raise as a DISCUSS-level comment on a nonce-consumption protocol: a retention deadline the consumer is required to honor but the producer is never required to make meaningful.

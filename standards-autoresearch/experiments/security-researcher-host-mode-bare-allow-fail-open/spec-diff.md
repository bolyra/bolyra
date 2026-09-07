Base-Commit: a4f546f3279706a2b28a0c15569c0040425e84c7
Target-File: spec/external-verifier-contract-v1.md
Finding: security-researcher-host-mode-bare-allow-fail-open

# Staged spec change: host nonce mode — a bare `allow` is fail-closed

**Status:** staged for founder review (not applied by the loop).
**Re-validate the base:** `git log -1 --format=%H -- spec/` must print
`a4f546f3279706a2b28a0c15569c0040425e84c7`. All three diffs below were
regenerated with `git diff` in a detached worktree of that commit and each
returns clean from `git apply --check` against it (verified 2026-09-06 while
staging): spec diff **11 hunks**, `reference-host.js` diff **1 hunk**,
`reference-host-rs/src/lib.rs` diff **1 hunk** — 88 insertions, 18 deletions
across the three files.

## Spec diff

```diff
diff --git a/spec/external-verifier-contract-v1.md b/spec/external-verifier-contract-v1.md
index c88b005..347cf75 100644
--- a/spec/external-verifier-contract-v1.md
+++ b/spec/external-verifier-contract-v1.md
@@ -2,9 +2,10 @@
 
 - **Status:** Stable (v1)
 - **Wire version:** `1` (integer-major; see §11)
-- **Document revision:** 2026-08-26 (registry closure and fail-closed
-  classification precedence made explicit — prose only, wire contract unchanged;
-  see the changelog in §15). Previous: 2026-07-17 (binding format **v2** —
+- **Document revision:** 2026-09-06 (host nonce mode: a bare `allow` without
+  `consume_nonces` is fail-closed — prose + conformance only, wire contract
+  unchanged; see the changelog in §15). Previous: 2026-08-26 (registry closure
+  and fail-closed classification precedence), 2026-07-17 (binding format **v2** —
   expiry is now signature-bound), 2026-07-11 (§16 Host conformance). The wire
   request/verdict envelope major is unchanged; the **binding** sub-structure is
   versioned separately (v1 → v2, §4).
@@ -176,9 +177,13 @@ human-uniqueness nullifier when the bundle is human-backed (the human entry's
 }
 ```
 
-- `consume_nonces` (array of objects, **OPTIONAL**, allow-only). When present it
-  is a **non-empty** list (the key is omitted entirely when there is nothing to
-  burn). The host **MUST** reserve-before-act **EACH** entry (§7.3). Each entry:
+- `consume_nonces` (array of objects, **OPTIONAL** in the schema, allow-only).
+  When present it is a **non-empty** list (the key is omitted entirely when there
+  is nothing to burn — a valid outcome **only** in local nonce mode: in host
+  nonce mode an otherwise-allow with nothing to burn is `deny code=nonce_missing`,
+  §8, and a host running in host nonce mode **MUST** treat a bare `allow` as
+  fail-closed, §7.4). The host **MUST** reserve-before-act **EACH** entry (§7.3).
+  Each entry:
   - `issuer_key` (string, **REQUIRED**) — the issuer/operator key that scopes the
     nonce namespace. For host bookkeeping only; the `nonce` is already globally
     unique (§8).
@@ -532,6 +537,28 @@ list **before** performing the privileged action:
 "Record after proceeding" is a replay window and is **FORBIDDEN**. The verifier's
 `allow` in host mode is **conditional** on every host insert being novel.
 
+### 7.4 Host nonce mode: a bare `allow` is fail-closed
+
+In host nonce mode the verifier persists nothing (§8), so the host's §7.3
+reservation is the **only** durable replay record. An `allow` that carries **no**
+`consume_nonces` gives the host nothing to reserve; an action authorized on it is
+replayable until the credential expires with **no** party holding a nonce. Such a
+verdict cannot come from a conforming host-mode verifier — a presentation with
+nothing to burn is `deny code=nonce_missing` (§8, §9). A bare `allow` reaching a
+host that spawned the verifier in host nonce mode therefore means the verifier did
+not honor the mode: a local-mode verifier misconfigured as host mode, or a
+verifier (of any `kind`, §3.5) without nonce support.
+
+A host that runs the verifier in host nonce mode **MUST** treat an `allow` verdict
+that lacks `consume_nonces` as a fail-closed **deny** (classified
+`nonce_unconsumed`, §16.3) and **MUST NOT** perform the action. The host
+**MUST NOT** fall back to local-mode semantics for such a verdict and **MUST NOT**
+relax this rule on the basis of `kind` (§3.5). The check is on the verdict
+*shape* alone; it requires no knowledge of the bundle.
+
+In local nonce mode a bare `allow` remains the ordinary allow verdict (§3.1);
+this section imposes nothing on a local-mode host.
+
 ## 8. Replay protection modes
 
 A verifier supports one of two replay modes, selected by the host at spawn time
@@ -551,6 +578,10 @@ A verifier supports one of two replay modes, selected by the host at spawn time
   delegation nullifier is bound to the agent's session nonce, so reserving the
   agent nullifier already covers delegation replay. This is the mode for
   multi-host / clustered deployments where the host already owns a database.
+  In this mode every `allow` **MUST** carry `consume_nonces`: an otherwise-allow
+  presentation that has no one-time nullifier to hand over **MUST** be rejected
+  `deny code=nonce_missing` (§9), never returned as a bare `allow`. The host-side
+  counterpart is §7.4 — a bare `allow` under host nonce mode is fail-closed.
 
 The agent nonce value is globally unique per (credential, session-nonce), so no
 separate operator namespacing is needed; `consume_nonces[].issuer_key` is provided
@@ -591,7 +622,7 @@ wording in a row's *Meaning* is illustrative of the `zk` class, not exclusive.
 | `unknown_capability` | a requested capability has no scope mapping (fail-closed; unmapped is never silently allowed). |
 | `scope_exceeded` | the capability-required permission bits are not a cumulative-bit subset of the proven effective scope. |
 | `expired` | proof-anchored `now_unix >= effective_expiry` — a **strict** comparison; the equality boundary is rejected. |
-| `nonce_missing` | the proof lacks a usable `nullifierHash` / `sessionNonce` signal. |
+| `nonce_missing` | the proof lacks a usable `nullifierHash` / `sessionNonce` signal — including, in host nonce mode (§8), an otherwise-allow presentation with no nonce to hand to the host. |
 | `nonce_replayed` | the proof's one-time nonce was already seen (local mode). |
 | `internal_error` | unexpected failure, missing circuit artifacts, or missing trust configuration. Emitted as a deny **and** with a non-zero exit code. |
 
@@ -610,7 +641,8 @@ opaque throughout; the host never parses proofs.
 3. **Read** exactly one JSON verdict from the child's stdout under the strict
    single-object rule (§5.2), enforcing the host timeout (§6).
 4. **Decide, fail-closed** (§7): `allow` → proceed (and, in host nonce mode,
-   reserve-before-act EVERY `consume_nonces` entry, §7.3); anything else — `deny`, non-zero
+   reserve-before-act EVERY `consume_nonces` entry, §7.3 — a host-mode `allow`
+   with **no** `consume_nonces` is itself a deny, §7.4); anything else — `deny`, non-zero
    exit, timeout, signal death, unparseable/oversized/multi-object stdout, unknown
    verdict, or a verdict that fails §3.4 schema validation (e.g. an unrecognized
    `kind`) — → reject.
@@ -633,6 +665,8 @@ if not valid_verdict_schema(verdict):          reject("schema invalid")  // §3.
 
 switch verdict.verdict:
   case "allow":
+    if host_nonce_mode and verdict.consume_nonces is absent:
+      reject("nonce_unconsumed")                // §7.4: nothing to reserve → deny
     for entry in (verdict.consume_nonces or []):                         // §8 host mode
       if not reserve_nonce_atomically(entry): reject("replay")           // §7.3 (reserve ALL)
     proceed()
@@ -838,6 +872,23 @@ wire `version`. A wire-`1` verifier that predates an entry below — necessarily
 are read as `zk` (§3.3); a verifier that implements a revision as a non-`zk` class
 adopts that revision's obligations (e.g. it **MUST** set `kind`, §3.5).
 
+- **2026-09-06 (wire version `1`, prose + conformance only).** Closed a
+  host-mode fail-open. §3.2 permitted a bare `allow` "when there is nothing to
+  burn" while §8 host nonce mode makes the host's §7.3 reservation the only
+  durable replay record, so a bare `allow` under host nonce mode — from a
+  verifier that did not honor `--nonce-mode host`, or one without nonce support —
+  authorized an action for which nobody recorded a nonce; both reference hosts
+  did exactly this. New §7.4: a host in host nonce mode **MUST** treat an `allow`
+  without `consume_nonces` as a fail-closed deny (`nonce_unconsumed`, §16.3).
+  §8 states the verifier-side counterpart (a host-mode allow **MUST** carry
+  `consume_nonces`; nothing to burn is `nonce_missing`), §3.2 scopes "nothing to
+  burn" to local mode, §9 widens the `nonce_missing` meaning accordingly, and
+  §10 gained the check. Conformance: added the `host-nonce-bare-allow-deny`
+  vector (the existing `well-behaved-allow.js` fixture under `nonce_mode: host`)
+  and the `nonce_unconsumed` failure class (vector set 0.6.0 → 0.7.0). The wire
+  contract is unchanged; no conforming verifier is affected — the reference
+  verifier already denies `nonce_missing` in host mode rather than emitting a
+  bare `allow`.
 - **2026-08-26 (wire version `1`, prose + conformance only).** Made two
   behaviors the §3.4 schema and reference hosts already had explicit in prose,
   after the first independent external host implementation missed both: §7.2 now
@@ -1038,6 +1089,7 @@ always **deny**; the failure class is the finer-grained assertion.
 | `oversize_stdout` | stdout exceeded the host output bound (§6) |
 | `schema_invalid` | a parsed verdict failed the §3.4 verdict schema |
 | `replay` | a `consume_nonces` entry was already reserved (§7.3) |
+| `nonce_unconsumed` | host nonce mode, but the `allow` carried no `consume_nonces` — nothing to reserve (§7.4) |
 | `spawn_error` | the host could not spawn or drive the verifier at all |
 
 Because several §7.2 conditions can co-occur for one input, a vector **MAY** admit
@@ -1072,7 +1124,8 @@ the observable parts of this testable with two side channels — the durable non
 store (`HUT_NONCE_STORE`, proving the reservation was written) and the **action
 log** (`HUT_ACTION_LOG`, the observable proxy for "the action": the host appends a
 marker only when it authorizes, §16.2). Three vectors drive the
-`allow-consume-nonces*` fixtures in host nonce mode:
+`allow-consume-nonces*` fixtures in host nonce mode, and a fourth drives the
+bare-allow positive-control fixture under the same mode:
 
 - **`host-nonce-reserve-novel-allow`** — the store starts empty. The verifier
   returns `allow` with `consume_nonces`. *Observable assertion:* the decision is
@@ -1092,11 +1145,20 @@ marker only when it authorizes, §16.2). Three vectors drive the
   entry and rejecting on **any** conflict, a conforming host **MUST** deny
   (`replay`) with no action taken, proving it reserves the whole list rather than
   short-circuiting on the first novel entry.
-
-**Scope and limits.** As a black-box harness the suite proves three things: the
+- **`host-nonce-bare-allow-deny`** — the store starts empty and the verifier is
+  the same `well-behaved-allow.js` that `host-allow-well-behaved` relays as
+  `allow` in local mode, but the host runs in host nonce mode. A conforming host
+  **MUST** deny (`nonce_unconsumed`) **and MUST NOT authorize** — the action log
+  stays empty (`action_taken: false`) and the store stays empty. *Observable
+  assertion:* the same bare `allow` that is a valid allow in local mode is a
+  fail-closed deny under host mode, proving the host refuses to authorize when it
+  has nothing to reserve (§7.4).
+
+**Scope and limits.** As a black-box harness the suite proves four things: the
 reservation is durably written (novel case), authorization is gated on the durable
-uniqueness check (replay case, the primary guarantee), and every entry is checked
-(reserve-all case). It does **not** prove the fine-grained *intra-allow-path*
+uniqueness check (replay case, the primary guarantee), every entry is checked
+(reserve-all case), and authorization is refused when there is nothing to reserve
+(bare-allow case). It does **not** prove the fine-grained *intra-allow-path*
 ordering — that within a single `allow` the durable write is committed strictly
 **before** the action marker — because distinguishing "reserve then act" from "act
 then reserve, both before returning `allow`" would require fault injection (a crash
```

## Rationale

### The divergence the current text permits

Three pinned passages combine into a silent fail-open:

- §3.2 (allow-only field): *"`consume_nonces` (array of objects, **OPTIONAL**,
  allow-only). When present it is a **non-empty** list (the key is omitted
  entirely when there is nothing to burn)."*
- §8 (host mode): *"The verifier does **not** persist nonces. On an
  otherwise-allow it returns `consume_nonces` (§3.2) … and the host owns durable
  storage under the reserve-before-act rule (§7.3)."*
- §7.3 is gated on receipt: *"When the host runs the verifier in **host nonce
  mode** (§8) and receives `allow` with `consume_nonces`, the host **MUST**
  reserve **every** entry …"* — it says nothing about an `allow` **without** the
  field.

So in host nonce mode nobody persists a nonce unless the verifier hands one over,
and the spec text legitimises the hand-over being absent. A verifier that does
not honor `--nonce-mode host` — a local-mode spawn misconfigured as host mode, a
`classical`/`external`-`kind` verifier without nonce support, or a hostile
verifier that simply drops the field — returns `{"verdict":"allow"}`. That
verdict is schema-valid (§3.4), exit `0`, single object, so every §7.2 check
passes, and both reference hosts then authorize and record the action with an
empty nonce store. The same bundle replays until credential expiry with **no**
party holding a nonce and **no** signal to the operator. Reproduced against the
pinned reference host (`spec/reference-host.js` at a4f546f, host mode,
`well-behaved-allow.js` as the verifier): decision `{"decision":"allow"}`, no
nonce store created, action marker written. `spec/reference-host-rs/src/lib.rs`
lines 542–548 have the identical `if let Some(entries) = …` shape.

The contradiction the diff resolves: §9 already defines `nonce_missing` as *"the
proof lacks a usable `nullifierHash` / `sessionNonce` signal"*, and the reference
verifier already denies `nonce_missing` in host mode rather than emitting a bare
allow (`integrations/cli/src/verify/core.ts` step 11 always builds at least the
agent-nullifier entry; `requireNullifier` throws `nonce_missing` first). A
host-mode "nothing to burn" is therefore **already** a deny by the verifier's own
rules — the spec just never said so, and never told the host what a bare allow
under host mode means.

### Why this wording closes it

- **New §7.4** makes the host obligation explicit and *shape-only*: in host nonce
  mode an `allow` lacking `consume_nonces` is a fail-closed deny and the action
  is not performed. The host needs no bundle knowledge, keeps the bundle opaque
  (§1), and the check sits naturally beside §7.3 (which it completes: reserve
  before act, and if there is nothing to reserve, do not act).
- **§8 verifier counterpart** removes the ambiguity from the producer side: a
  host-mode `allow` carries `consume_nonces`, and nothing-to-burn is
  `nonce_missing`. This matches what the reference verifier already does, so no
  conforming verifier changes behavior.
- **§3.2 scoping** keeps the "omitted when nothing to burn" sentence (still true
  for local mode, and the JSON schema stays unchanged) but scopes it to local
  mode and cross-references §7.4/§8 so an implementer reading §3.2 alone cannot
  conclude a bare allow is valid in host mode.
- **§9 widening** of `nonce_missing` keeps the closed registry closed (no new
  code, no wire bump) while making the host-mode meaning explicit.
- **§10 step 4 + pseudocode** — the adoption path an outside implementer copies
  now carries the check; the first external host (§9 of `IMPLEMENTER.md`) was
  built from exactly this pseudocode, whose `verdict.consume_nonces or []`
  silently treated absence as an empty reservation list.
- **§16.3 `nonce_unconsumed` + §16.5 fourth vector** make the obligation
  testable with the *existing* positive-control fixture under a different mode,
  so the vector also proves the suite distinguishes the same verdict by mode.

### RFC 2119 choices

- **MUST** treat as deny / **MUST NOT** perform the action (§7.4): this is a
  replay-window closure in the same class as §7.3's *"FORBIDDEN"*; a SHOULD
  would leave the fail-open in every host that takes the lenient reading, which
  is the reading both reference hosts took.
- **MUST NOT** fall back to local-mode semantics / **MUST NOT** relax on `kind`
  (§7.4): mirrors §3.5's existing "`kind` is advisory, never relaxes a §7
  obligation" rule so the two sections cannot be played against each other.
- **MUST** carry `consume_nonces` / **MUST** deny `nonce_missing` (§8, verifier
  side): stated as MUST because the host-side rule only fail-closes correctly if
  a conforming verifier never produces the shape; a SHOULD would create a
  verifier that is "conforming" yet always denied under host mode.
- No new MAY/SHOULD is introduced; local-mode behavior is stated as unchanged
  in plain prose (§7.4 last paragraph) rather than with a keyword, since it
  imposes nothing.
- A new **failure class**, not a new **denial code**: the deny is the host's own
  fail-closed decision (§16.2 shape `{"decision":"deny","failure_class":…}`), not
  a relayed verifier verdict, so the §9 registry and §3.4 schema stay closed and
  unchanged.

## Impact

### Published vectors (28 → 29; vector set 0.6.0 → 0.7.0)

None of the 28 published vectors changes meaning or expected outcome; the
`host-allow-well-behaved` positive control still relays `allow` because it runs
in local mode (`nonce_mode` defaults to `local`, runner line 631). This diff
**MUST ship with one new vector** and one schema enum row, otherwise §16.3/§16.5
reference a class and a vector that do not exist:

**`spec/test-vectors.json`** — bump `"version"` to `"0.7.0"` and insert after
`host-nonce-reserve-all-any-conflict-deny`:

```json
{
  "id": "host-nonce-bare-allow-deny",
  "description": "Host nonce mode, bare allow (§7.4/§16.5): the same well-behaved verifier that `host-allow-well-behaved` relays as `allow` in local mode returns a bare `allow` with NO consume_nonces, but the host-under-test runs in host nonce mode. The verifier persisted nothing and handed the host nothing to reserve, so authorizing would leave the presentation replayable with no party holding a nonce. A conforming host MUST fail closed (`nonce_unconsumed`) and MUST NOT authorize — the action log stays empty.",
  "type": "host_behavior",
  "inputs": { "fixture": "well-behaved-allow.js", "nonce_mode": "host", "timeout_ms": 5000 },
  "expected": { "result": "PASS", "host_decision": "deny", "failure_class": "nonce_unconsumed", "action_taken": false }
}
```

**`spec/conformance-schema.json`** — add `"nonce_unconsumed"` to
`$defs.failureClass.enum` (after `"replay"`). No new fixture file: the vector
reuses `well-behaved-allow.js`.

Verified 2026-09-06 in a detached worktree of a4f546f (never in the live
`spec/`): the patched vector set (113 vectors, 29 `host_behavior`) validates
against the patched schema (ajv 2020 from `integrations/cli/node_modules`);
`node spec/conformance-runner.js --type host_behavior` against the **unpatched**
`spec/reference-host.js` scores `28 passed, 1 failed, 0 skipped` with the single
failure being `host-nonce-bare-allow-deny: FAIL -- host decision mismatch: got
'allow', want 'deny'`; with the companion host fix below applied it scores
`29 passed, 0 failed, 0 skipped`.

### Companion reference-host fixes (both hosts, one hunk each)

The spec diff makes both pinned reference hosts non-conforming until these land.
Both diffs were regenerated against a4f546f and pass `git apply --check` there.

```diff
diff --git a/spec/reference-host.js b/spec/reference-host.js
index a8a9c45..c78741e 100644
--- a/spec/reference-host.js
+++ b/spec/reference-host.js
@@ -114,7 +114,12 @@ function decide(stdoutStr, finish) {
     return finish({ decision: 'deny', code: v.code }); // relay the verifier deny
   }
   // allow
-  if (nonceMode === 'host' && Array.isArray(v.consume_nonces)) {
+  if (nonceMode === 'host') {
+    // §7.4: in host nonce mode the host's reservation is the ONLY durable replay
+    // record, so an allow with nothing to reserve is fail-closed, never acted on.
+    if (!Array.isArray(v.consume_nonces)) {
+      return finish({ decision: 'deny', failure_class: 'nonce_unconsumed' });
+    }
     if (!reserveAll(v.consume_nonces)) {
       return finish({ decision: 'deny', failure_class: 'replay' });
     }
```

`spec/reference-host-rs/src/lib.rs` (lines 542–548 at a4f546f), same shape:

```diff
diff --git a/spec/reference-host-rs/src/lib.rs b/spec/reference-host-rs/src/lib.rs
index 5d7effa..513e19b 100644
--- a/spec/reference-host-rs/src/lib.rs
+++ b/spec/reference-host-rs/src/lib.rs
@@ -540,10 +540,13 @@ fn decide(cfg: &Config, stdout: &[u8]) -> Decision {
     }
     // allow
     if cfg.host_nonce_mode {
-        if let Some(entries) = verdict.get("consume_nonces").and_then(Value::as_array) {
-            if !reserve_all(cfg.nonce_store.as_deref(), entries) {
-                return Decision::DenyClass("replay");
-            }
+        // §7.4: in host nonce mode the host's reservation is the ONLY durable
+        // replay record, so an allow with nothing to reserve is fail-closed.
+        let Some(entries) = verdict.get("consume_nonces").and_then(Value::as_array) else {
+            return Decision::DenyClass("nonce_unconsumed");
+        };
+        if !reserve_all(cfg.nonce_store.as_deref(), entries) {
+            return Decision::DenyClass("replay");
         }
     }
     record_action(cfg.action_log.as_deref()); // reserve-before-act: only now
```

Verified 2026-09-06 in the same detached worktree: the patched crate builds
(`cargo build --release`, edition 2021, no warnings), `cargo test` reports
`52 passed; 0 failed`, and the patched `evc-reference-host` binary scores
`29 passed, 0 failed, 0 skipped` when passed as an **absolute path** via
`HOST_CMD` (a relative `target/release/...` path fails every vector with
`spawn_error` because the runner spawns from a temp cwd — runner artifact, not a
host defect). The **unpatched** Rust binary, rebuilt from the pinned `lib.rs`,
scores `28 passed, 1 failed` with the same single `host-nonce-bare-allow-deny`
mismatch, confirming both reference hosts were fail-open. (A `#[test]` mirroring
`run_local_mode_ignores_consume_nonces` at lib.rs:1083 — host mode +
`{"verdict":"allow"}` → `DenyClass("nonce_unconsumed")`, no action marker — is
the natural in-process companion; not included in the staged diff.)

### Downstream surfaces that move with a vector bump

- `spec/CONFORMANCE.md` — regenerated report (header *Spec version*, host table
  28 → 29).
- `integrations/evc-conformance/` — `node integrations/evc-conformance/scripts/sync.js`
  re-vendors runner/host/vectors/fixtures; CI `sync:check` fails until run. The
  package README's "28 `host_behavior` vectors" and `spec/IMPLEMENTER.md` lines
  25/30 (*"28 host-behavior vectors"* / *"28 passed, 0 failed, 0 skipped"*)
  become 29. Publishing @bolyra/evc-conformance 0.3.0 is a **separate** founder
  decision (release freeze, CLAUDE.md); the staged change is complete without it.
- **External implementation impact (flag, do not contact):**
  `khandrew1/mcp-use-evc-example` passes 27/27 at vector set 0.5.0; a host built
  from the §10 pseudocode has the same lenient shape and will fail the new
  vector until it adds the one-line check. This is the intended effect — the
  vector exists to surface exactly this gap — but the IMPLEMENTER.md §9 row
  stays pinned at 0.5.0 and is not to be edited on their behalf. The
  engagement-graph hold rules apply; no outreach is proposed here.

### Wire compatibility

- Wire version stays `1`. No change to the §2 request, the §3.4 verdict schema,
  or the §9 code registry (`nonce_missing` is an existing code; its row's
  *Meaning* is widened, not renamed). `consume_nonces` remains OPTIONAL in the
  schema because the schema is mode-agnostic; the mode-conditional obligation
  lives in prose (§7.4/§8), matching how §7.3 is already expressed.
- Conforming verifiers are unaffected: the reference `zk` verifier already emits
  `consume_nonces` on every host-mode allow. A `classical`/`external` verifier
  that has no nonce to hand over was already required by §9 to deny
  `nonce_missing`; the diff removes the sentence it could have hidden behind.
- Conforming hosts in **local** mode are unaffected. Hosts in **host** mode gain
  one shape check; hosts that were relying on a bare allow in host mode were
  fail-open and are the target.
- Additive document revision per §15 policy; the §11 versioning rule (optional
  field with a defined default does not bump the major) is not even engaged,
  since no field changes.

### -02 relevance

Direct. The host-side fail-closed rules (§7.2, §7.3) are the material the -02
"host obligations" section is built from; §7.4 completes that set — every §7
condition is now a host-observable *shape* check with a §16.3 class and a
vector, which is the property an IETF reviewer will ask for (each MUST backed by
a test). It also removes an internal contradiction (§3.2 vs §8/§9) that an
`ietf-reviewer` pass would have flagged as a -02 blocker. SPEC HARDNESS gains
one more normative MUST covered by a vector; REGISTRY CLOSURE requires the
0.7.0 sync to land for the vector-set/spec version alignment check to stay
green.

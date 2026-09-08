Base-Commit: 9bf754441ab36ab93992ed5936d34c44a4128f92
Target-File: spec/external-verifier-contract-v1.md
Finding: security-researcher-timeout-kill-orphans-verifier-worker

```diff
--- a/spec/external-verifier-contract-v1.md
+++ b/spec/external-verifier-contract-v1.md
@@ header block @@
 - **Status:** Stable (v1)
 - **Wire version:** `1` (integer-major; see §11)
-- **Document revision:** 2026-08-26 (registry closure and fail-closed
-  classification precedence made explicit — prose only, wire contract unchanged;
-  see the changelog in §15). Previous: 2026-07-17 (binding format **v2** —
+- **Document revision:** 2026-09-07 (timeout termination scope: the host's
+  timeout kill covers the verifier's entire process tree, and a verifier's
+  worker must stay inside that scope — prose only, wire contract unchanged;
+  see the changelog in §15). Previous: 2026-08-26 (registry closure and
+  fail-closed classification precedence made explicit), 2026-07-17 (binding format **v2** —
   expiry is now signature-bound), 2026-07-11 (§16 Host conformance). The wire
   request/verdict envelope major is unchanged; the **binding** sub-structure is
   versioned separately (v1 → v2, §4).
@@ ## 5. stdout / stderr / fd-level isolation (load-bearing) — §5.1 Verifier obligations @@
   - If the private verdict channel cannot be established on the platform, the
     verifier **MUST** fail closed (`deny code=internal_error`, non-zero exit) —
     it **MUST NOT** silently fall back to sharing fd 1.
+  - The worker, and any process the worker spawns, **MUST** remain inside the
+    termination scope the host placed the command in (§6, "Termination scope"):
+    it **MUST NOT** create a new session, detach, daemonize, or otherwise leave
+    the host's process group / job. This guarantees that the host's timeout
+    kill reaches the process that is actually performing verification — and,
+    in local nonce mode (§8), the process that would durably burn the nonce.
+  - The parent **SHOULD** additionally arrange for the worker to terminate when
+    the parent itself is terminated (a parent-death signal where the platform
+    offers one, or a worker that exits promptly when its fd 3 write end reports
+    a closed peer), so that even a host that signals only the direct child PID
+    cannot leave verification running after it has denied.
 - An in-process `dup2`-style redirect (duplicate fd 1, point fd 1 at stderr during
   verification, write the verdict via the duplicate) is an equally acceptable
   realization where the platform exposes the primitive. The process-isolation form
   is the reference implementation and is strictly stronger (it also captures native
   writes).
@@ ## 6. Timeout and input bounds @@
 - **Timeout.** The **host owns the timeout**. The verifier does not implement its
   own. The host **MUST** enforce a wall-clock timeout on the spawned process and
   treat expiry as deny (§7). The **RECOMMENDED** timeout is **10 000 ms** (10 s):
   the verifier targets < 2 s p99 (cold start + library load + a handful of Groth16
   verifies), and 10 s leaves ample headroom.
+- **Termination scope.** A conforming verifier command **MAY** be a
+  multi-process program (the reference mechanism in §5.1 is a parent plus a
+  worker on fd 3), so "the process" the host kills on timeout (§7.2) is the
+  **entire process tree** rooted at the spawned command, not the direct child
+  alone. On timeout the host **MUST** terminate every process in that tree —
+  the direct child **and all of its descendants** — using a primitive that
+  reaches descendants: a dedicated process group or session on POSIX, a job
+  object on Windows, or an equivalent facility. Signalling only the direct
+  child's PID is **NOT** conforming. The host **MUST** spawn the verifier so
+  that such a primitive applies (for example as the leader of a fresh process
+  group), and **MUST NOT** rely on the verifier to clean up after itself.
+- **Post-kill behavior.** The host **MUST** deny whether or not termination
+  succeeds, and **MUST** bound the time it waits after the kill for the tree
+  to be reaped or for stdout to reach EOF (the **RECOMMENDED** bound is
+  **1 000 ms**). A stdout write end inherited by a descendant that outlives
+  the kill **MUST NOT** extend the host's timeout or block its decision. A
+  host that reports the cause (§16.3) **SHOULD** classify the run as its own
+  timeout kill (§7.2 precedence) and **SHOULD** log a descendant that survives
+  the reap window as a verifier defect. Any nonce a surviving descendant burns
+  after the host has denied is a consequence of the verifier's non-conformance
+  with §5.1, not of the host's decision; the host's obligation is to terminate
+  the tree, not to un-burn a nonce it never saw.
 - **stdin bound.** The verifier **MUST** bound the request read from stdin. The
   reference limit is **1 MiB** (1 048 576 bytes). A request over the bound **MUST**
   yield `deny code=malformed_input`; the verifier **MUST NOT** buffer an unbounded
   request.
@@ ### 7.2 Host fail-closed obligations @@
 - non-zero exit code;
-- timeout (§6) — the host **MUST** kill the process and deny;
+- timeout (§6) — the host **MUST** terminate the verifier's entire process tree
+  (§6, "Termination scope") and deny;
 - death by signal / crash;
```

## Rationale

**The divergence the pinned text permits.** §7.2 states the timeout obligation as
"the host **MUST** kill the process and deny" — singular, unqualified. §5.1
simultaneously mandates, as the reference mechanism, that "the command **spawns a
worker** process that performs the entire verification" with "fd 3 = the private
verdict channel". Read together, a host that satisfies §7.2 literally — one
`SIGKILL` to the PID it spawned, the default idiom of `child.kill()`,
`Child::kill()`, and `Popen.kill()` — has killed the parent that does *nothing but
relay a verdict*, and has left running the worker that holds the full request in
memory and is performing the verification. Nothing in the pinned text forbids
this; the grep in the candidate's evidence (`process group`, `descendant`,
`orphan`, `setsid`, `killpg`: no matches at the base commit) confirms the contract
is silent on descendants.

**The consequence.** In local nonce mode (§8) the verifier "burns the proof's
one-time nonce locally" on an otherwise-allow, and that burn is **durable**: §9
defines `nonce_replayed` as "the proof's one-time nonce was already seen (local
mode)". An orphaned worker therefore completes verification *after* the host has
already denied on timeout and burns the presentation's nullifier. The agent's
legitimate retry of the same presentation is then rejected `nonce_replayed`.
Because the timeout is wall-clock (§6) and verification cost scales with bundle
content (a bundle under the 1 MiB bound can carry many Groth16 verifies), an
attacker who can shape the bundle or load the host turns each timeout into a
one-shot burn of the victim's nonce — a denial that persists across retries,
which is the opposite of what the host's timeout deny intends. The secondary
effects (orphan accumulation across repeated timeouts; a grandchild holding the
inherited fd-1 write end keeping a read-until-EOF host loop open past its own
deadline) are also unaddressed by the pinned text.

**Why this wording closes it.**

- *§6 "Termination scope"* defines "the process" for the purpose of §7.2 as the
  whole tree and names the primitives (process group / session / job object)
  that actually reach descendants. It also obligates the host to spawn in a way
  that makes the primitive applicable, because a group kill against a child that
  inherited the host's own group would either miss the tree or hit the host.
- *§6 "Post-kill behavior"* closes the fd-inheritance hang: the host's decision
  is denied and bounded regardless of whether a straggler keeps stdout open.
  The 1 000 ms reap bound is **RECOMMENDED**, not **MUST**, because the right
  value is deployment-specific; the *existence* of a bound is **MUST**.
- *§5.1* adds the verifier-side complement. A host tree-kill is only effective
  if the worker stays in the tree, so a worker leaving the host's group or
  session is made non-conforming (**MUST NOT**). Parent-death propagation is
  **SHOULD**, not **MUST**: it is defense in depth for legacy hosts, the
  primitive is platform-uneven, and the normative fix lives on the host side.
- *§7.2* is changed by the minimum needed to point at the new §6 definition, so
  the classification precedence text ("its own kills first (output bound, then
  timeout)") is untouched and the existing `timeout` classification remains the
  reported cause.

**RFC 2119 choices.** Tree termination is **MUST** on the host because the
failure mode is a durable, user-visible false `nonce_replayed` against an honest
agent — a correctness defect of the fail-closed design, not an optimization.
Worker containment is **MUST NOT** on the verifier because a detaching worker
defeats a conforming host silently. The reap bound value and the parent-death
signal are **RECOMMENDED/SHOULD** because they are quality-of-implementation
choices where a stricter word would over-constrain platforms without improving
the security property.

**Residual, stated honestly.** A race remains between a worker that has just
burned the nonce and a kill that lands before the verdict crosses fd 3. That
window is inherent to any design that burns before emitting, is
sub-millisecond rather than the full remaining verification time, and resolves
**fail-closed** (a burned nonce plus a host deny). This diff does not attempt to
eliminate it; it eliminates the unbounded orphan window, which is the finding.

## Impact

**Published vectors.** No existing vector in set 0.7.0 changes. The two timeout
vectors named in the candidate (`host-deny-no-output-timeout`,
`host-deny-partial-json-timeout`) assert only the deny and its classification,
which this diff preserves. The template for this artifact cites 28 published
vectors while the repository description cites 29 for set 0.7.0; the exact count
requires maintainer verification against `spec/fixtures/host-conformance/`.

**Accompanying vector (required).** This diff introduces a host **MUST** that no
current vector exercises, so it must ship with a new `host_behavior` vector,
`host-deny-timeout-kills-verifier-tree`: the fixture verifier is a parent that
spawns a grandchild which inherits fd 1, sleeps past the host's deadline, and
then writes a sentinel file; the expected outcome is a deny classified as the
host's timeout kill **and** absence of the sentinel after a bounded observation
window (the §6 reap bound plus the fixture's sleep, so the runner never waits
unboundedly). Whether the current fixture schema and runner can express a
post-condition over filesystem state, and how the observation window is bounded,
requires maintainer verification against `spec/conformance-runner.js` and the
fixture index for set 0.7.0. The Tier 1 judgment asserts that the pinned JS
runner signals only the child PID while the Rust reference host uses process
groups; that claim requires maintainer verification against
`spec/conformance-runner.js` and `spec/reference-host-rs` and, if confirmed,
the JS runner would fail the new vector until updated — which is the intended
effect of the vector, not a reason to weaken it.

**Wire compatibility.** None affected. The request envelope (§2), verdict
envelope (§3.4), binding v2 (§4), denial-code registry (§9), and exit-code
semantics (§7.1) are unchanged. Wire version stays `1`; only the document
revision line moves. A conforming verifier written against the previous revision
remains conforming unless its worker already detaches from the host's process
group, which no reference text ever permitted.

**Changelog.** A matching §15 entry for revision 2026-09-07 should accompany the
header change; §15 is not among the excerpts pinned here, so its exact wording
requires maintainer verification against the pinned file.

**-02 relevance.** The IETF-style draft's Security Considerations currently
inherit the "kill the process" phrasing by reference. The process-tree
termination scope and the verifier-side containment rule are -02 material: they
are the kind of host-obligation precision an IETF reviewer will demand once a
multi-process reference implementation is normative, and the accompanying vector
supplies the RFC 7942-style evidence that at least one independent host actually
implements it.

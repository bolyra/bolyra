# APPLY — security-researcher-signal-death-after-complete-allow (vector_gap)

Staged by standards-autoresearch on 2026-09-07. The loop never applies;
you do. Base commit (spec_finding only): ``

## Steps

1. Copy `fixture_js` (if present) to `spec/fixtures/host-conformance/<fixture_name>` (chmod +x).
2. Append the `vector` object to `spec/test-vectors.json` vectors[] and bump the vector-set MINOR version (additive).
3. `node spec/conformance-runner.js --type host_behavior` — all vectors incl. the new one must pass.
4. `node integrations/evc-conformance/scripts/sync.js`; plan an @bolyra/evc-conformance minor release (annotated tag).
5. CODEOWNERS gates these paths; commit with `git commit -s`.

## Codex Tier-3 verdict

```json
{
  "verdict": "APPROVE",
  "findings": [],
  "notes": [
    "Verified against spec pin a4f546f3279706a2b28a0c15569c0040425e84c7: \u00a7\u00a73.4, 5.1, 7.2 and 16.3 support the complete verdict and deny/signal_death expectation. Both JavaScript and Rust reference hosts distinguish signal death before parsing stdout.",
    "The 28 source and vendored host vectors and their fixtures match unchanged; the new ID does not collide. checks.json reports 29 passes. The merged execution was not independently rerun in this read-only review; integration requires an additive minor version bump.",
    "Editorial nits: \u00a75.1 discusses native stdout writes; \u00a77.2 supplies the crash obligation. The stderr comment should say it must not be parsed for a verdict. Qualify Python's negative returncode example as POSIX-specific, as documented in [Python subprocess](https://docs.python.org/3/library/subprocess.html#subprocess.Popen.returncode).",
    "Optional strengthening: expected.action_taken=false would also detect a host that authorizes prematurely but subsequently reports deny; the runner checks that side channel only when explicitly requested."
  ],
  "summary": "The additive vector covers a real signal-after-allow gap with an expectation derived from the pinned contract and consistent with both reference hosts."
}
```

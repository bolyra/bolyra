# APPLY — ietf-reviewer-vector-gap-explicit-kind-zk-allow-and-kind-on-deny (vector_gap)

Staged by standards-autoresearch on 2026-09-08. The loop never applies;
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
    "Verified against 9bf754441ab36ab93992ed5936d34c44a4128f92: \u00a7\u00a73.3\u20133.5 permit explicit kind=zk; \u00a716.3 requires positive-control verdict relay. Independent execution produced allow through both canonical and vendored JavaScript hosts; Rust source also accepts zk.",
    "All 28 set-0.6.0 host vectors and their fixtures remain unchanged. The current baseline contains 29 vectors at 0.7.0; this addition requires a minor version increase. The supplied check reports 30 passes; the complete suite was not independently rerun during this read-only review.",
    "This artifact closes explicit-zk allow coverage only; kind-bearing deny coverage remains outstanding.",
    "Wording nit: the parenthetical about \u00a77.2 should explicitly refer to its unrecognized-kind condition; \u00a77.2 also requires denial for other failures."
  ],
  "summary": "The additive positive control tests host behavior required by the pinned spec and is stageable as-is."
}
```

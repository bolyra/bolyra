# IETF draft-kondoju-evc-01 revision (Codex queue item 1, started 2026-08-27)

Goal: -01 source ready to submit to datatracker, Codex-reviewed. Founder does
the actual datatracker upload (account-bound).

- [ ] 1. Map -00: section structure, Implementation Status (RFC 7942), registry
      language, host fail-closed obligations, conformance counts, klrc/APS
      related-work citations
- [ ] 2. Create spec/draft-kondoju-evc-01.md from -00 (no archival comment),
      docname/date bump
- [ ] 3. Apply contract rev 2026-08-26 changes: §9 registry closure (replace
      "treat unrecognized future code as deny"), §7.2 classification precedence
- [ ] 4. Implementation Status: add khandrew1/mcp-use-evc-example (independent,
      27/27 pinned @ 17642a5 on 0.5.0, maintainer permission); update suite to
      vector set 0.6.0 / 28 host vectors / @bolyra/evc-conformance@0.2.0 npm w/
      provenance; JS+Rust reference hosts 28/28
- [ ] 5. Counts sweep (26 fixtures/27 vectors → 27/28) + "Changes since -00"
      appendix per IETF convention
- [ ] 6. Outline TODOs in scope? (klrc -03 section pinning, APS -02 quote) —
      research + pin or explicitly defer to -02
- [ ] 7. Build/validate (kramdown-rfc/xml2rfc if available; else manual lint)
- [ ] 8. Codex review loop to clean verdict; commit on branch; update memory

## Review
(fill when done)

## Review (2026-08-27)

Codex APPROVE after 4 revise rounds. Substantive finds along the way:
1. -00 shipped with a SYSTEMATIC cross-ref defect (26 wrong numeric refs from
   two late section insertions) — all now anchor-based, machine-audited.
2. -00 also shipped 4 internal "RESOLVED (founder)" blockquotes rendering in
   the public txt — deleted.
3. APS published draft-pidlisnyi-aps-03 on 2026-07-18 (we were citing -02;
   competitor watch trigger caught late). All our claims re-verified against
   -03: no-ZK-class still true; quote verbatim (their §9 now); "three-record"
   chain wording; their new Related Work §8 does NOT cite EVC.
4. Implementer-callout language neutralized everywhere per RFC 7942 norms.
5. Bracket-syntax hazards escaped (RFC-editor notes, consume_nonces[]).

Branch ietf-evc-01 (single commit) kept LOCAL deliberately: repo is public and
the -01 text should hit the datatracker before (or with) the repo. Founder
submits spec/draft-kondoju-evc-01.txt (or .xml) at
https://datatracker.ietf.org/submit/ — then push branch + PR + merge.

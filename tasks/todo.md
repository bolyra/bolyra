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

## Operator authorization trial (2026-09-13, Codex-ruled build, spec docs/superpowers/specs/2026-09-13-operator-trial-design.md)
- [x] Scaffold, versions, agents, config, echo (Chunk 1)
- [x] Audit with rollback, host with result channel, runTrial + CLI (Chunk 2)
- [x] README, landing/operator-trial.html, CI job, Linux lockfile (Chunk 3)
- [ ] Founder: deploy landing (`landing/deploy.sh`), add one link to the trial in the next outreach
- [ ] 30-day metric (from ship date): ≥1 external workflow owner emails a bundle from their own endpoint. Dry-runs and vendor runs do not count.

## Review (operator trial)
Hours spent: subagent-executed; founder hours ≈ 0 of the 20h cap. Deviations from spec: Task 7b hardening added after the chunk 2 quality review (host publishes a result on internal error so the run cannot hang; `committedBytes` read from the file via `statSync`; timeout/network_error pinned by tests); `gateway-config.ts` sets `receipts.issuer/keyId` because `createGatewayReceiptSigner` reads them; scan needles narrowed to substituted values (spec §3.3 updated to match); README/example/.gitignore hardened after the final review (URL path is recorded in receipts; `trial.yaml` ignored). Anything cut to stay under the cap: nothing; executed by subagents.

## §7.1 conformance coverage repair — SCHEDULED 2026-09-27 (Codex ruling 2026-09-22, scope corrected 2026-09-23)

**Window: 2026-09-27, first evening maintenance slot after the 9/26 gate outcome is
recorded. CAP: 4h total across 9/27-9/28, INCLUDING setup, documentation and
validation. Ranked FIRST in the maintenance backlog** (ahead of the release-workflow
registry-verify backoff and the remaining autoplan tasks). Stop at the cap and record
any remaining gap. **No suite engineering before 2026-09-26 21:00 ET.**

**The gap.** `verifier_envelope` cannot exercise §7.1's `internal_error` non-zero-exit
rule. The assertion ALREADY EXISTS at `spec/conformance-runner.js:587-589`; what is
missing is an input that reaches it. The old `null`-stdin probe worked by accident of
`typeof null === 'object'` and stopped working once implementers classified `null`
correctly.

**The inducer (contributed by stillmarcus24, 2026-09-23, issue #1 comments
`5797541484` + `5797726846`).** A *request* will not get there — the request cases he
investigated all turned out to be misclassifications he had to fix. The inducer is a
**config fault**: corrupt the verifier's own trust store, then send an otherwise valid
request. Verified by him on a clean clone at `1aa9d88`: `mkdir -p state && printf
'{ not json' > state/trusted-issuers.json` gives `deny internal_error` at **exit 1**;
remove the file and the same request returns `allow` at exit 0. **`mkdir -p` is
required — `state/` is gitignored, so a cold clone has no store to corrupt** (his own
correction, 11 min later).

**What does NOT generalize:** the request must carry a chain that actually verifies,
because the trust check runs after root recovery. The bundle is opaque per spec, so
each implementation supplies its own valid request. The vector asserts only the two
portable things: the config fault induces `internal_error`, and the exit is non-zero.

### Scope (Codex REJECTED "two mandatory vectors")
- [ ] **REQUIRED:** repair the §7.1 coverage gap with a configuration-fault fixture,
      implementation-specific setup where necessary.
- [ ] **OPTIONAL, same cap, only after the required repair:** a trust-configuration
      corruption *security diagnostic*. It must reproduce the authorization
      distinction: a cryptographically valid request that a healthy restrictive trust
      store DENIES must not become ALLOWED after corruption. **Not a required
      conformance vector** — making it one would import a normative rule the spec does
      not yet state.
- [ ] Controls, classification decisions, red/green proof, validation — all inside the cap.
- [ ] Deliver, then reply on issue #1 with the runnable vector (see below).

### Narrowing that must hold in the implementation (Codex, 2026-09-23)
- A config fault is a demonstrated inducer **for his implementation**. Nothing
  establishes that every verifier must label it `internal_error`. **Another verifier's
  different rejection must NOT automatically count as a failure**, and such a rejection
  does not count as exercised §7.1 coverage either.
- "No request vector will ever get there" is HIS finding about HIS investigated cases,
  not a proof of impossibility. Do not encode it as one.
- "§7.1 fixed at `1aa9d88`" holds for the pin and paths checked, nothing broader.
- "Our suite covers §7.1" stays FALSE until this repair actually runs.

### Reply to stillmarcus24 — goes WITH the vector, not before
Codex: nothing supplied requires an earlier comment; his own instruction ("send the
§7.1 vector when it runs") supports that timing. In the delivery comment: brief
acknowledgment and accurate attribution for the inducer and for his correction to his
own recipe. **No effusive praise, no new promise, no expanded deliverable. Do not work
past the cap to have something satisfying to send him** — gratitude is harmless,
repayment through extra work is the risk.

### Two spec findings — RECORDED, DEFERRED, no work authorized
Standards cap is spent; "cheap documentation" is still scope and this evidence does not
justify a cap exception.
1. **Present-but-unusable trust source belongs in the fail-closed requirements**
   (Codex: yes, it does). Failure to load or validate a *configured* trust source must
   not silently disable trust enforcement. `external-verifier-contract-v1.md:709`
   currently covers only the ABSENT case; every "unparseable" clause in the contract is
   about stdout, never the verifier's own trust store. Required behavior and error
   classification need explicit treatment BEFORE this becomes a portable conformance
   assertion. Do not draft a broader trust-policy redesign.
2. **`process.exit()` footgun beside the §7.1 MUST.** Mandating a non-zero exit pushes
   implementers toward `process.exit(1)`, which can abandon a pending async stdout
   write to a pipe and truncate the very verdict §5.1 requires be complete. The
   requirements are compatible (complete stdout AND non-zero exit is achievable, via
   `process.exitCode`); what is missing is implementation guidance. His measurement:
   node v22.22.1, `process.exit()` capped at 1 MiB where `process.exitCode` wrote all
   5,000,055 bytes — **that version and workload, not a universal limit.**

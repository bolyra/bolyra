# examples/gov-stats-portal (founder task 2 from the 2026-10-03 rogue-agent handoff; overrides the "build nothing now" brainstorm ruling by direct instruction)

Codex plan: 3 rounds (R1 APPROVE WITH EDITS 7, R2 APPROVE WITH EDITS 1, R3 APPROVE under delegated approval).
Plan: ~/.claude/plans/reactive-giggling-sunset.md. Red→green record below.

- [x] 1. scaffold + fixtures (fixtures.test RED → copy → GREEN)
- [x] 2. credential.test RED → src/credential.ts GREEN
- [x] 3. portal.test RED → src/portal.ts + data.ts + portal-main.ts GREEN
- [x] 4. scenes.test + demo.test RED → src/scenes.ts + demo.ts GREEN
- [x] 5. README (disclosure first, attribution rule), CI job, CHANGELOG
- [x] 6. lockfile in node:20; verify-lockfiles.sh; container run; Codex review → clean; DCO; PR; merge

## Review (2026-10-03)
- Shipped: PR #203 squash-merged `1ba5de71`; main CI green; CI job `gov-stats-portal` green from a clean checkout.
- Codex: plan 3 rounds (7 + 1 edits, then APPROVE under delegated approval); code review clean R1.
- Honesty: disclosure first (repo test-vector proof unchanged; bindings re-signed with public key 42n;
  enforcement not identity); decision origin on every response; no incident claims.
- Found+fixed before merge: `ts-node` demo path bug (child entry only exists compiled). Post-merge nit:
  unused test import removed (CodeQL).
- Handoff tasks 1, 3, 4 not done (not requested); task-4 facts recorded in memory.

## Red→green record
- fixtures.test RED (ENOENT) → copied 5 files → GREEN 1/1
- credential.test RED (TS2307 module missing) → GREEN 3/3
- spike (not committed): published verifier on P1/P2 → allow, request_mismatch×2, nonce_replayed, scope_exceeded, invalid_bundle, invalid_signature, invalid_proof, ~0.85 s each
- portal.test RED (TS2307) → GREEN 5/5 (first run)
- scenes.test + demo.test RED (TS2307) → demo deviated on scene 1 origin (200 body lacked origin) → fixed → GREEN 12/12
- container: `npm run demo` via ts-node FAILED (child entry resolved to src/portal-main.js, which only exists compiled) while tests passed; demo script switched to `tsc && node dist/src/demo.js`, ts-node dropped; green on host

---

# Playground usage signals (founder: "i want to learn about how people are using the playground", 2026-10-01)

Claude take → Codex BUILD (bounded same-origin instrumentation, ½-day cap, daily counts, no funnels,
no demand inference); plan approved. Red→green:
- test/unit/usage.test.js RED (module missing) → GREEN 7/7
- build/artifact usage expectations RED (Plausible present, no track export) → GREEN (node 75/75)
- browser.mjs beacon policy + canary + 500 tolerance: written with the UI hooks in the same pass;
  first run green (no observed red for this file)
- test/unit/usage-report.test.js RED (module missing) → GREEN (unit 61/61)
- Codex review R1: 1 P2 (report skipped middle months) → monthsBetween test RED (no export) → GREEN (unit 62/62)
- Codex review R2: 1 P2 (HEAD requests counted as loads/events) → GET-only test RED → GREEN (unit 63/63)

- [x] 1. usage.js + hooks + template (Plausible removed, Codex privacy wording)
- [x] 2. landing/e + deploy.sh upload + verify.sh needles/forbidden/endpoint
- [x] 3. tools/usage-report.mjs
- [x] 4. container run, Codex review, PR, merge, deploy, live synthetic event confirmed in logs

Review (2026-10-02): PR #202 `6266149e` deployed; verify.sh green incl. /e 200. Live synthetic check from Chrome: interacted, tab_decode, sample_decode, run_decode, decode_ok all 200 and visible in `tools/usage-report.mjs` output ~10 min later. Gap: browser.mjs had no observed red (hooks written in the same pass).

---

# Playground Phase B: Decode a 402 + EVC wire shapes (founder "playground Phase B", 2026-09-30)

Goal: two illustrative tabs on bolyra.ai/playground; nothing fabricated (build-time extraction
from spec/fixtures/@bolyra/mpp), parse-only port of x402LocalChallenge/peekHeader differentially
tested against @bolyra/payment-protocols@0.9.0; Codex-approved plan (3 rounds, APPROVE) at
~/.claude/plans/reactive-giggling-sunset.md; approval delegated by founder ("let codex decide").
Red→green record: each test file's first run is logged here before its implementation exists.

- [x] 1. worktree + pins (payment-protocols 0.9.0 devDep, engines range, config) + lock in node:20.19
- [x] 2. x402.diff.test.js + x402.test.js (RED) → src/core/x402.js (GREEN)
- [x] 3. spec-extract.test.js + mini-schema.test.js + evc-shapes.test.js (RED) → tools/{spec-extract,mini-schema,deny-table}.mjs (GREEN)
- [x] 4. build.test.js + artifact.test.js additions (RED) → build.mjs/template/index.js/bundle-runner ops (GREEN)
- [x] 5. DecodeView.jsx + WireView.jsx + App.jsx (4 tabs) → npm run build → npm test → npm run check
- [x] 6. browser.mjs additions (RED) → green; test:cli still green
- [x] 7. landing/verify.sh needles + payment-protocols pin; README; CHANGELOG
- [x] 8. node:20.19 container run; Codex review → clean; DCO commits; PR; merge; deploy; verify live

## Red→green record
(append: `<test file> RED <reason> → GREEN <count>`)
- test/unit/x402.diff.test.js + x402.test.js RED (ERR_MODULE_NOT_FOUND src/core/x402.js) → GREEN 15/15 (diff suite green first run) 2026-09-30
- test/unit/{spec-extract,mini-schema,evc-shapes}.test.js RED (ERR_MODULE_NOT_FOUND build/*.mjs) → GREEN (unit total 53/53) 2026-09-30
- test/build.test.js + test/artifact.test.js Phase B additions RED (needles absent; unknown ops x402.*/shapes) → GREEN (node total 66/66) 2026-09-30
- test/browser.mjs Phase B: NO red observed — the UI was built in step 5 before this file was extended, and the old 2-tab assertion was replaced in the same edit that added the new checks; first run of the extended gate passed (all checks). test:cli green on the new run dir.
- Codex code review R1: 2 P2 (hostile object-valued decoded fields crash the render; header trimmed before parse). browser.mjs assertions added → RED (timeout: hostile header unmounted the page) → fix: safe `show()` renderer, no trim, per-view ErrorBoundary. R2: 1 P2 (audience trimmed before the byte-equality matcher) → browser assertion RED → audience/resource kept byte-exact, matcher via pg.defaultPayeeMatch.

## Review (2026-10-01)
- Shipped: PR #201 squash-merged `f1a16841`; main CI green; `landing/deploy.sh` ran the pre-upload
  gates (live CSP == snapshot; 66 tests; drift; Playwright; CLI), uploaded, invalidated
  `I9O2QNG7BKYSUD0P3DXI3DOZ9X`; verify.sh: byte identity, Phase A + Phase B needles,
  receipts 0.11.0 and payment-protocols 0.9.0 three-way pins, fetched-bundle smoke → `✓ all checks passed`.
- Scope: Codex scoped Phase B DOWN from the proposed resolver port to the illustrative decode
  (plan R1 REVISE 11 → R2 APPROVE WITH EDITS 4 → R3 APPROVE; approval delegated by the founder).
  Quote verification (jose, keys, resolver port) is deferred to a separate request.
- Code review: R1 2×P2 (hostile object-valued fields crashed the render; header trimmed),
  R2 1×P2 (audience trimmed before byte-equality display), R3 clean. All fixed test-first.
- Honest gaps in the red→green record: browser.mjs's Phase B assertions were first run after the
  UI existed (no red for that file in step 6; later rounds did have red runs).
- Lessons: the root .gitignore ignores `build/` (helper dir renamed to `tools/`); `codex exec`
  prompts must be passed as an argument when stdin is /dev/null; node 20 prints TAP.

---

# Playground rebuild: real receipt verification (founder "go ahead and build", 2026-09-30)

Goal: replace landing/playground.html with a prebuilt static page that verifies real
receipts with @bolyra/receipts@0.11.0 in-browser and simulates spend policy honestly;
Codex-approved plan at ~/.claude/plans/reactive-giggling-sunset.md (4 rounds).

- [x] 1. apps/playground scaffold: package.json (exact pins), lock in node:20, csp snapshot
- [x] 2. tiers.js (red → green) + differential test vs @bolyra/mpp@0.7.0
- [x] 3. verify.js (red → green): parse/limits, envelope, options, central overall-ok
- [x] 4. simulate.js (red → green): session, decide, chained real receipts, export, reset
- [x] 5. build.mjs + template.html + UI (React); build.test.js; artifact.test.js
- [x] 6. browser.mjs (Playwright, CSP, request policy) + cli.test.js (browser download → CLI)
- [x] 7. landing/verify.sh + deploy.sh gates; ci.yml playground job; CHANGELOG
- [x] 8. node:20 container run; Codex review → clean; DCO commits; PR; merge; deploy; verify live

## Review (2026-09-30)
- Shipped: PR #198 squash-merged as `3313834d`; deployed via `landing/deploy.sh` (pre-upload gates
  incl. live-CSP compare + Playwright + CLI; CloudFront invalidation `I7VJCQ3CW7TZGJD5P1KNY4BYU2`);
  `verify.sh` proved `/playground` byte-identical, needles/forbidden, receipts pin 0.11.0 ==
  lockfile == config, and executed the fetched bundle against repository fixtures.
- Codex: R1 four P2 (commerce field validation + bare intentHash, signature.keyId == payload.keyId,
  checkpoint `unchecked` on chain-verifier exception, per-field sample provenance), R2 one P2 (views
  unmounted on tab switch dropped the simulator session), R3 clean. All fixed test-first.
- Container node:20: 41/41 + check green (twice); host browser gate + container CLI gate PASS.
- Lessons: esbuild escapes `</script` only, not `<!--`/`<script` (post-process to `\x3C`); Node 20
  prints TAP so grep for `# pass`, not `ℹ pass`; `node --test <dir>` needs a glob on Node 24;
  `require(relative)` in `node -e` resolves against node_modules (use `path.resolve`).
- Not done: Phase B (402 decoder, EVC wire shapes) awaits a separate founder request.

---

# x402 issuer-quoted payee binding + spec §4.2 (founder override 2026-09-29, started 2026-09-29)

Goal: `@bolyra/payment-protocols` 0.9.0 with an agent-side host mode that binds a
placeholder `payTo` to an issuer-signed quote (Tavily agent-pay shape), fail-closed
throughout, plus spec §4.2; Codex-approved plan at
`~/.claude/plans/reactive-giggling-sunset.md`. No publish, no outbound.

- [x] 1. F2 compat probe: jose@^6 + engines + jest allow-list; compiled require
      probe in node:20.19 and node:22.12; one-line jest import test
- [x] 2. A1 payeeMatches literal-true + thenable assimilation (red → green)
- [x] 3. A2 asset-aware resolveUsdAmount, fixture assetDecimals:6 (red → green)
- [x] 4. A3 finite-time guards (red → green)
- [x] 5. Types + local challenge helper `x402LocalChallenge` (red → green)
- [x] 6. jws.ts signature layer vs RFC 7515 A.3 (red → green)
- [x] 7. createIssuerQuotePayeeResolver: config validation, parser contract,
      claims, products, settlementFields (red → green)
- [x] 8. verify wiring: resolvePayee, snapshots, double recheck, quote nonce,
      checkedLeg, payee_binding (red → green)
- [x] 9. openssl full-profile ES256/ES384 fixtures + sanitized Tavily fixture +
      real-token wrong-key test + replay/race/config-fault suites
- [x] 10. tsconfig.test.json + typecheck:test + ci.yml; README section; spec §4.2;
      residual wording fixes; CHANGELOG 0.9.0 (BREAKING A2); demo assetDecimals
- [x] 11. node:20.19 + node:22.12 full runs, --network none gate, npm pack
      consumer smoke
- [x] 12. sdk-guardian PASS-after-fixes + security SHIP-after-fixes DONE; Codex review → clean; DCO commits; PR;
      CI on PR and main

## Review (2026-09-29)

Shipped on branch `feat/x402-issuer-quote-payee` (PR to follow), 12 DCO commits.
- Tests: 343 green in the package (was 132); `typecheck:test` green; node:20.19 and
  node:22.12 gates green incl. packed CJS/ESM consumers; resolver suites green under
  `--network none` (194).
- Reviews: bolyra-sdk-guardian FAIL → fixed (sdk range widened by the jose install,
  checkedLeg vs verified requirements, jsdoc/CHANGELOG honesty); bolyra-security
  SHIP WITH FIXES → fixed (H1 unbound `extra` fields reaching settlement, M1 options
  re-read after await, L1-L4, I1/I3); Codex `review --base origin/main` 4 rounds
  (3 findings → 1 → 1 → clean): fresh request clock after resolution, dotted
  tokenField, 2×skew bound, verifier config deep copy, local challenge snapshot-first.
- Pattern worth keeping: every "snapshot" must be ONE structuredClone taken before any
  read, and every check must run on that clone; three separate findings (L3, verifier
  config, selectedLeg) were the same TOCTOU shape.
- Not done: publish 0.9.0 (separate, Codex-routed); the reply to Zach/probe402
  (separate Claude-take → Codex → founder-send step).

---

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
- [x] **REQUIRED — DONE 2026-09-23, commit `6aad395a` on branch `evc-71-config-fault-coverage`.**
      `verifier_config_fault` class + vector; set 0.10.0 -> 0.11.0. Added to `NON_CRYPTO_TYPES`
      (the runner test caught that it otherwise dragged in circomlibjs) and to the sync filter
      (without it the vector would live in `spec/` and never ship to implementers).
      **Real red/green, not stubs:** `660902f6` FAILS (fail-open), `1aa9d88` PASSES.
      Envelope 11/11 unchanged, package 30/30, sync:check clean, green in a node:20 container.
- [ ] **OPTIONAL, NOT DONE — now eligible** (required repair is complete and validated).
      NOTE: the shipped vector already catches the fail-open, but with a request the healthy store
      ALLOWS. The diagnostic Codex specified is sharper and still missing: a request the healthy
      restrictive store DENIES (`untrusted_root`) must not flip to `allow` after corruption.
      Original wording: a trust-configuration
      corruption *security diagnostic*. It must reproduce the authorization
      distinction: a cryptographically valid request that a healthy restrictive trust
      store DENIES must not become ALLOWED after corruption. **Not a required
      conformance vector** — making it one would import a normative rule the spec does
      not yet state.
- [x] Controls, classification, red/green, validation — done inside the cap.
- [ ] **Deliver:** push branch + PR, then release `@bolyra/evc-conformance` so the vector is
      actually runnable by an implementer (a vector he cannot `npx` is not delivered), THEN the
      reply on issue #1. **Reply needs an explicit founder go** (Codex 2026-09-23).

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

## Backlog fixes (2026-09-24, founder: "lets fix the backlog items"; plan Codex-APPROVED after 5 review passes)
Plan: ~/.claude/plans/eager-discovering-babbage.md · order ruled by Codex: C1 → A1 → B → A2 → D1 → D2 → E → OPS
- [x] PR-C1 (MERGED #183, main `4cf75f91`) E9 (CI boots wrangler dev in hosted-verify-tests; five exact checks: health, 401, unregistered deny, register 201, allow) + E10 (@bolyra/mpp devDep; digest agreement from the installed package; example asserts the Worker's id in-process)
- [x] PR-A1 (MERGED #184) schema_meta + E5 E7 E8 E17 E18 T6 E14 E11
- [x] PR-B (MERGED #187) E2 E13 T10 E15 E16 E19 — OPS: founder must run the two `tenant.sh migrate --from` commands before any tenant mutation
- [x] PR-A2 (MERGED #185) E6
- [x] PR-D1 (MERGED #186) T8 TD-1 TD-2 engines — [ ] publish @bolyra/mpp 0.7.0 (FOUNDER GO; unpublished)
- [ ] PR-D2 example migration to 0.7.0
- [x] PR-E (MERGED #188) T3 T4 T7 spec wording
- [x] OPS: [x] migrate tenant records (founder ran both, 2026-09-25) · [x] staging deploy a16251b1 + canary leg + example 21/21 · [x] prod deploy 07a5a031 (auth boundary) · [x] strict health (dispatch green on main) · [x] bolyra-canary tenant + canary leg on prod (7a224328, 0d75ed6f) · [x] remove `--allow-missing-tenant` · [x] bolyra-smoke removal (tenant_count 1)
Deferred by ruling: release backoff widen, T9 keychain seam, E19 overlap, T6 docs links.

## Review (backlog fixes)
(fill per PR)

## 2026-10-03 — Handoff task 1: scope-bound authorization walkthrough (docs)

Founder instruction "do task 1" (overrides Codex "defer drafting"; honesty constraints kept).
Shape per Codex evening ruling: hypothetical authorization-boundary walkthrough, explicit
assumptions, what is constrained, what remains unprotected, no incident-prevention claims.

- [x] Draft `docs/scope-bound-authorization-walkthrough.md` (cites origin/main 5b0ab459)
- [x] Fact-check cites: core.ts L321–370, receipts types L20+, spec §2.1/§4.1/§8/§9
- [x] Codex round 1: REVISE (3 factual, 7 overclaim, §1 incident background CUT), PUBLISH NO
- [x] Codex round 2: REVISE (rejected-vs-absent bundle receipts in §4.3), PUBLISH NO
- [x] Codex round 3: APPROVE, PUBLISH YES
- [ ] DCO commit, docs PR, checks, merge (no CHANGELOG entry, same as the gap-note PR #204)

Review: the handoff title ("would have stopped") was not usable under the no-incident-claims
hold; the shipped doc is a hypothetical walkthrough with six explicit assumptions, a fixed
verifier check order, three constrained situations, and a §5 that itemizes seven ways the
assumptions fail. Codex cut the incident background paragraph entirely in round 1.

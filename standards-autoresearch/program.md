# Standards AutoResearch Loop — Program (the contract)

This file is the graded contract for every model call in this loop. It is
injected into every Fable prompt and every Codex judgment. If an instruction
here conflicts with anything a stage template says, THIS FILE WINS.

## 1. Objective

Compound Bolyra/EVC toward being THE standard for agent authorization. The
loop's product each iteration is exactly three things:

1. **Reconciled boards** — `output/threat_board.json` + `output/adoption_board.json`,
   every card verified against live ground truth.
2. **Staged artifacts** — spec-hardening diffs, new conformance vectors, and
   interop-evidence material in `output/staged/<date>/`, each with an
   `APPLY.md` for the founder. Nothing is applied by the loop.
3. **An append-only evidence ledger** — `output/evidence_ledger.jsonl`,
   third-party-verifiable facts only.

The loop NEVER sends, posts, publishes, or applies. It researches and stages.

## 2. Hard Rules (violating any of these is an automatic REJECT)

a. **ADDITIVE ONLY.** The loop writes exclusively inside `standards-autoresearch/`.
   It never modifies `spec/`, `integrations/`, `sdk/`, or any published package.
   Spec changes are expressed as staged diffs pinned to a base commit.
b. **Claude MAX CLI only.** No API keys, no SDKs, no pip installs.
   Generator model: `claude-fable-5-1` (Fable 5.1). Judge: Codex
   (`codex exec`, from the repo root, stdin closed). If either is unavailable,
   FAIL LOUDLY — no silent model fallback.
c. **NO OUTBOUND, EVER.** No GitHub comments, no PRs to external repos, no
   emails, no DMs, nothing in `drafts/`. v1 has no outreach arm by design.
d. **Engagement-graph holds are load-bearing.** The loop reads
   `~/Projects/.viswa/projects/bolyra-engagement-graph.md` READ-ONLY. Any
   entity under a hold ("no nudges", "ball in his/her court", "awaiting",
   "hold") gets `state: "hold"` on its adoption card and a `channel_state`
   score capped at 5. The loop never proposes contacting a held entity.
e. **Moat guardrail.** Artifacts give away the WHY, the boundary, and the
   spec — never repo-specific build plans or the hosted operational system.
f. **Roadmap freezes are binding.** No new packages, no listing/example PRs,
   nothing that implies the hosted platform. The operator-call sprint owns
   founder attention; this loop runs on autopilot beside it.
g. **Terminal states are terminal.** A merged/closed PR, an expired/replaced
   draft, an archived repo: the card flips to `terminal` and is never
   reopened. New developments get a NEW card with `superseded_by` links.
h. **Reconcile before everything; recompute, never accumulate.** Stage 0a
   verifies every card and tracked entity against live truth before any
   model call. Board totals and the standard-ness score are recomputed from
   reconciled truth each iteration. (Encodes the pr-outreach postmortem:
   that loop inferred PR state from dates and drafted a closing comment for
   an already-merged PR.)
i. **Human gate** between Tier 1 and Tier 2 unless `--auto-approve`.
   Auto-approve is safe ONLY because of rules a–c: every output is a board
   update or a staged artifact.
j. **Regression halts.** A standard-ness drop > 2.0 stops the loop with a
   REGRESSION report. This is a feature: a drop means ground truth moved
   against us (e.g. a competing spec landed a major host) and the founder
   should see it, not have the loop paper over it.
k. **Evidence or it doesn't exist.** No candidate advances without a URL,
   a repo, a datatracker entry, or a runnable command. Claims about our own
   code are verified against the pinned source before they appear in any
   artifact.

## 3. Standard-ness Score (0–100, objective-first)

| Dim | Wt | Basis | Scored by |
|---|---|---|---|
| IMPLEMENTATIONS | 25 | Independent implementations passing conformance at pinned commits; RFC 7942 listability | objective count |
| SPEC HARDNESS | 20 | Open CONFIRMED spec findings against us (fewer = higher); % of normative MUSTs covered by a conformance vector | objective + coverage map |
| INTEROP EVIDENCE | 20 | Ledger entries that are third-party reproducible (pinned commit + command); `rfc7942_ready` count | objective count |
| ECOSYSTEM POSITION | 20 | Citations, competing specs neutralized into adapters, datatracker standing, threat pressure | **Codex** vs rubric anchors |
| REGISTRY CLOSURE | 15 | Published suite freshness, `sync:check` green, vector-set/spec version alignment, -02 material completeness | objective |

No target score — the loop is open-ended. Exits: drought (3 consecutive
iterations with zero new board cards AND zero Tier-3 approvals — scan-only
iterations count toward drought), `--max-iters`, regression halt.

## 4. Boards

Cards are append-only; scores update-if-higher with a `history[]` event; a
card is never deleted, only `terminal` or `superseded` (via `superseded_by`).
Kinds: `threat` (dims: momentum / overlap / adoption_risk / counter_available,
0–25 each) and `adoption_target` (dims: incentive_fit / technical_fit /
channel_state / effort, 0–25 each). Every evidence entry carries a URL, a
date, a claim, and `verified_by` (gh_api | datatracker | npm | websearch).

Ledger entries (`evidence_ledger.jsonl`): `{id, date, kind:
interop_run|implementation|citation|registry_event, subject, pinned_commit,
reproduce_cmd, urls[], rfc7942_ready, iter}` — append-only facts, never
rescored, never deleted.

## 5. Stages

| Stage | What | Model |
|---|---|---|
| 0a RECONCILE | `reconcile.py` verifies every entity/card: gh api, IETF datatracker JSON, npm view. Stale = error stub, never a crash. Log to `history/reconcile_log.jsonl` | none |
| 0b SIGNAL FETCH | `sources/fetch_signals.py` — one WebSearch call per registry query; dedup vs `history/seen_signals.jsonl` | Fable 5.1 |
| 1 ATTACK & DISCOVER | 6 personas fan out; **Codex judges** the pool vs `rubrics/tier1_rubric.md` | Fable 5.1 → Codex |
| 2 BUILD | Typed artifacts per winner; objective checks (`checks/`); **Codex acceptance** (APPROVE/REVISE/DROP) | Fable 5.1 → scripts → Codex |
| 3 ADVERSARIAL REVIEW | **Codex** vs `rubrics/tier3_adversarial_rubric.md`; APPROVE → `output/staged/` + APPLY.md; REJECT findings → next Tier 1 | Codex |
| 4 SCORE | `scoring.py` — objective dims from reconciled truth; ECOSYSTEM POSITION judged by **Codex** | scripts + Codex |

## 6. Personas (Tier 1)

Attack: **hostile-implementer** (reads spec text alone; finds ambiguity a
lazy or malicious host exploits), **security-researcher** (fail-open paths,
replay, binding/expiry edges; Binding-v2-aware), **competing-spec-author**
(argues APS/argentum/VATE/draft-klrc does X better; every real gap becomes a
spec_finding or a counter-evidence candidate), **ietf-reviewer** (RFC 2119
rigor, IANA/registry gaps, RFC 7942 readiness, -02 blockers).
Scout: **ecosystem-scout** (converts Stage-0b signals into threat/adoption
cards with falsification evidence), **evidence-curator** (what run record
would a skeptical third party demand next — the VATE #57 pattern).

Candidate types: `spec_finding | vector_gap | evidence_opportunity |
threat_update | adoption_target`.

## 7. Verdicts

- Tier 1 (Codex): per-candidate 4×25 dims from `rubrics/tier1_rubric.md`.
  PROMOTE ≥70 AND all dims ≥12 · CONSIDER ≥50 AND no dim ≤5 · DROP otherwise.
- Tier 2 (Codex acceptance): APPROVE (advance to Tier 3) / REVISE (one Fable
  revision pass, then re-judge once) / DROP.
- Tier 3 (Codex adversarial): APPROVE (→ staged + APPLY.md) / CONDITIONAL
  (concerns recorded on the artifact, stays in experiments/) / REJECT
  (findings feed next iteration's Tier 1 as context).

## 8. Founder Apply Protocol

Every `output/staged/<date>/<id>/APPLY.md` must contain: the base commit the
artifact is pinned to and a re-validation command; exact apply steps (where
the diff lands, `node integrations/evc-conformance/scripts/sync.js` when
vectors change, golden regeneration commands); DCO reminder (`git commit -s`);
a note that CODEOWNERS gates spec/verifier paths.

## 9. Anti-Drift Protocol

Reconcile methods per entity kind: `gh_repo` → `gh api repos/{r}` (pushed_at,
archived); `gh_pr`/`gh_issue` → state + merged + last comment author/time;
`ietf_draft` → datatracker `/api/v1/doc/document/<name>/` (rev, expired,
replaced); `npm` → `npm view <pkg> version`. Unreachable → `{"error": "..."}`
stub + card `state: "stale"`; the iteration continues. Every check appends a
row to `history/reconcile_log.jsonl` with method, target, result, and
timestamp.

## 10. Registry note

This loop is registered in `bolyra/CLAUDE.md` (Standards row). Its source
registry is DISJOINT from `discovery-autoresearch/` by charter: this loop
tracks named standards entities and artifacts; discovery tracks market
demand. Do not mix winners between loops.

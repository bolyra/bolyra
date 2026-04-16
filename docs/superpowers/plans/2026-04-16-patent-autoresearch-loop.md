# Patent Autoresearch Loop Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Karpathy-style two-tier autoresearch loop that iteratively strengthens the IdentityOS provisional patent (drafts/provisional-patent-identityos.md) by running **automated adversarial review** at scale — generating hostile attacks in parallel, proposing candidate claim rewrites, scoring them on multiple dimensions, and converging on the strongest filing-ready claim set.

**Core primitive: automated adversarial review.** This loop is the natural extension of the manual adversarial reviews already done (rounds 1-3, in `drafts/adversarial-review*.md`). Each round manually:
1. Dispatched one or two hostile reviewers (Codex, Opus subagent)
2. Collected findings
3. Triaged severity
4. Applied fixes
5. Ran the next round

The autoresearch loop automates all five steps and runs them end-to-end per iteration. Tier 1 (Adversarial Attack Discovery) replaces step 1-3: N parallel hostile personas attack the patent and an LLM judge prioritizes findings by severity + specificity + remediability. Tier 2 (Claim Strengthening) replaces steps 4-5: for each prioritized weakness, generate K candidate fixes, score each on 5 dimensions (101 survival, 103 defense, 112 support, design-around resistance, claim scope), and apply the winner. The loop repeats — round 4, 5, 6, N — until the composite score plateaus or a target is reached. **The previous manual adversarial reviews (r1, r2, r3) become the training data and baseline for the automated system.**

**Tech Stack:** Python 3.13, Claude CLI (per feedback_claude_max preference), subprocess for orchestration, JSON for all I/O between stages, thread pool for parallel reviewer fanout, exact-string replacement for claim mutations. No external dependencies beyond what ZKProva already has.

---

## File Structure

```
patent-autoresearch/
├── program.md                          # Master instructions for Claude (~400 lines)
├── run_tier1_attack.py                 # Tier 1: parallel adversarial review (attack discovery)
├── run_tier2_claim.py                  # Tier 2: candidate claim generation + scoring
├── run_loop.py                         # Orchestrator: runs tier1 → tier2 → apply → repeat
├── judge.py                            # LLM-as-judge for Tier 1 (weakness prioritization)
├── scoring.py                          # 5-dimension scorer for Tier 2 candidates
├── mutator.py                          # Applies approved claim mutations to patent draft
├── baseline.py                         # Scores current patent (no mutation) as baseline
│
├── personas.json                       # 6 hostile reviewer personas (USPTO examiner, competitor attorney, etc.)
├── rubrics/
│   ├── tier1_attack_rubric.md          # Severity + specificity + remediability scoring
│   └── tier2_claim_rubric.md           # 5-dim claim-strength rubric
│
├── prior_art.json                      # Curated prior-art database (refs + what-they-teach)
├── case_law.json                       # Alice/103/112 case law for grounding
├── seed_findings.json                  # Findings from manual adversarial reviews r1+r2+r3
│                                       # Prevents Tier 1 from rediscovering known issues
│
├── runs/                               # Per-iteration adversarial review state
│   └── iter_NNN_TIMESTAMP/
│       ├── current_patent.md           # Snapshot of patent at iteration start
│       ├── tier1_attacks.json          # Raw attacks from all reviewers (this round's adversarial review)
│       ├── tier1_scored.json           # Attacks ranked by judge (severity/specificity/remediability)
│       ├── tier1_selected.json         # Attacks promoted to Tier 2 (top N high-priority)
│       ├── tier2_candidates.json       # K candidate fixes per selected attack
│       ├── tier2_scored.json           # Candidates scored on 5 dimensions
│       ├── tier2_winners.json          # Winners (highest-scoring per weakness, total ≥ 60)
│       ├── patent_after.md             # Patent after mutations applied
│       └── iteration_report.md         # Human-readable summary of this round's adversarial review
│
├── history/
│   ├── baseline_score.json             # Iteration 0 score (current patent)
│   ├── score_trajectory.jsonl          # Score per iteration (one line per round)
│   └── plateau_detector.py             # Stops loop when score plateaus
│
├── reports/
│   ├── adversarial-review-r4.md        # Auto-generated after iter 1 (rounds 1-3 were manual)
│   ├── adversarial-review-r5.md        # Auto-generated after iter 2
│   └── ...                             # One per iteration; drop-in successors to drafts/adversarial-review-r{1,2,3}.md
│
├── scripts/
│   ├── render_patent.sh                # Pretty-print current patent
│   ├── diff_patent.sh                  # Show claim-level diff between runs
│   └── summarize_run.py                # Generate FINAL_REPORT.md
│
└── README.md                           # Runbook
```

**Continuity with manual reviews:** The `reports/adversarial-review-r{N}.md` files are the direct successors to the existing `drafts/adversarial-review.md`, `drafts/adversarial-review-r2.md`, and `drafts/adversarial-review-r3.md` from rounds 1-3. The loop is the sustainable version of the same process.

---

## Chunk 1: Foundation and scoring infrastructure

### Task 1: Set up patent-autoresearch directory and baseline spec

**Files:**
- Create: `patent-autoresearch/program.md`
- Create: `patent-autoresearch/README.md`
- Create: `patent-autoresearch/personas.json`
- Create: `patent-autoresearch/prior_art.json`
- Create: `patent-autoresearch/case_law.json`

- [ ] **Step 1: Create directory skeleton**

```bash
cd /Users/lordviswa/Projects/identityos
mkdir -p patent-autoresearch/{rubrics,runs,history,scripts,experiments}
```

- [ ] **Step 2: Write program.md (master spec)**

Contents must include:
- Objective: two-tier patent strengthening loop
- Architecture: Tier 1 parallel attack discovery, human gate, Tier 2 candidate claim generation + scoring, mutation application, loop until plateau
- Rules: ADDITIVE ONLY to patent draft (never delete claims, only refine); NEVER change inventor name or docket; ALWAYS keep a snapshot of previous version; all work in `patent-autoresearch/runs/`; use Claude CLI (not API SDK) per user preference
- Scoring: 5 dimensions for Tier 2 (101, 103, 112, design-around, scope), weighted equally at 20 pts each = 100 total
- Exit condition: 3 consecutive iterations with <2 pt score delta OR score ≥90 OR 10 iterations max

- [ ] **Step 3: Write personas.json (6 hostile reviewers)**

```json
[
  {"id": "examiner_strict",      "role": "USPTO examiner, post-Alice/KSR aggressive", "focus": ["101", "103"]},
  {"id": "competitor_attorney",  "role": "Patent attorney for a competitor drafting design-arounds", "focus": ["design_around", "claim_scope"]},
  {"id": "alice_specialist",     "role": "101-focused litigator citing Electric Power Group, Two-Way Media, BSG Tech", "focus": ["101"]},
  {"id": "obviousness_hunter",   "role": "103 specialist combining prior art with motivation-to-combine arguments", "focus": ["103"]},
  {"id": "enablement_auditor",   "role": "112(a)/(b) specialist finding written-description gaps and indefinite terms", "focus": ["112"]},
  {"id": "code_spec_auditor",    "role": "Reviewer who reads the code AND the patent, finds mismatches", "focus": ["accuracy", "enablement"]}
]
```

- [ ] **Step 4: Write prior_art.json (curated prior-art database)**

Seed with references already identified across the three adversarial reviews:
- Semaphore v4, World AgentKit, Iden3, UCAN, Biscuit, Tornado Cash Nova, Tornado MerkleTreeWithHistory, DAC (ePrint 2008/428), Aztec Connect, MACI, zkLogin/Mysten Labs, AnonCreds/BBS+, RLN, zkCreds/Cinderella, Indicio ProvenAI

Each entry: `{id, name, url, year, what_it_teaches, threatens_claims}`.

- [ ] **Step 5: Write case_law.json (Alice/103/112 grounding)**

Seed with cases already cited: Alice Corp v. CLS Bank, Electric Power Group v. Alsthom, Two-Way Media v. Comcast, BSG Tech v. BuySeasons, Santarus v. Par, LizardTech v. Earth Resource Mapping, Ariad v. Eli Lilly, Interval Licensing v. AOL, Nautilus v. Biosig, Festo Corp v. Shoketsu, Prism Technologies v. T-Mobile, Burstiq v. Dentaquest.

Each entry: `{id, name, holding, applies_to_claim_types}`.

- [ ] **Step 6: Seed findings from rounds 1-3**

Create `patent-autoresearch/seed_findings.json` containing the attacks already identified in the three manual adversarial reviews. This serves two purposes: (a) Tier 1 judges can cross-reference against it to avoid duplicating known findings, (b) it anchors the baseline score so improvement is measured against the post-r3 state.

```bash
cat > patent-autoresearch/seed_findings.json << 'EOF'
{
  "source_reviews": [
    "drafts/adversarial-review.md",
    "drafts/adversarial-review-r2.md",
    "drafts/adversarial-review-r3.md"
  ],
  "resolved": [
    {"id": "r1_nonce_eq", "category": "112", "summary": "Nonce equality not enforced on-chain", "status": "fixed in Attack 2"},
    {"id": "r1_agent_revocation", "category": "accuracy", "summary": "Agent revocation key mismatch", "status": "fixed in bug round"},
    {"id": "r1_delegation_identity_binding", "category": "103", "summary": "Delegation chain doesn't bind delegator identity", "status": "fixed in bug round"},
    {"id": "r2_chain_state_undefined", "category": "112", "summary": "'chain-state mapping' undefined in spec", "status": "fixed via Section 7.5"},
    {"id": "r3_m2_self_inflicted", "category": "112+103", "summary": "M2 genus broadening created LizardTech 112(a) hole + read on Tornado Cash", "status": "reverted in MF1/MF2"}
  ],
  "open": [
    {"id": "r3_mf3", "category": "strategy", "summary": "Priority anchors for CIP candidates (recursive SNARK, platform attestations)", "status": "pending"},
    {"id": "r3_mf4", "category": "112", "summary": "sessionNonce generation mechanism not specified", "status": "pending"},
    {"id": "r3_mf5", "category": "112", "summary": "Scope commitment brute-force mitigation missing", "status": "pending"},
    {"id": "r3_alice_15", "category": "101", "summary": "Claim 15 at only 40-50% 101 survival", "status": "pending"},
    {"id": "r3_claim_15_prime", "category": "strategy", "summary": "Add backup Claim 15' with specific Poseidon/EdDSA/BabyJub/LeanIMT stack", "status": "pending"}
  ],
  "persistent_risks": [
    {"id": "persistent_obviousness", "summary": "Semaphore v4 + Indicio + zkLogin + Tornado Cash root history → Claim 1 obviousness"},
    {"id": "persistent_agent_only", "summary": "Pure agent-to-agent system escapes Claim 15 'human user and AI agent' language"}
  ]
}
EOF
```

- [ ] **Step 7: Commit**

```bash
git add patent-autoresearch/
git commit -m "feat(patent-autoresearch): directory skeleton + persona/prior-art/case-law/seed-findings"
```

---

### Task 2: Write scoring.py (5-dimension claim rubric)

**Files:**
- Create: `patent-autoresearch/scoring.py`
- Create: `patent-autoresearch/rubrics/tier2_claim_rubric.md`
- Test: `patent-autoresearch/test_scoring.py`

- [ ] **Step 1: Write the failing test**

```python
# patent-autoresearch/test_scoring.py
import json
from pathlib import Path
from scoring import score_candidate, DimensionScore, CandidateScore

def test_score_candidate_returns_all_five_dimensions():
    candidate = {
        "id": "test_candidate_1",
        "claim_text": "A method comprising...",
        "rationale": "Narrows 101 risk by...",
        "targets_weakness": "W1"
    }
    score = score_candidate(candidate, context_patent_text="...", context_priorart=[])
    assert isinstance(score, CandidateScore)
    assert set(score.dimensions.keys()) == {"alice_101", "obviousness_103", "support_112", "design_around", "scope"}
    for dim_score in score.dimensions.values():
        assert 0 <= dim_score.points <= 20
    assert 0 <= score.total <= 100

def test_score_candidate_returns_evidence():
    candidate = {"id": "t", "claim_text": "...", "rationale": "...", "targets_weakness": "W1"}
    score = score_candidate(candidate, context_patent_text="...", context_priorart=[])
    for dim_score in score.dimensions.values():
        assert dim_score.evidence, "each dimension must have evidence"
        assert dim_score.critique, "each dimension must have critique"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd patent-autoresearch && python3 -m pytest test_scoring.py -v`
Expected: FAIL with `ModuleNotFoundError: scoring`.

- [ ] **Step 3: Write minimal scoring.py**

```python
# patent-autoresearch/scoring.py
"""5-dimension claim scorer using Claude CLI as LLM-as-judge."""
from __future__ import annotations
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DIMENSIONS = ["alice_101", "obviousness_103", "support_112", "design_around", "scope"]
MAX_PER_DIMENSION = 20
MAX_TOTAL = 100

@dataclass
class DimensionScore:
    name: str
    points: int
    max_points: int = MAX_PER_DIMENSION
    evidence: str = ""
    critique: str = ""

@dataclass
class CandidateScore:
    candidate_id: str
    dimensions: dict[str, DimensionScore] = field(default_factory=dict)
    total: int = 0
    verdict: str = "reject"  # "apply" | "consider" | "reject"

def _load_rubric() -> str:
    return (Path(__file__).parent / "rubrics" / "tier2_claim_rubric.md").read_text()

def _call_claude_judge(prompt: str) -> str:
    """Invoke Claude CLI for judgment. Uses user's Claude MAX per feedback_claude_max."""
    result = subprocess.run(
        ["claude", "-p", prompt, "--model", "opus"],
        capture_output=True, text=True, timeout=300
    )
    if result.returncode != 0:
        raise RuntimeError(f"Claude CLI failed: {result.stderr}")
    return result.stdout

def _parse_judge_response(raw: str) -> dict[str, DimensionScore]:
    """Judge returns JSON with one object per dimension."""
    # Find the JSON block in the response
    start = raw.find("{")
    end = raw.rfind("}") + 1
    data = json.loads(raw[start:end])
    dims = {}
    for name in DIMENSIONS:
        d = data[name]
        dims[name] = DimensionScore(
            name=name,
            points=int(d["points"]),
            evidence=d.get("evidence", ""),
            critique=d.get("critique", ""),
        )
    return dims

def score_candidate(
    candidate: dict[str, Any],
    context_patent_text: str,
    context_priorart: list[dict],
) -> CandidateScore:
    rubric = _load_rubric()
    prompt = f"""You are a hostile USPTO patent examiner + competitor attorney.
Score the following candidate claim revision on 5 dimensions (0-20 each, 100 total).

RUBRIC:
{rubric}

PATENT CONTEXT (for reference, not to be scored):
{context_patent_text[:8000]}

PRIOR ART DATABASE:
{json.dumps(context_priorart, indent=2)[:4000]}

CANDIDATE:
{json.dumps(candidate, indent=2)}

Return ONLY a JSON object of the form:
{{
  "alice_101":       {{"points": N, "evidence": "...", "critique": "..."}},
  "obviousness_103": {{"points": N, "evidence": "...", "critique": "..."}},
  "support_112":     {{"points": N, "evidence": "...", "critique": "..."}},
  "design_around":   {{"points": N, "evidence": "...", "critique": "..."}},
  "scope":           {{"points": N, "evidence": "...", "critique": "..."}}
}}
"""
    raw = _call_claude_judge(prompt)
    dims = _parse_judge_response(raw)
    total = sum(d.points for d in dims.values())
    verdict = "apply" if total >= 80 else ("consider" if total >= 60 else "reject")
    return CandidateScore(candidate["id"], dims, total, verdict)
```

- [ ] **Step 4: Write rubric markdown**

```markdown
# Tier 2 Claim Strength Rubric

Each dimension scored 0-20. Total 100.

## alice_101 (0-20) — 35 USC 101 survival odds
  0-4:  Pure abstract idea, "apply it on a computer," WURC primitives only
  5-9:  Some technical recitation but result-oriented
  10-14: Concrete mechanism with specific cryptographic operations
  15-18: Specific machine + transformation, post-Alice-strong framing
  19-20: Tied to specific circuit constraints, arity-specific hashes, concrete EVM/SNARK mechanisms

## obviousness_103 (0-20) — 35 USC 103 defense odds
  0-4:  Every element in 1 prior-art reference
  5-9:  2-reference combination with clear motivation
  10-14: 3-4 reference combination required
  15-18: Specific integration not taught by any combination
  19-20: Non-obvious primitive (genuinely new) + unexpected technical result

## support_112 (0-20) — Written description + definiteness
  0-4:  Key terms undefined, functional/negative language without support
  5-9:  Partial support, scope broader than spec
  10-14: Adequate support for main embodiment
  15-18: Full support across all embodiments, all terms defined
  19-20: Genus language fully anchored by multiple worked examples

## design_around (0-20) — Competitor escape resistance
  0-4:  One-line code change escapes
  5-9:  Low-cost (hours) escape with different primitive
  10-14: Moderate-cost (days) escape requiring redesign
  15-18: High-cost (weeks) escape requiring architectural change
  19-20: Product-defining claim — escape means not building the product

## scope (0-20) — Commercial coverage breadth
  0-4:  Narrow to single trivial embodiment
  5-9:  Narrow but covers main product
  10-14: Covers main product + one extension
  15-18: Covers product + foreseeable variations
  19-20: Covers product, variations, and future CIP candidates

## Verdicts
  - apply     — total ≥ 80 AND no dimension ≤ 8
  - consider  — total 60-79
  - reject    — total < 60 OR any dimension ≤ 4
```

- [ ] **Step 5: Run test to verify it passes**

Note: This test calls Claude CLI, so requires `CLAUDE_CODE_USE_VERTEX` or equivalent login. For CI, gate with `@pytest.mark.integration`.

Run: `cd patent-autoresearch && python3 -m pytest test_scoring.py::test_score_candidate_returns_all_five_dimensions -v -m integration`
Expected: PASS (may take 60s due to Claude CLI call)

- [ ] **Step 6: Commit**

```bash
git add patent-autoresearch/scoring.py patent-autoresearch/rubrics/ patent-autoresearch/test_scoring.py
git commit -m "feat(patent-autoresearch): 5-dim scoring harness with Claude CLI judge"
```

---

### Task 3: Write judge.py (Tier 1 attack prioritizer)

**Files:**
- Create: `patent-autoresearch/judge.py`
- Create: `patent-autoresearch/rubrics/tier1_attack_rubric.md`
- Test: `patent-autoresearch/test_judge.py`

- [ ] **Step 1: Write the failing test**

```python
# patent-autoresearch/test_judge.py
import pytest
from judge import rank_attacks, AttackScore

@pytest.mark.integration
def test_rank_attacks_assigns_severity_specificity_remediability():
    attacks = [
        {"id": "a1", "persona": "alice_specialist", "finding": "Claim 1 step (d) is pure abstract state write, no technical anchor"},
        {"id": "a2", "persona": "obviousness_hunter", "finding": "Tornado Cash root history anticipates claim 6"},
    ]
    ranked = rank_attacks(attacks, context_patent_text="")
    assert len(ranked) == 2
    for r in ranked:
        assert isinstance(r, AttackScore)
        assert 0 <= r.severity <= 10
        assert 0 <= r.specificity <= 10
        assert 0 <= r.remediability <= 10
        assert r.priority in {"high", "medium", "low"}
```

- [ ] **Step 2: Run test, expect FAIL (module missing)**

- [ ] **Step 3: Write minimal judge.py**

```python
# patent-autoresearch/judge.py
"""Tier 1 attack prioritizer. Scores raw attacks on severity, specificity, remediability."""
from __future__ import annotations
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

@dataclass
class AttackScore:
    attack_id: str
    severity: int        # 0-10 — how much it threatens the patent
    specificity: int     # 0-10 — how actionable the feedback is
    remediability: int   # 0-10 — how easily it can be fixed
    priority: str        # "high" | "medium" | "low"
    total: int = 0

    def __post_init__(self):
        self.total = self.severity + self.specificity + self.remediability
        if self.total >= 22: self.priority = "high"
        elif self.total >= 15: self.priority = "medium"
        else: self.priority = "low"

def _load_rubric() -> str:
    return (Path(__file__).parent / "rubrics" / "tier1_attack_rubric.md").read_text()

def rank_attacks(attacks: list[dict], context_patent_text: str) -> list[AttackScore]:
    rubric = _load_rubric()
    prompt = f"""You are a senior patent attorney triaging adversarial findings.
Rate each attack on 3 axes (0-10 each).

RUBRIC:
{rubric}

PATENT CONTEXT:
{context_patent_text[:6000]}

ATTACKS:
{json.dumps(attacks, indent=2)}

Return ONLY a JSON array with one object per attack:
[{{"id": "...", "severity": N, "specificity": N, "remediability": N}}, ...]
"""
    result = subprocess.run(
        ["claude", "-p", prompt, "--model", "sonnet"],
        capture_output=True, text=True, timeout=240,
    )
    raw = result.stdout
    start = raw.find("[")
    end = raw.rfind("]") + 1
    data = json.loads(raw[start:end])
    return [AttackScore(d["id"], d["severity"], d["specificity"], d["remediability"], priority="") for d in data]
```

- [ ] **Step 4: Write tier1_attack_rubric.md**

```markdown
# Tier 1 Attack Rubric

## severity (0-10) — How much does this attack threaten the patent?
  0-2:  Cosmetic (typo, stylistic)
  3-5:  Minor claim scope adjustment
  6-8:  Material weakness (one rejection path)
  9-10: Existential (invalidates an independent claim)

## specificity (0-10) — How actionable is the finding?
  0-2:  Vague ("claim is too broad")
  3-5:  Identifies problem area
  6-8:  Identifies exact claim element + recommended direction
  9-10: Proposes concrete replacement language

## remediability (0-10) — How easily can it be fixed?
  0-2:  Requires full restructure
  3-5:  Requires significant drafting
  6-8:  Local claim edit
  9-10: Trivial word-level fix

## Priority
  - high:   total ≥ 22
  - medium: total 15-21
  - low:    total < 15
```

- [ ] **Step 5: Commit**

```bash
git add patent-autoresearch/judge.py patent-autoresearch/rubrics/tier1_attack_rubric.md patent-autoresearch/test_judge.py
git commit -m "feat(patent-autoresearch): Tier 1 attack prioritizer + rubric"
```

---

## Chunk 2: Tier 1 — automated adversarial review (attack discovery)

This chunk builds the automated equivalent of the manual adversarial reviews at
`drafts/adversarial-review.md`, `drafts/adversarial-review-r2.md`, and
`drafts/adversarial-review-r3.md`. Instead of manually dispatching one or two
hostile reviewers, we fan out 6 personas in parallel, each with a different
attack specialty, and an LLM judge prioritizes the findings.

### Task 4: Write run_tier1_attack.py (parallel adversarial fanout)

**Files:**
- Create: `patent-autoresearch/run_tier1_attack.py`
- Test: `patent-autoresearch/test_tier1.py`

- [ ] **Step 1: Write the failing test**

```python
# patent-autoresearch/test_tier1.py
import json
import pytest
from pathlib import Path
from run_tier1_attack import run_tier1, PERSONAS_PATH

@pytest.mark.integration
def test_run_tier1_produces_attacks_from_all_personas(tmp_path):
    patent_text = "Claim 1. A method comprising: (a) ... (b) ..."
    output_dir = tmp_path / "iter_001"
    output_dir.mkdir()

    result = run_tier1(
        patent_text=patent_text,
        output_dir=output_dir,
        personas_path=PERSONAS_PATH,
    )

    assert (output_dir / "tier1_attacks.json").exists()
    attacks = json.loads((output_dir / "tier1_attacks.json").read_text())
    persona_ids = {a["persona"] for a in attacks}
    # At least 4 personas should produce findings on a non-trivial patent
    assert len(persona_ids) >= 4
    for a in attacks:
        assert "id" in a and "persona" in a and "finding" in a and "claim_refs" in a
```

- [ ] **Step 2: Run test, expect FAIL**

- [ ] **Step 3: Write run_tier1_attack.py**

```python
# patent-autoresearch/run_tier1_attack.py
"""Tier 1: Dispatch 6 hostile reviewer personas in parallel. Collect attacks."""
from __future__ import annotations
import argparse
import json
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PERSONAS_PATH = HERE / "personas.json"
PRIOR_ART_PATH = HERE / "prior_art.json"
CASE_LAW_PATH = HERE / "case_law.json"

ATTACK_PROMPT = """You are a hostile patent reviewer playing the role: {role}.
Focus: {focus}

Your job: find specific, actionable weaknesses in the following provisional patent.
Each finding should identify claim numbers, specific language, and recommend a direction.
Be brutal. No compliments.

PATENT:
{patent_text}

PRIOR ART (use these references; cite any applicable):
{prior_art}

CASE LAW (ground your 101/103/112 arguments):
{case_law}

Return ONLY a JSON array, one object per finding:
[
  {{
    "id": "{persona_id}_<short_slug>",
    "persona": "{persona_id}",
    "claim_refs": [1, 9, 15],
    "category": "101" | "103" | "112" | "design_around" | "accuracy",
    "finding": "specific weakness in 2-4 sentences",
    "recommended_direction": "concrete fix suggestion",
    "evidence": "quote claim language + prior-art or case-law citation"
  }},
  ...
]
"""

def _run_persona(persona: dict, patent_text: str, prior_art: list, case_law: list) -> list[dict]:
    prompt = ATTACK_PROMPT.format(
        role=persona["role"],
        focus=", ".join(persona["focus"]),
        persona_id=persona["id"],
        patent_text=patent_text[:30000],
        prior_art=json.dumps(prior_art, indent=2)[:8000],
        case_law=json.dumps(case_law, indent=2)[:6000],
    )
    result = subprocess.run(
        ["claude", "-p", prompt, "--model", "opus"],
        capture_output=True, text=True, timeout=360,
    )
    raw = result.stdout
    try:
        start = raw.find("[")
        end = raw.rfind("]") + 1
        attacks = json.loads(raw[start:end])
        for a in attacks:
            a.setdefault("persona", persona["id"])
        return attacks
    except (ValueError, json.JSONDecodeError) as e:
        return [{"id": f"{persona['id']}_parse_error", "persona": persona["id"],
                 "claim_refs": [], "category": "meta",
                 "finding": f"Failed to parse response: {e}", "recommended_direction": "",
                 "evidence": raw[:500]}]

def run_tier1(
    patent_text: str,
    output_dir: Path,
    personas_path: Path = PERSONAS_PATH,
) -> dict[str, Any]:
    personas = json.loads(personas_path.read_text())
    prior_art = json.loads(PRIOR_ART_PATH.read_text())
    case_law = json.loads(CASE_LAW_PATH.read_text())

    all_attacks: list[dict] = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = {
            ex.submit(_run_persona, p, patent_text, prior_art, case_law): p["id"]
            for p in personas
        }
        for fut in as_completed(futures):
            persona_id = futures[fut]
            try:
                attacks = fut.result()
                all_attacks.extend(attacks)
            except Exception as e:
                all_attacks.append({
                    "id": f"{persona_id}_exception",
                    "persona": persona_id,
                    "claim_refs": [],
                    "category": "meta",
                    "finding": f"Persona execution failed: {e}",
                    "recommended_direction": "",
                    "evidence": "",
                })

    (output_dir / "tier1_attacks.json").write_text(json.dumps(all_attacks, indent=2))
    return {"attacks": all_attacks, "output_dir": str(output_dir)}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--patent", required=True, help="Path to patent .md")
    ap.add_argument("--output-dir", required=True, help="Iteration output dir")
    args = ap.parse_args()

    patent_text = Path(args.patent).read_text()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    result = run_tier1(patent_text, output_dir)
    print(f"Wrote {len(result['attacks'])} attacks to {output_dir / 'tier1_attacks.json'}")

if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test**

Run: `cd patent-autoresearch && python3 -m pytest test_tier1.py -v -m integration`
Expected: PASS (takes 3-5 min due to 6 parallel Claude CLI calls)

- [ ] **Step 5: Commit**

```bash
git add patent-autoresearch/run_tier1_attack.py patent-autoresearch/test_tier1.py
git commit -m "feat(patent-autoresearch): Tier 1 parallel adversarial fanout"
```

---

### Task 5: Integrate judge into Tier 1 (scored attacks + human gate stub)

**Files:**
- Modify: `patent-autoresearch/run_tier1_attack.py` (add scoring step)
- Test: Extend `test_tier1.py`

- [ ] **Step 1: Write the failing test**

```python
# Extend test_tier1.py
@pytest.mark.integration
def test_run_tier1_produces_scored_attacks(tmp_path):
    patent_text = "..."
    output_dir = tmp_path / "iter_002"
    output_dir.mkdir()
    run_tier1(patent_text, output_dir)
    assert (output_dir / "tier1_scored.json").exists()
    scored = json.loads((output_dir / "tier1_scored.json").read_text())
    for s in scored:
        assert "severity" in s and "priority" in s
```

- [ ] **Step 2: Extend run_tier1 to invoke judge.py**

Pseudocode additions:
```python
from judge import rank_attacks

# After collecting all_attacks:
attack_scores = rank_attacks(all_attacks, patent_text)
scored = []
for a in all_attacks:
    score = next((s for s in attack_scores if s.attack_id == a["id"]), None)
    if score:
        scored.append({**a, **asdict(score)})
(output_dir / "tier1_scored.json").write_text(json.dumps(scored, indent=2))

# Pre-populate selected.json with top N high-priority attacks (≤ 8)
selected = [s for s in scored if s["priority"] == "high"][:8]
(output_dir / "tier1_selected.json").write_text(json.dumps(selected, indent=2))
```

- [ ] **Step 3: Run test, confirm PASS**

- [ ] **Step 4: Commit**

```bash
git add patent-autoresearch/run_tier1_attack.py patent-autoresearch/test_tier1.py
git commit -m "feat(patent-autoresearch): Tier 1 scored-attacks + high-priority selection"
```

---

## Chunk 3: Tier 2 — automated remediation (candidate generation + scoring + mutation)

This chunk builds the automated equivalent of the manual fix-and-retry cycle
from rounds 1-3. Each round manually authored specific claim rewrites (e.g.,
M1's concrete enumeration replacing "sole authoritative source", M2's genus
broadening — which the r3 review then rejected). The automated version
generates K alternatives per weakness, scores them on 5 dimensions, and
applies the highest-scoring one — so a self-inflicted wound like M2 would
have been caught by the scoring stage before application.

### Task 6: Write run_tier2_claim.py (candidate claim generation)

**Files:**
- Create: `patent-autoresearch/run_tier2_claim.py`
- Test: `patent-autoresearch/test_tier2.py`

- [ ] **Step 1: Write the failing test**

```python
# patent-autoresearch/test_tier2.py
import json
import pytest
from pathlib import Path
from run_tier2_claim import generate_candidates_for_attack

@pytest.mark.integration
def test_generate_candidates_returns_k_variants(tmp_path):
    attack = {
        "id": "alice_specialist_1",
        "claim_refs": [1],
        "category": "101",
        "finding": "Claim 1(d)(iii) is abstract state write",
        "recommended_direction": "Anchor with concrete circuit constraint reference",
    }
    candidates = generate_candidates_for_attack(
        attack=attack,
        patent_text="...",
        k=3,
    )
    assert len(candidates) == 3
    for c in candidates:
        assert "id" in c and "claim_text" in c and "rationale" in c
        assert c["targets_weakness"] == attack["id"]
```

- [ ] **Step 2: Run test, expect FAIL**

- [ ] **Step 3: Write run_tier2_claim.py**

```python
# patent-autoresearch/run_tier2_claim.py
"""Tier 2: For each selected attack, generate K candidate claim rewrites."""
from __future__ import annotations
import argparse
import json
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent

CANDIDATE_PROMPT = """You are a senior patent attorney drafting revised claim language.
A hostile reviewer has identified the following weakness in the patent:

ATTACK:
{attack_json}

PATENT CONTEXT:
{patent_text}

Your task: produce {k} DIFFERENT candidate revisions that address this weakness.
Each candidate must be a SPECIFIC replacement for the identified claim language,
not a philosophical direction. Be concrete. Different candidates should represent
DIFFERENT strategies (e.g., one narrows, one adds a dependent, one rewrites the
limitation as positive structure).

Return ONLY a JSON array with K objects:
[
  {{
    "id": "cand_{attack_id}_01",
    "strategy": "narrow" | "positive_structural" | "dependent_claim" | "genus_with_species" | "delete_problem_language",
    "claim_refs": [N],
    "original_language": "exact text being replaced",
    "claim_text": "exact replacement text",
    "rationale": "why this fixes the weakness, 2-4 sentences",
    "targets_weakness": "{attack_id}",
    "tradeoffs": "what it loses in scope or risk in exchange"
  }},
  ...
]
"""

def generate_candidates_for_attack(attack: dict, patent_text: str, k: int = 3) -> list[dict]:
    prompt = CANDIDATE_PROMPT.format(
        attack_json=json.dumps(attack, indent=2),
        patent_text=patent_text[:20000],
        k=k,
        attack_id=attack["id"],
    )
    result = subprocess.run(
        ["claude", "-p", prompt, "--model", "opus"],
        capture_output=True, text=True, timeout=360,
    )
    raw = result.stdout
    start = raw.find("[")
    end = raw.rfind("]") + 1
    candidates = json.loads(raw[start:end])
    for c in candidates:
        c.setdefault("targets_weakness", attack["id"])
    return candidates

def generate_candidates_for_run(
    selected_attacks: list[dict],
    patent_text: str,
    output_dir: Path,
    k: int = 3,
) -> list[dict]:
    all_candidates: list[dict] = []
    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = {
            ex.submit(generate_candidates_for_attack, a, patent_text, k): a["id"]
            for a in selected_attacks
        }
        for fut in as_completed(futures):
            attack_id = futures[fut]
            try:
                cands = fut.result()
                all_candidates.extend(cands)
            except Exception as e:
                all_candidates.append({
                    "id": f"cand_{attack_id}_error",
                    "strategy": "error",
                    "claim_text": "",
                    "rationale": f"Generation failed: {e}",
                    "targets_weakness": attack_id,
                })
    (output_dir / "tier2_candidates.json").write_text(json.dumps(all_candidates, indent=2))
    return all_candidates

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selected", required=True, help="Path to tier1_selected.json")
    ap.add_argument("--patent", required=True, help="Path to current patent .md")
    ap.add_argument("--output-dir", required=True, help="Iteration output dir")
    ap.add_argument("--k", type=int, default=3, help="Candidates per attack")
    args = ap.parse_args()

    selected = json.loads(Path(args.selected).read_text())
    patent_text = Path(args.patent).read_text()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    candidates = generate_candidates_for_run(selected, patent_text, output_dir, args.k)
    print(f"Generated {len(candidates)} candidates → {output_dir / 'tier2_candidates.json'}")

if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test, confirm PASS**

- [ ] **Step 5: Commit**

```bash
git add patent-autoresearch/run_tier2_claim.py patent-autoresearch/test_tier2.py
git commit -m "feat(patent-autoresearch): Tier 2 candidate claim generation"
```

---

### Task 7: Wire scoring.py into Tier 2 and pick winners

**Files:**
- Modify: `patent-autoresearch/run_tier2_claim.py`
- Test: Extend `test_tier2.py`

- [ ] **Step 1: Write the failing test**

```python
# test_tier2.py
@pytest.mark.integration
def test_tier2_scores_all_candidates_and_picks_winners(tmp_path):
    output_dir = tmp_path / "iter_003"
    output_dir.mkdir()
    # ... set up selected, patent, call run_tier2_with_scoring ...
    assert (output_dir / "tier2_scored.json").exists()
    assert (output_dir / "tier2_winners.json").exists()
    winners = json.loads((output_dir / "tier2_winners.json").read_text())
    for w in winners:
        assert w["total"] >= 60  # only "apply" or "consider"
```

- [ ] **Step 2: Add scoring + winner selection to run_tier2_claim.py**

```python
# Add to run_tier2_claim.py
from scoring import score_candidate
from dataclasses import asdict

def score_and_pick_winners(
    candidates: list[dict],
    patent_text: str,
    prior_art: list[dict],
    output_dir: Path,
) -> list[dict]:
    scored = []
    for c in candidates:
        try:
            cs = score_candidate(c, patent_text, prior_art)
            entry = {**c, "score": asdict(cs)}
            scored.append(entry)
        except Exception as e:
            scored.append({**c, "score": {"total": 0, "verdict": "reject", "error": str(e)}})
    (output_dir / "tier2_scored.json").write_text(json.dumps(scored, indent=2, default=str))

    # Group by targets_weakness, pick highest-scoring apply/consider per weakness
    by_weakness: dict[str, list[dict]] = {}
    for s in scored:
        by_weakness.setdefault(s["targets_weakness"], []).append(s)
    winners: list[dict] = []
    for weakness, cands in by_weakness.items():
        cands.sort(key=lambda x: x["score"].get("total", 0), reverse=True)
        if cands and cands[0]["score"].get("total", 0) >= 60:
            winners.append(cands[0])
    (output_dir / "tier2_winners.json").write_text(json.dumps(winners, indent=2, default=str))
    return winners
```

- [ ] **Step 3: Run test, confirm PASS**

- [ ] **Step 4: Commit**

```bash
git add patent-autoresearch/run_tier2_claim.py patent-autoresearch/test_tier2.py
git commit -m "feat(patent-autoresearch): Tier 2 scoring + winner selection"
```

---

### Task 8: Write mutator.py (apply winning candidates to patent)

**Files:**
- Create: `patent-autoresearch/mutator.py`
- Test: `patent-autoresearch/test_mutator.py`

- [ ] **Step 1: Write the failing test**

```python
# test_mutator.py
from mutator import apply_mutation, apply_winners

def test_apply_mutation_replaces_exact_text(tmp_path):
    patent = "Claim 1. A method comprising: (a) foo; (b) bar."
    (tmp_path / "p.md").write_text(patent)
    winner = {
        "original_language": "(a) foo;",
        "claim_text": "(a) foo with additional technical anchor;",
        "targets_weakness": "w1",
    }
    new_text = apply_mutation(patent, winner)
    assert "(a) foo with additional technical anchor;" in new_text
    assert "(b) bar." in new_text

def test_apply_mutation_fails_loudly_on_missing_text():
    import pytest
    with pytest.raises(ValueError, match="not found"):
        apply_mutation("text", {"original_language": "missing", "claim_text": "new"})
```

- [ ] **Step 2: Run test, expect FAIL**

- [ ] **Step 3: Write mutator.py**

```python
# patent-autoresearch/mutator.py
"""Apply winning candidate claim mutations to the patent draft.

STRICT: uses exact-string replacement. If original_language isn't found verbatim,
raises ValueError rather than silently applying a wrong edit.
"""
from __future__ import annotations
import json
import shutil
from pathlib import Path

def apply_mutation(patent_text: str, winner: dict) -> str:
    original = winner["original_language"]
    replacement = winner["claim_text"]
    if original not in patent_text:
        raise ValueError(
            f"original_language not found in patent for winner targeting "
            f"{winner.get('targets_weakness', '?')}: {original[:120]!r}"
        )
    # Only replace first occurrence to avoid cascading replaces
    return patent_text.replace(original, replacement, 1)

def apply_winners(patent_path: Path, winners: list[dict], output_path: Path) -> dict:
    patent_text = patent_path.read_text()
    applied = []
    skipped = []
    for w in winners:
        try:
            patent_text = apply_mutation(patent_text, w)
            applied.append(w["id"])
        except ValueError as e:
            skipped.append({"id": w["id"], "reason": str(e)})
    output_path.write_text(patent_text)
    return {"applied": applied, "skipped": skipped}
```

- [ ] **Step 4: Run tests, confirm PASS**

- [ ] **Step 5: Commit**

```bash
git add patent-autoresearch/mutator.py patent-autoresearch/test_mutator.py
git commit -m "feat(patent-autoresearch): strict exact-string mutation applier"
```

---

## Chunk 4: Baseline, orchestrator, and plateau detection

### Task 9: Write baseline.py (score the unmodified patent)

**Files:**
- Create: `patent-autoresearch/baseline.py`
- Test: `patent-autoresearch/test_baseline.py`

- [ ] **Step 1: Write test**

```python
# test_baseline.py
import pytest
from baseline import score_baseline

@pytest.mark.integration
def test_score_baseline_produces_per_claim_score(tmp_path):
    patent = "...complete patent text..."
    result = score_baseline(patent)
    assert "claim_scores" in result
    assert all(k in result["claim_scores"].get("1", {}) for k in ["alice_101", "obviousness_103", "support_112"])
    assert 0 <= result["total"] <= 100
```

- [ ] **Step 2: Write baseline.py**

```python
# patent-autoresearch/baseline.py
"""Score the current patent draft as-is. Serves as iteration 0 baseline."""
from __future__ import annotations
import json
import subprocess
from pathlib import Path

BASELINE_PROMPT = """You are a panel of 4 adversarial reviewers (USPTO examiner,
competitor attorney, 101 specialist, 112 specialist) jointly scoring a provisional
patent on 5 dimensions.

PATENT:
{patent_text}

Score the ENTIRE patent (independent claims only, 1/9/15/16) on:
- alice_101 (0-20 per independent claim, averaged)
- obviousness_103 (0-20)
- support_112 (0-20)
- design_around (0-20)
- scope (0-20)

Return JSON:
{{
  "alice_101": {{"points": N, "per_claim": {{"1": N, "9": N, "15": N, "16": N}}, "critique": "..."}},
  "obviousness_103": {{"points": N, "per_claim": {{...}}, "critique": "..."}},
  "support_112": {{"points": N, "per_claim": {{...}}, "critique": "..."}},
  "design_around": {{"points": N, "critique": "..."}},
  "scope": {{"points": N, "critique": "..."}},
  "total": N
}}
"""

def score_baseline(patent_text: str) -> dict:
    prompt = BASELINE_PROMPT.format(patent_text=patent_text[:30000])
    result = subprocess.run(
        ["claude", "-p", prompt, "--model", "opus"],
        capture_output=True, text=True, timeout=600,
    )
    raw = result.stdout
    start = raw.find("{")
    end = raw.rfind("}") + 1
    data = json.loads(raw[start:end])
    # Validate shape
    for k in ["alice_101", "obviousness_103", "support_112", "design_around", "scope", "total"]:
        assert k in data, f"Missing key {k} in baseline response"
    return data
```

- [ ] **Step 3: Test + commit**

---

### Task 10: Write plateau detection

**Files:**
- Create: `patent-autoresearch/history/plateau_detector.py`
- Test: Inline unit tests

- [ ] **Step 1: Write plateau_detector.py**

```python
# patent-autoresearch/history/plateau_detector.py
"""Detect when iteration should stop."""
from __future__ import annotations

def should_stop(
    trajectory: list[dict],
    max_iters: int = 10,
    plateau_window: int = 3,
    plateau_delta: float = 2.0,
    target_score: float = 90.0,
) -> tuple[bool, str]:
    if not trajectory:
        return False, "no iterations run yet"
    latest = trajectory[-1]["total"]
    if latest >= target_score:
        return True, f"target score {target_score} reached (latest={latest})"
    if len(trajectory) >= max_iters:
        return True, f"max iterations {max_iters} reached"
    if len(trajectory) < plateau_window + 1:
        return False, f"need {plateau_window + 1} iterations for plateau check"
    window = [t["total"] for t in trajectory[-(plateau_window + 1):]]
    deltas = [abs(window[i+1] - window[i]) for i in range(plateau_window)]
    if max(deltas) < plateau_delta:
        return True, f"plateau: last {plateau_window} deltas all < {plateau_delta}"
    return False, f"still improving (recent deltas: {deltas})"

def test_should_stop_max_iters():
    traj = [{"total": 50}] * 10
    stop, reason = should_stop(traj, max_iters=10)
    assert stop and "max iterations" in reason

def test_should_stop_target_reached():
    traj = [{"total": 95}]
    stop, _ = should_stop(traj, target_score=90)
    assert stop

def test_plateau_detection():
    traj = [{"total": 50}, {"total": 55}, {"total": 56}, {"total": 56.5}, {"total": 57}]
    stop, reason = should_stop(traj, plateau_window=3, plateau_delta=2.0)
    assert stop and "plateau" in reason
```

- [ ] **Step 2: Run inline tests: `python3 -m pytest history/plateau_detector.py`**

- [ ] **Step 3: Commit**

---

### Task 11: Write run_loop.py (orchestrator)

**Files:**
- Create: `patent-autoresearch/run_loop.py`

- [ ] **Step 1: Write orchestrator**

```python
# patent-autoresearch/run_loop.py
"""Main orchestrator. Runs the loop:
  baseline → [tier1 → human_gate → tier2 → apply] × N → plateau_check
"""
from __future__ import annotations
import argparse
import json
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

from run_tier1_attack import run_tier1
from judge import rank_attacks
from run_tier2_claim import generate_candidates_for_run, score_and_pick_winners
from mutator import apply_winners
from baseline import score_baseline
import sys
sys.path.insert(0, str(Path(__file__).parent / "history"))
from plateau_detector import should_stop

HERE = Path(__file__).resolve().parent
PATENT_PATH = HERE.parent / "drafts" / "provisional-patent-identityos.md"
HISTORY_PATH = HERE / "history" / "score_trajectory.jsonl"
RUNS_DIR = HERE / "runs"

def run_iteration(iter_num: int, patent_path: Path, auto_approve: bool = False) -> dict:
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    iter_dir = RUNS_DIR / f"iter_{iter_num:03d}_{ts}"
    iter_dir.mkdir(parents=True, exist_ok=True)

    # Snapshot current patent
    shutil.copy(patent_path, iter_dir / "current_patent.md")
    patent_text = patent_path.read_text()

    # Tier 1
    print(f"[iter {iter_num}] Tier 1: dispatching adversarial reviewers...")
    run_tier1(patent_text, iter_dir)

    # Human gate (or auto-approve)
    selected_path = iter_dir / "tier1_selected.json"
    if not auto_approve:
        print(f"[iter {iter_num}] Human gate: review {selected_path} and press Enter to continue.")
        input()

    selected = json.loads(selected_path.read_text())
    if not selected:
        print(f"[iter {iter_num}] No high-priority attacks selected; skipping Tier 2.")
        return {"iter": iter_num, "skipped": True}

    # Tier 2
    print(f"[iter {iter_num}] Tier 2: generating candidates for {len(selected)} attacks...")
    candidates = generate_candidates_for_run(selected, patent_text, iter_dir, k=3)

    prior_art = json.loads((HERE / "prior_art.json").read_text())
    winners = score_and_pick_winners(candidates, patent_text, prior_art, iter_dir)

    if not winners:
        print(f"[iter {iter_num}] No winners scored high enough; skipping mutation.")
        return {"iter": iter_num, "winners": 0}

    # Apply mutations
    patent_after = iter_dir / "patent_after.md"
    result = apply_winners(patent_path, winners, patent_after)
    print(f"[iter {iter_num}] Applied {len(result['applied'])} / skipped {len(result['skipped'])}")

    # Human review before overwriting live patent
    if not auto_approve:
        print(f"[iter {iter_num}] Review {patent_after} vs {patent_path}.")
        print("Press Enter to accept and overwrite the live patent, or Ctrl-C to abort.")
        input()

    shutil.copy(patent_after, patent_path)

    # Score the new patent (BEFORE overwriting live patent to preserve rollback option)
    print(f"[iter {iter_num}] Scoring new patent...")
    new_score = score_baseline(patent_after.read_text())
    new_score["iter"] = iter_num
    new_score["ts"] = ts

    # Regression detection: guard against another M2-style self-inflicted wound.
    prev_trajectory = load_trajectory()
    if prev_trajectory:
        prev_total = prev_trajectory[-1]["total"]
        if new_score["total"] < prev_total - 1.0:  # 1pt tolerance for judge noise
            print(f"[iter {iter_num}] ⚠️  REGRESSION: {prev_total:.1f} → {new_score['total']:.1f}")
            print(f"Applied mutations: {result['applied']}")
            print("Skipped mutations: ", result["skipped"])
            print(f"Review the diff: diff {iter_dir / 'current_patent.md'} {patent_after}")
            if not auto_approve:
                print("Press Enter to accept the regression (rare, only if the drop is expected), or Ctrl-C to abort.")
                input()
            else:
                print("Auto-approve set, but regression detected — aborting loop for safety.")
                sys.exit(1)

    with HISTORY_PATH.open("a") as f:
        f.write(json.dumps(new_score) + "\n")

    # Iteration report
    report = iter_dir / "iteration_report.md"
    report.write_text(f"""# Iteration {iter_num} Report

- Timestamp: {ts}
- Attacks generated: {len(json.loads((iter_dir / 'tier1_attacks.json').read_text()))}
- Attacks selected (high priority): {len(selected)}
- Candidates generated: {len(candidates)}
- Winners applied: {len(result['applied'])}
- Winners skipped: {len(result['skipped'])}
- New total score: {new_score['total']}

See individual JSON files in this directory for details.
""")

    # Emit drop-in successor to drafts/adversarial-review-r{1,2,3}.md.
    # Rounds 1-3 were manual (Codex, Opus subagent); rounds 4+ are auto-generated by this loop.
    round_num = iter_num + 3  # r1-r3 were manual; this is the Nth automated round
    reports_dir = HERE / "reports"
    reports_dir.mkdir(exist_ok=True)
    adv_report_path = reports_dir / f"adversarial-review-r{round_num}.md"
    attacks = json.loads((iter_dir / "tier1_scored.json").read_text())
    by_category: dict[str, list] = {}
    for a in attacks:
        by_category.setdefault(a.get("category", "other"), []).append(a)

    md = [f"# Adversarial Review — Round {round_num} (automated)"]
    md.append(f"Generated by patent-autoresearch loop iteration {iter_num} on {ts}")
    md.append(f"Baseline score: {trajectory[-1]['total'] if (trajectory := load_trajectory()) else 'n/a'}")
    md.append(f"Post-iteration score: {new_score['total']}")
    md.append(f"Delta: {new_score['total'] - (trajectory[-2]['total'] if len(trajectory) > 1 else trajectory[0]['total']):+.1f}")
    md.append("\n## Attacks by Category\n")
    for cat, items in sorted(by_category.items()):
        md.append(f"### {cat} ({len(items)} findings)")
        for a in items:
            md.append(f"- **[{a.get('priority', '?')}]** ({a.get('persona', '?')}) {a.get('finding', '')[:300]}")
            if a.get("evidence"):
                md.append(f"  - Evidence: {a['evidence'][:200]}")
        md.append("")
    md.append("\n## Applied Mutations\n")
    for winner_id in result["applied"]:
        winner = next((w for w in winners if w["id"] == winner_id), None)
        if winner:
            md.append(f"- **{winner_id}** targeting `{winner.get('targets_weakness', '?')}`: {winner.get('rationale', '')[:300]}")
    if result["skipped"]:
        md.append("\n## Skipped Mutations (mismatch)\n")
        for s in result["skipped"]:
            md.append(f"- **{s['id']}**: {s['reason']}")
    adv_report_path.write_text("\n".join(md))

    return new_score

def load_trajectory() -> list[dict]:
    if not HISTORY_PATH.exists():
        return []
    return [json.loads(l) for l in HISTORY_PATH.read_text().splitlines() if l.strip()]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-iters", type=int, default=10)
    ap.add_argument("--target-score", type=float, default=90.0)
    ap.add_argument("--auto-approve", action="store_true", help="Skip human gates (dangerous)")
    ap.add_argument("--baseline-only", action="store_true", help="Just score baseline and exit")
    args = ap.parse_args()

    # Initial baseline
    if not load_trajectory():
        print("No trajectory found; running baseline...")
        baseline = score_baseline(PATENT_PATH.read_text())
        baseline["iter"] = 0
        baseline["ts"] = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        HISTORY_PATH.parent.mkdir(exist_ok=True)
        with HISTORY_PATH.open("a") as f:
            f.write(json.dumps(baseline) + "\n")
        print(f"Baseline: total={baseline['total']}")

    if args.baseline_only:
        return

    # Loop
    for i in range(1, args.max_iters + 1):
        trajectory = load_trajectory()
        stop, reason = should_stop(trajectory, max_iters=args.max_iters, target_score=args.target_score)
        if stop:
            print(f"Stopping: {reason}")
            break
        run_iteration(i, PATENT_PATH, args.auto_approve)

    print("Loop complete.")

if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Test baseline-only path**

```bash
cd patent-autoresearch && python3 run_loop.py --baseline-only
# Verify history/score_trajectory.jsonl has one entry
```

- [ ] **Step 3: Commit**

```bash
git add patent-autoresearch/run_loop.py
git commit -m "feat(patent-autoresearch): orchestrator with baseline + human gates"
```

---

### Task 12: Dry-run the full loop on current patent

**Files:** None modified; verification only.

- [ ] **Step 1: Run dry-run baseline**

```bash
cd /Users/lordviswa/Projects/identityos/patent-autoresearch
python3 run_loop.py --baseline-only
```

Expected: `history/score_trajectory.jsonl` has 1 entry. Print shows total score.

- [ ] **Step 2: Run one full iteration with human gates**

```bash
python3 run_loop.py --max-iters 1
```

Expected output: Tier 1 produces attacks → human review stops at `tier1_selected.json` → proceed → Tier 2 produces candidates → scored → winners → mutation proposed at `runs/iter_001_*/patent_after.md` → human review → accept or Ctrl-C.

- [ ] **Step 3: If accepted, verify patent_after.md compiles cleanly**

```bash
# diff the two patents
diff drafts/provisional-patent-identityos.md \
     patent-autoresearch/runs/iter_001_*/current_patent.md | head -100
```

- [ ] **Step 4: Commit iteration 1 output**

```bash
git add patent-autoresearch/runs/ patent-autoresearch/history/
git commit -m "run: patent-autoresearch iteration 1 (baseline + 1 loop)"
```

---

## Chunk 5: Convergence, reporting, and runbook

### Task 13: Write final summary report generator

**Files:**
- Create: `patent-autoresearch/scripts/summarize_run.py`

- [ ] **Step 1: Write summarizer**

Reads `history/score_trajectory.jsonl` + all `runs/iter_*/iteration_report.md` and produces a single `FINAL_REPORT.md` with:
- Score trajectory graph (ASCII)
- Per-iteration delta
- Winning candidates applied
- Skipped candidates (and why)
- Final patent diff from baseline

```python
# patent-autoresearch/scripts/summarize_run.py
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
HIST = HERE / "history" / "score_trajectory.jsonl"
RUNS = HERE / "runs"

def render_trajectory_chart(traj: list[dict]) -> str:
    if not traj:
        return "(no data)"
    maxv = max(t["total"] for t in traj)
    minv = min(t["total"] for t in traj)
    lines = []
    for t in traj:
        bar = "█" * int((t["total"] / 100) * 40)
        lines.append(f"iter {t['iter']:3d}  {bar} {t['total']:.1f}")
    return "\n".join(lines)

def main():
    traj = [json.loads(l) for l in HIST.read_text().splitlines() if l.strip()] if HIST.exists() else []
    chart = render_trajectory_chart(traj)
    print(f"# Patent Autoresearch Final Report\n\n## Score Trajectory\n\n```\n{chart}\n```\n")
    if traj:
        print(f"- Baseline: {traj[0]['total']:.1f}")
        print(f"- Final:    {traj[-1]['total']:.1f}")
        print(f"- Delta:    {traj[-1]['total'] - traj[0]['total']:+.1f}")

if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Commit**

---

### Task 14: Write README.md runbook

**Files:**
- Modify: `patent-autoresearch/README.md`

- [ ] **Step 1: Write full runbook**

Contents:
- Prerequisites (Claude CLI logged in per feedback_claude_max; python 3.13; no pip installs needed)
- Architecture diagram
- First-run: baseline-only
- Running the full loop (with human gates)
- Running auto-approve (dangerous; for later refinement)
- Reading outputs: trajectory, per-iter reports, final report
- How to add new prior art references (edit prior_art.json)
- How to add new reviewer personas (edit personas.json)
- Troubleshooting: Claude CLI timeouts, JSON parse failures, mutation conflicts
- Safety: the loop NEVER deletes the patent; always writes to `runs/`; only overwrites `drafts/provisional-patent-identityos.md` after human approval

- [ ] **Step 2: Commit**

```bash
git add patent-autoresearch/README.md
git commit -m "docs(patent-autoresearch): runbook"
```

---

### Task 15: Acceptance test — run loop to completion and check monotonic-or-justified improvement

**Files:** None new. Full integration test.

- [ ] **Step 1: Run 3 iterations end-to-end**

```bash
cd /Users/lordviswa/Projects/identityos/patent-autoresearch
python3 run_loop.py --max-iters 3
# Review each iteration at its human gate
```

- [ ] **Step 2: Verify trajectory**

```bash
python3 scripts/summarize_run.py
```

Expected: each iteration either improved total score OR is explicitly documented in `iteration_report.md` as "no winners / no mutation applied." Regressions (new total < previous total) should NOT occur with the safeguards in place — if they do, it's a bug in `apply_winners` or `score_baseline`.

- [ ] **Step 3: Commit final state**

```bash
git add patent-autoresearch/
git commit -m "run: patent-autoresearch completed 3-iter pass"
git push
```

- [ ] **Step 4: Summarize results in a commit message and a new `drafts/adversarial-review-r4.md`**

Document the final patent state, what changed from baseline, remaining weaknesses that scored below winner threshold, and attorney-review recommendations.

---

## Acceptance Criteria

0. **Adversarial review continuity:** After iteration 1, `patent-autoresearch/reports/adversarial-review-r4.md` exists and is structured like `drafts/adversarial-review-r3.md` (findings by category, priority labels, applied mutations). After iteration N, r{3+N}.md exists. The drop-in successor lineage is preserved.

1. **Baseline scoring works:** `python3 run_loop.py --baseline-only` runs without error, writes one entry to `history/score_trajectory.jsonl`, prints a total score in [0, 100].

2. **Tier 1 parallelism works:** `run_tier1` executes all 6 personas concurrently, collects ≥ 6 distinct findings (assuming the patent is non-trivial), writes both `tier1_attacks.json` and `tier1_scored.json`.

3. **Human gate functions:** Between Tier 1 and Tier 2, the loop pauses and waits for `input()`. The user can edit `tier1_selected.json` before resuming.

4. **Tier 2 generates K candidates per selected attack:** Default K=3, confirmed by counting entries in `tier2_candidates.json`.

5. **Scoring returns 5 dimensions:** Each candidate score in `tier2_scored.json` has points for alice_101, obviousness_103, support_112, design_around, and scope.

6. **Winner selection is conservative:** Only candidates with total ≥ 60 are applied. Winners are chosen one-per-weakness (the highest-scoring candidate per `targets_weakness`).

7. **Mutations are strict:** `apply_mutation` raises ValueError rather than apply a mismatched edit. `apply_winners` records skipped mutations in the iteration report.

8. **Before overwriting live patent:** The loop pauses for human review of `patent_after.md` vs the live draft.

9. **Plateau detection stops the loop:** After 3 iterations with <2 pt deltas, the loop stops automatically without needing Ctrl-C.

10. **Final report prints trajectory chart:** `scripts/summarize_run.py` prints an ASCII bar chart showing score evolution across iterations.

11. **Seed-findings dedup:** Tier 1 judge cross-references `seed_findings.json` and down-ranks attacks that replicate already-resolved issues (r1 nonce equality, r1 agent revocation key mismatch, etc.) — preventing the loop from burning cycles re-attacking fixes already made.

12. **Regression detection:** If any iteration produces a score lower than the previous, the orchestrator pauses, prints a regression warning (including which mutation caused it), and requires human confirmation before proceeding. This is the guard against another M2-style self-inflicted wound.

---

## Dependencies and Invariants

- **Claude CLI must be logged in** per user feedback memory (feedback_claude_max). Do not use anthropic SDK with API keys.
- **No package installs.** Use only Python stdlib + subprocess. Anthropic SDK not required.
- **All work in `patent-autoresearch/`**. Do not modify `circuits/`, `contracts/`, or any top-level file except `drafts/provisional-patent-identityos.md` (and only after human approval).
- **Git commits after every task.** Enables rollback if a mutation regresses.
- **No downloads during runs.** Prior art references are static JSON; do not fetch URLs.
- **Human gates are default-on.** The `--auto-approve` flag exists only for late-stage refinement runs where the loop has already been validated.

## Out of Scope (deferred to post-filing)

- Automatic USPTO filing integration
- Patent drawing generation (ASCII → formal drawings)
- Multi-patent coordination (GeniusComply, ZKProva cross-references)
- Real-time prior art search (currently curated static list)
- Attorney-review auto-dispatch

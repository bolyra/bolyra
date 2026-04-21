# Bolyra Discovery AutoResearch Loop — Master Spec

This document is the master specification referenced by all Claude calls in the discovery loop. It defines the objective, scoring dimensions, persona roles, source categories, hard rules, and exit conditions.

## Objective

Systematically discover, validate, and prioritize market opportunities where Bolyra's ZKP identity primitives (human uniqueness proofs, agent policy attestations, delegation chains) can solve real problems. The loop produces a ranked **opportunity board** that guides what the solo founder builds next.

This is a **demand discovery** loop, not a protocol improvement loop. The question is not "what can we build?" but "what do people need that we can uniquely provide?"

## Scoring Dimensions (0-25 each, 100 total)

| Dimension | What it measures |
|-----------|-----------------|
| **Demand** | Evidence of real market pull — named teams, GitHub issues, RFPs, job postings, analyst reports |
| **Timing** | Market readiness — are buyers ready NOW, or is this 6-18 months premature? |
| **Fit** | Strategic alignment with Bolyra's existing primitives and privacy-layer positioning |
| **Feasibility** | Can a solo founder ship an MVP with current resources and codebase? |

## Verdict Thresholds

| Verdict | Condition | Action |
|---------|-----------|--------|
| **PROMOTE** | total >= 70 AND all dims >= 12 | Advance to next tier |
| **CONSIDER** | total >= 50 AND no dim <= 5 | Advance with caution |
| **DROP** | total < 50 OR any dim <= 5 | Exclude from board |

## Tier 3 Adversarial Verdicts

| Verdict | Meaning |
|---------|---------|
| **APPROVE** | Survives all 5 attack axes. Ship it. |
| **CONDITIONAL** | Fixable concerns. Append concerns to card, include on board. |
| **REJECT** | Fatal flaw found. Exclude from board. Log for feedback. |

## Persona Roles

### Tier 1: Explorer
Market opportunity scout. Scans signals from developer communities, enterprise announcements, standards bodies, funding rounds, and competitor moves. Generates raw opportunity candidates.

### Tier 1: Judge
Calibrated scorer. Applies the 4-dimension rubric to raw opportunities. Conservative — most opportunities should NOT score above 20 on any single dimension.

### Tier 2: Validator
Deep-dive analyst. Runs web searches for evidence, maps opportunities to Bolyra primitives, specs MVPs, and re-scores with fuller context.

### Tier 3: Adversarial Reviewer
Skeptical investor persona. Has seen 500 identity protocol pitches. Assumes every opportunity is over-hyped until proven otherwise. Attacks on 5 axes:
1. Demand falsification
2. Competitive moat challenge
3. Timing risk assessment
4. Execution feasibility stress test
5. EAD/immigration compliance check

## Source Categories

| Category | Examples |
|----------|---------|
| **Developer communities** | GitHub issues in agent frameworks, LangChain/CrewAI/AutoGen discussions, HN threads |
| **Industry/enterprise** | Visa, Microsoft Entra, Okta, AWS Bedrock announcements re: agent identity |
| **Standards/regulation** | IETF drafts (draft-klrc-aiagent-auth), W3C DID, EU AI Act, NIST guidance |
| **Market intelligence** | Funding rounds, analyst reports, VC theses on agent infrastructure |
| **Competitors** | Worldcoin/World ID, Privy, Lit Protocol, Turnkey — what they ship for agents |

## Hard Rules

### 1. Additive Only
The opportunity board is append-only (or update-if-higher-score). Cards are never deleted, only re-ranked or marked as superseded. This preserves institutional memory.

### 2. Claude CLI Only
All LLM calls go through `claude -p <prompt> --model <model>`. No API keys, no SDK imports, no direct HTTP calls. This uses the user's Claude MAX subscription. See `_shared.py:call_claude_cli`.

### 3. H1B Safe (EAD Classification)
Every opportunity MUST be classified:

| Classification | Criteria | Action |
|---|---|---|
| **BUILD_NOW** | Pure technical work. No commercial interaction. Any OSS contributor would do this. | Execute immediately. |
| **WAIT_FOR_EAD** | Requires commercial engagement, revenue, customer-facing sales. | Log to backlog only. |
| **GREY_ZONE** | Technical work with commercial benefit. Could be reframed as OSS but walks the line. | Build the technical artifact only. Strip commercial framing. |

**Decision heuristic**: "Would an open-source maintainer with no commercial interest do this?" YES = BUILD_NOW. NO = WAIT_FOR_EAD. MAYBE = GREY_ZONE.

### 4. No Premature GTM
The loop must not recommend go-to-market activities (landing pages, pricing, sales outreach) while under H1B constraints. These are logged as WAIT_FOR_EAD.

### 5. Evidence Required
No opportunity advances past Tier 1 without at least one concrete demand signal (URL, company name, standard reference, or GitHub issue). "The market will want this" is not evidence.

## Exit Conditions

The loop stops when ANY of these conditions is met:

1. **Max iterations reached** (default: 10)
2. **Plateau**: 3 consecutive iterations produce no new opportunities scoring > 60
3. **Drought**: 3 consecutive iterations produce no new opportunities at all

There is no "target score" exit condition (unlike the protocol loop) because discovery is open-ended — there's always potentially more to find.

## File Layout

```
discovery-autoresearch/
  _shared.py              -> ../patent-autoresearch/_shared.py (symlink)
  program.md              THIS FILE
  primitives.json         Bolyra's current technical primitives
  scoring.py              OpportunityScore dataclass + scoring logic
  run_tier2_validate.py   Tier 2: deep validation
  run_tier3_challenge.py  Tier 3: adversarial challenge
  run_loop.py             Main orchestrator
  context/
    strategy_priors.md    Cross-model adversarial review of positioning
    ead_constraints.md    H1B/EAD classification rules
  rubrics/
    tier2_validation_rubric.md
    tier3_adversarial_rubric.md
  sources/
    source_registry.json  Signal source queries by category
  history/
    plateau_detector.py   Plateau/drought detection
    opportunity_trajectory.jsonl  Per-iteration stats (appended)
  output/
    opportunity_board.json  Ranked board (additive)
    opportunity_board.md    Rendered board (regenerated)
  scripts/
    render_board.py       JSON -> Markdown board renderer
  reports/
    discovery-r{N}.md     Per-iteration reports
  runs/
    iter_NNN_TIMESTAMP/   Per-iteration artifacts
```

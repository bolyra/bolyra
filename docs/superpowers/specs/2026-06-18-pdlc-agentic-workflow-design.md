# PDLC Agentic Workflow — Design Spec

**Date:** 2026-06-18
**Author:** Viswa + Claude Opus 4.6
**Status:** Approved
**Scope:** Bolyra monorepo (`~/Projects/bolyra/`)

## Overview

End-to-end agentic product development lifecycle for Bolyra. A `bolyra-pdlc` orchestrator agent conducts a 7-stage pipeline with 4 human gates. Subagents implement code in isolated git worktrees. Each approved feature ships as its own release (continuous delivery).

## Design Principles

- **Human-at-the-gates.** Agents do work between checkpoints. Viswa approves at spec, plan, implementation review, and post-ship.
- **Agents implement in worktrees.** Implementation is delegated to subagents with isolated git worktrees. Viswa reviews code, doesn't write it.
- **Continuous release.** Every approved feature ships independently. No version batching.
- **Conversational entry.** Pipeline starts from natural language ("add receipt expiration"). No issue tracker required.
- **Session-resilient.** State persists to disk. Work resumes across sessions.

## Pipeline

```
INTAKE → SPEC → [Gate 1] → PLAN → [Gate 2] → IMPLEMENT → REVIEW → [Gate 3] → RELEASE → [Gate 4]
```

### Stage 1: INTAKE

User describes what they want conversationally. Orchestrator asks 1-2 clarifying questions if scope is ambiguous. No gate because the user is already present.

### Stage 2: SPEC

Orchestrator writes a design document to `docs/superpowers/specs/{date}-{topic}-design.md`.

Conditional dispatches:
- `bolyra-standards` — if the change touches `spec/`, `circuits/`, or protocol-level SDK functions. Produces conformance delta and IETF mapping notes.
- `bolyra-security` — if the change touches auth, nonce, delegation, or payment surfaces. Produces a threat sketch of attack surface additions/changes.

### Gate 1: Spec Approval

Orchestrator presents the spec summary. Spec is on disk for full review. User approves, revises (with feedback), or rejects.

### Stage 3: PLAN

Orchestrator decomposes the spec into discrete implementation tasks. Each task includes:
- Description (what to build)
- Input files (what to read)
- Output files (what to create/modify)
- Test expectations (what tests should pass after)
- Dependencies (which tasks must complete first)
- Parallelization tag: `parallel` or `sequential(after: task-N)`

Plan written to `docs/superpowers/plans/{date}-{topic}.md`.

### Gate 2: Plan Approval

Orchestrator presents the task list with complexity estimates (S/M/L) and parallelization strategy. User approves, adjusts scope, or rejects.

### Stage 4: IMPLEMENT

Orchestrator fans out tasks to subagents in git worktrees.

**Worktree lifecycle:**
1. Create: `git worktree add ~/Projects/bolyra/.worktrees/task-N -b pdlc/task-N`
2. Dispatch subagent with `isolation: "worktree"` containing: spec excerpt, task description, file paths, test commands, DCO sign-off requirement
3. Subagent implements, runs tests, commits with `Signed-off-by:`
4. Subagent returns: branch name, commit SHAs, test results, files changed
5. Orchestrator collects completed branches

**Parallelization:**
- Tasks tagged `parallel` run concurrently in separate worktrees
- Tasks tagged `sequential(after: task-N)` wait for dependencies

**Failure handling:**
- Test failure: orchestrator retries once with error context
- Retry failure: task flagged at Gate 3 with failure details
- User decides: fix, send back with guidance, or drop

**Subagent prompt template:**
```
You are implementing Task {N} of the Bolyra PDLC pipeline.

SPEC: {excerpt from design doc}
TASK: {description}
FILES TO READ: {list}
FILES TO MODIFY/CREATE: {list}
TEST COMMAND: {command}
EXPECTED: {what passing looks like}

Rules:
- Every commit needs Signed-off-by: Viswanadha Pratap Kondoju <kondojuviswanadha@gmail.com>
- Run tests before returning. Report pass/fail.
- Do not modify files outside your task scope.
- If you're blocked, return with a clear description of what's blocking you.
```

### Stage 5: REVIEW

Orchestrator dispatches review agents against implementation diffs:

| Reviewer | Scope | Fires When |
|----------|-------|------------|
| `bolyra-sdk-guardian` | API surface, version consistency, cross-package compat | Always |
| `bolyra-security` | Targeted audit on changed attack surfaces | Always (scoped to changed files) |
| `circuit-zkp-reviewer` | Circuit constraints, trusted setup | `circuits/` or `contracts/` in diff |
| Claude Code review (`/review` skill) | Structural diff review: SQL safety, trust boundaries, side effects | Always |
| Codex CLI review (`codex review`) | Independent second opinion: adversarial, different model | Always |
| Conformance runner | `npm run conformance` | Always |
| Full test suite | `npm test` | Always |

**Dual code review rationale:** Claude Code and Codex use different models and review heuristics. Running both catches issues that either alone would miss. Claude Code's `/review` skill analyzes the diff against the base branch. Codex review runs independently with its own pass/fail gate. If either flags an issue, it surfaces at Gate 3.

### Gate 3: Ship Approval

Orchestrator presents:
- Review results (pass/fail per reviewer, findings)
- Test results (pass/fail, count)
- Diff summary (files changed, lines added/removed)
- Issues flagged (if any)

If review agents disagree, orchestrator surfaces both opinions with its own recommendation. User approves to ship, sends back for fixes, or rejects.

### Stage 6: RELEASE

Orchestrator merges task branches:
1. Sequential rebase of task branches into `pdlc/{feature}` in task-ID order (linear history)
2. If merge conflicts arise between parallel tasks: trivial conflicts (import statements, adjacent lines) are auto-resolved; non-trivial conflicts are flagged to user
3. If conflict resolution changes code, REVIEW stage re-runs on the merged result
4. Squash-merge to main

Then delegates to `bolyra-release`:
- Version bump (patch for fixes, minor for features, major for breaking)
- CHANGELOG update
- Git tag
- npm publish (OIDC)
- PyPI publish (if Python SDK changed)
- Landing page update (if warranted)
- GitHub release with notes

### Gate 4: Post-Ship Confirmation

Orchestrator confirms:
- Packages published and verified on registries
- Conformance passing
- Landing page verified (if updated)

Optional post-ship dispatches:
- `gtm-outbound` — draft outbound message if release is minor+ (not patches)
- `bolyra-standards` — update conformance report (`spec/CONFORMANCE.md`)

User acknowledges. Pipeline complete.

## Agent Dispatch Map

| Stage | Agent | Task | Output |
|-------|-------|------|--------|
| SPEC | Orchestrator | Write design doc | `docs/superpowers/specs/{date}-{topic}-design.md` |
| SPEC | `bolyra-standards` (conditional) | Spec/protocol impact | Conformance delta, IETF notes |
| SPEC | `bolyra-security` (conditional) | Threat sketch | Attack surface changes |
| PLAN | Orchestrator | Task decomposition | `docs/superpowers/plans/{date}-{topic}.md` |
| IMPLEMENT | General subagents | Code in worktrees | Branches with commits |
| REVIEW | `bolyra-sdk-guardian` | API + compat review | Pass/fail + findings |
| REVIEW | `bolyra-security` | Security audit | Pass/fail + findings |
| REVIEW | `circuit-zkp-reviewer` (conditional) | Circuit audit | Pass/fail + findings |
| REVIEW | Claude Code `/review` | Structural diff review | Pass/fail + findings |
| REVIEW | Codex CLI `codex review` | Independent adversarial review | Pass/fail + findings |
| RELEASE | `bolyra-release` | Publish pipeline | Published packages |
| POST-SHIP | `gtm-outbound` (conditional) | Outbound draft | Draft in `.viswa/agent/drafts/` |
| POST-SHIP | `bolyra-standards` | Conformance update | Updated `spec/CONFORMANCE.md` |

## State Management

### State file

Each pipeline run persists to `~/Projects/bolyra/tasks/pdlc/{feature-slug}.json`:

```json
{
  "id": "pdlc-{date}-{slug}",
  "feature": "Human-readable description",
  "status": "active|rejected|complete",
  "stage": "INTAKE|SPEC|PLAN|IMPLEMENT|REVIEW|RELEASE|POST_SHIP",
  "mode": "standard|hotfix",
  "created": "ISO-8601",
  "updated": "ISO-8601",
  "spec": "path to spec doc (null in hotfix mode)",
  "plan": "path to plan doc (null in hotfix mode)",
  "gates": {
    "spec": { "status": "pending|approved|revised|rejected", "at": "ISO-8601" },
    "plan": { "status": "pending|approved|revised|rejected", "at": "ISO-8601" },
    "ship": { "status": "pending|approved|revised|rejected", "at": "ISO-8601" },
    "post_ship": { "status": "pending|acknowledged", "at": "ISO-8601" }  // note: "acknowledged" (not "approved") — post-ship is confirmation, not approval
  },
  "tasks": [
    {
      "id": 1,
      "description": "Task description",
      "type": "parallel|sequential",
      "depends_on": [],
      "status": "pending|in_progress|complete|failed",
      "branch": "pdlc/task-N-slug",
      "commits": ["sha1"],
      "tests": "pass|fail|pending",
      "files_changed": ["path"]
    }
  ],
  "reviews": {
    "sdk_guardian": { "status": "pass|fail", "findings": [] },
    "security": { "status": "pass|fail", "findings": [] },
    "circuit": { "status": "pass|fail|skipped", "findings": [] },
    "claude_review": { "status": "pass|fail", "findings": [] },
    "codex_review": { "status": "pass|fail", "findings": [] },
    "conformance": { "status": "pass|fail" },
    "tests": { "status": "pass|fail", "count": 0 }
  },
  "release": {
    "version": "0.8.1",
    "packages": ["@bolyra/sdk@0.8.1"],
    "npm_verified": false,
    "pypi_verified": false,
    "landing_verified": false
  }
}
```

### Session continuity

- **Resume:** "resume {feature}" or "status" reads state file, reports current stage, picks up
- **Multiple pipelines:** Multiple features can be in flight simultaneously. "list pipelines" shows all active `tasks/pdlc/*.json`
- **Cleanup:** After Gate 4, state file status changes to `"complete"`, worktree branches deleted. File stays as historical record.
- **Rejection:** When a pipeline is rejected at any gate, status changes to `"rejected"`. State file stays on disk. "list pipelines" distinguishes active from rejected from complete.
- **Staleness:** Pipelines inactive for >7 days should be reviewed for relevance before resuming. The orchestrator warns on resume if the pipeline has been idle that long.

## Orchestrator Agent

### Identity

Top-level pipeline conductor for Bolyra. Sequences stages, dispatches agents, manages gates. Does not write implementation code. Writes specs, plans, and state files directly.

### Entry points

| Trigger | Action |
|---------|--------|
| "build X" / "add X" / "implement X" | Start new pipeline from INTAKE |
| "resume X" / "status" | Read state file, pick up at current stage |
| "list pipelines" | Show all active `tasks/pdlc/*.json` |
| "hotfix: {description}" | Skip SPEC and PLAN, single task, straight to IMPLEMENT → REVIEW → RELEASE |

### In-session commands

| Command | Action |
|---------|--------|
| "approve" | Pass the current gate |
| "revise: {feedback}" | Send current stage back with notes |
| "reject" | Kill the pipeline |
| "skip to release" | For hotfixes, jump to RELEASE after REVIEW |

### Hotfix mode

For urgent fixes: skip SPEC and PLAN. Orchestrator creates a single implementation task from the description, dispatches it, runs review agents, presents at Gate 3. State file records `"mode": "hotfix"`.

### What the orchestrator does NOT delegate

- Gate presentations (always the orchestrator talking to user)
- Task decomposition and parallelization decisions
- Conflict resolution when review agents disagree
- Deciding whether to send back for fixes vs ship with known issues

### DCO enforcement

Every subagent prompt includes the sign-off requirement. Orchestrator verifies all commits carry `Signed-off-by:` before presenting at Gate 3. Unsigned commits are amended before merging.

### Conflict resolution

If review agents disagree (e.g., sdk-guardian says "breaking API change" but the user intended it), orchestrator surfaces both opinions at Gate 3 with its own recommendation. User decides.

## Non-Goals

- **Issue tracker integration.** Pipeline starts from conversation, not GitHub Issues. Issues can be filed manually after the fact.
- **Multi-repo orchestration.** This pipeline is Bolyra-only. GeniusComply and ZKProva have their own workflows.
- **Automated gate approval.** All 4 gates require explicit human approval. No auto-ship.
- **Rollback automation.** If a release has issues, manual intervention required. The pipeline is forward-only.
- **Branch protection rules.** The pipeline manages its own branches. Main branch protection is a GitHub setting, not orchestrator responsibility.

## File Layout

```
bolyra/
├── tasks/
│   └── pdlc/                          # Pipeline state files
│       ├── receipt-expiration.json     # Active pipeline
│       ├── nonce-overflow-hotfix.json  # Completed hotfix
│       └── ...
├── docs/superpowers/
│   ├── specs/                         # Design docs (written by orchestrator)
│   └── plans/                         # Implementation plans (written by orchestrator)
└── .claude/agents/
    └── (orchestrator agent definition lives in ~/Projects/.claude/agents/)
```

## Dependencies

Requires these agents to exist (all created 2026-06-18):
- `bolyra-sdk-guardian`
- `bolyra-security`
- `bolyra-standards`
- `bolyra-release`
- `circuit-zkp-reviewer`
- `gtm-outbound`

The orchestrator agent definition (`bolyra-pdlc`) is a separate deliverable built from this spec.

Requires these skills/tools:
- `/review` skill (Claude Code built-in diff review)
- `codex review` (Codex CLI independent review — see `/codex` skill)

## Success Criteria

1. A feature described conversationally reaches npm within a single session (or across 2 sessions for complex features)
2. Every shipped release has: spec on disk, plan on disk, review results, test results, conformance passing
3. No code ships without sdk-guardian and security review
4. Pipeline state survives session boundaries
5. Hotfixes ship in under 30 minutes from description to npm

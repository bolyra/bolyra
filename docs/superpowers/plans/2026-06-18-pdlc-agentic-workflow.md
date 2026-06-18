# PDLC Agentic Workflow — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `bolyra-pdlc` orchestrator agent that conducts a 7-stage pipeline with 4 human gates, dispatching to existing Bolyra agents for implementation, review, and release.

**Architecture:** Single agent definition file at `~/Projects/.claude/agents/bolyra-pdlc.md`. The agent uses Read/Write for state management (JSON files in `tasks/pdlc/`), Agent tool for dispatching subagents, Bash for running tests/conformance/codex, and Skill tool for `/review`. No external dependencies beyond the existing agent swarm.

**Tech Stack:** Claude Code agent definition (markdown), JSON state files, git worktrees, existing agent swarm (12 agents), `/review` skill, `codex review` CLI.

**Spec:** `docs/superpowers/specs/2026-06-18-pdlc-agentic-workflow-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `~/.claude/agents/bolyra-pdlc.md` | Orchestrator agent definition (the entire deliverable) |
| `~/Projects/bolyra/tasks/pdlc/*.json` | Pipeline state files (created at runtime by the agent) |
| `~/Projects/.claude/projects/-Users-lordviswa-Projects/memory/agent_swarm.md` | Swarm registry (update with new agent) |

The orchestrator is a single agent definition file. It's large (~400 lines) but atomic — no code files, no scripts, no libraries. All behavior is encoded in the agent prompt. State management uses the Read/Write tools on JSON files.

---

## Chunk 1: Orchestrator Agent Definition

### Task 1: Write the orchestrator agent frontmatter and identity [parallel]

**Files:**
- Create: `~/Projects/.claude/agents/bolyra-pdlc.md`

- [ ] **Step 1: Write the frontmatter block**

The YAML frontmatter defines how Claude Code discovers and dispatches the agent.

```yaml
---
name: bolyra-pdlc
description: "End-to-end PDLC orchestrator for Bolyra. Conducts a 7-stage pipeline
  (INTAKE → SPEC → PLAN → IMPLEMENT → REVIEW → RELEASE → POST-SHIP) with 4 human
  gates. Dispatches to existing agents for implementation, review, and release.
  Manages pipeline state in tasks/pdlc/*.json for session continuity.\n\n..."
model: opus
memory: project
---
```

Include examples in the description:
- "build X" / "add X" → new pipeline
- "resume X" / "status" → pick up where left off
- "hotfix: X" → skip spec/plan, straight to implement
- "list pipelines" → show active state files

- [ ] **Step 2: Write the identity and read-order sections**

Identity: top-level pipeline conductor. Does not write implementation code. Writes specs, plans, state files. Dispatches to agents for everything else.

Read order on every invocation:
1. `~/Projects/bolyra/CLAUDE.md` — project context
2. `~/Projects/bolyra/tasks/pdlc/*.json` — active pipelines (if resuming)
3. Spec referenced in state file (if resuming mid-pipeline)

### Task 2: Write the pipeline stage logic [sequential after Task 1]

**Files:**
- Modify: `~/Projects/.claude/agents/bolyra-pdlc.md`

- [ ] **Step 1: Write the INTAKE stage**

Behavior:
- Parse user's feature request
- Ask 1-2 clarifying questions if scope is ambiguous
- Create state file: `tasks/pdlc/{slug}.json` with `status: "active"`, `stage: "INTAKE"`, `mode: "standard"`
- Transition to SPEC

Include the slug generation rule: lowercase, hyphens, no special chars, derived from the feature description.

- [ ] **Step 2: Write the SPEC stage**

Behavior:
- Write design doc to `docs/superpowers/specs/{date}-{topic}-design.md`
- Conditional dispatch:
  - If change touches `spec/`, `circuits/`, or protocol SDK functions → dispatch `bolyra-standards` (background)
  - If change touches auth, nonce, delegation, payment → dispatch `bolyra-security` (background)
- Collect results from conditional dispatches
- Update state: `stage: "SPEC"`
- Present spec summary at Gate 1

Include the Gate 1 presentation template:
```
## Gate 1: Spec Approval

**Feature:** {description}
**Spec:** `{path to spec doc}`

**Summary:**
{2-3 paragraph summary of what will be built}

**Standards impact:** {results from bolyra-standards or "N/A"}
**Security impact:** {results from bolyra-security or "N/A"}

Approve, revise, or reject?
```

- [ ] **Step 3: Write the PLAN stage**

Behavior:
- Read the approved spec
- Decompose into tasks with: description, input files, output files, test expectations, dependencies, parallelization tag
- Write plan to `docs/superpowers/plans/{date}-{topic}.md`
- Update state: `stage: "PLAN"`, populate `tasks` array
- Present task list at Gate 2

Include the Gate 2 presentation template:
```
## Gate 2: Plan Approval

**Feature:** {description}
**Plan:** `{path to plan doc}`

| # | Task | Complexity | Type | Depends On |
|---|------|-----------|------|------------|
| 1 | ... | S/M/L | parallel | — |
| 2 | ... | S/M/L | sequential | 1 |

**Parallelization:** Tasks {X,Y} run concurrently. Task {Z} waits for {X,Y}.

Approve, adjust scope, or reject?
```

- [ ] **Step 4: Write the IMPLEMENT stage**

Behavior:
- For each task in the plan:
  - If `parallel` and no unmet dependencies → dispatch immediately
  - If `sequential` → wait for `depends_on` tasks to complete
- Dispatch via Agent tool with `isolation: "worktree"`
- Subagent prompt template (from spec, verbatim)
- On subagent return: update state task entry with branch, commits, test status, files_changed
- On test failure: retry once with error context. On second failure: mark task `failed`
- Update state: `stage: "IMPLEMENT"` while tasks are running
- When all tasks complete (or fail): transition to REVIEW

- [ ] **Step 5: Write the REVIEW stage**

Behavior:
- Collect all task branches
- Dispatch review agents (all in parallel where possible):
  1. `bolyra-sdk-guardian` — always
  2. `bolyra-security` — always (scoped to changed files)
  3. `circuit-zkp-reviewer` — only if `circuits/` or `contracts/` in any task's `files_changed`
  4. `/review` skill — always (Claude Code diff review)
  5. `codex review` via Bash — always (Codex CLI adversarial review)
  6. `npm run conformance` via Bash — always
  7. `npm test` via Bash — always
- Collect all results into state `reviews` object
- Update state: `stage: "REVIEW"`
- Present at Gate 3

Include the Gate 3 presentation template:
```
## Gate 3: Ship Approval

**Feature:** {description}

### Review Results
| Reviewer | Status | Findings |
|----------|--------|----------|
| SDK Guardian | PASS/FAIL | {count} findings |
| Security | PASS/FAIL | {count} findings |
| Circuit | PASS/FAIL/SKIPPED | {count} findings |
| Claude Code | PASS/FAIL | {count} findings |
| Codex | PASS/FAIL | {count} findings |
| Conformance | PASS/FAIL | — |
| Tests | PASS/FAIL | {count} passing |

### Diff Summary
{files changed, lines +/-}

### Issues
{any findings from reviewers, grouped by severity}

Approve to ship, send back for fixes, or reject?
```

- [ ] **Step 6: Write the RELEASE stage**

Behavior:
- Merge task branches: sequential rebase in task-ID order into `pdlc/{feature}`
- Trivial merge conflicts (imports, adjacent lines): auto-resolve
- Non-trivial conflicts: flag to user, pause pipeline
- If conflict resolution changed code: re-run REVIEW
- DCO check: verify all commits have `Signed-off-by:`. Amend if missing.
- Squash-merge to main
- Dispatch `bolyra-release` agent with: version bump type (patch/minor/major based on change scope), packages changed, changelog entry
- Update state: `stage: "RELEASE"`, populate `release` object
- Present at Gate 4

Include the Gate 4 presentation template:
```
## Gate 4: Post-Ship Confirmation

**Feature:** {description}
**Version:** {version}

### Published
| Package | Version | npm | PyPI |
|---------|---------|-----|------|
| @bolyra/sdk | {v} | verified/pending | — |
| ... | ... | ... | ... |

### Verification
- Conformance: PASS/FAIL
- Landing page: verified/skipped

### Post-Ship (optional)
- GTM outbound: {drafted/skipped}
- Conformance report: {updated/skipped}

Acknowledge to complete pipeline.
```

- [ ] **Step 7: Write the hotfix mode section**

Behavior:
- Entry: "hotfix: {description}"
- Create state file with `mode: "hotfix"`, `spec: null`, `plan: null`
- Create a single task from the description
- Skip directly to IMPLEMENT (one task, no parallelization)
- Then REVIEW → Gate 3 → RELEASE → Gate 4
- Same review and release process as standard mode

- [ ] **Step 8: Write the session continuity section**

Behavior:
- On "resume {feature}": glob `tasks/pdlc/*.json`, find matching state file, read it, report current stage, pick up
- On "status": same as resume but just report, don't advance
- On "list pipelines": glob all state files, show table of id/feature/status/stage/updated
- Staleness warning: if `updated` is >7 days ago, warn before resuming
- On "reject": set `status: "rejected"`, stop pipeline

- [ ] **Step 9: Write the state file management section**

Include:
- State file path: `~/Projects/bolyra/tasks/pdlc/{slug}.json`
- Full JSON schema (from spec)
- Read/write discipline: always read before write, write atomically (full file replacement via Write tool)
- Transition rules: which stages can transition to which
- Cleanup: on Gate 4 acknowledgment, set `status: "complete"`, note that worktree branches should be deleted

### Task 3: Validate the agent definition [sequential after Task 2]

**Files:**
- Read: `~/Projects/.claude/agents/bolyra-pdlc.md`

- [ ] **Step 1: Verify all referenced agents exist**

Check that every agent name dispatched in the definition exists in `~/Projects/.claude/agents/`:
- `bolyra-sdk-guardian` ✓
- `bolyra-security` ✓
- `bolyra-standards` ✓
- `bolyra-release` ✓
- `circuit-zkp-reviewer` ✓
- `gtm-outbound` ✓

- [ ] **Step 2: Verify all referenced skills/commands exist**

Check:
- `/review` skill is available in the skill list
- `codex review` command works: `which codex && codex --version`
- `npm run conformance` works in `~/Projects/bolyra/`
- `npm test` works in `~/Projects/bolyra/`

- [ ] **Step 3: Verify state directory exists**

```bash
ls -la ~/Projects/bolyra/tasks/pdlc/
```

Expected: directory exists (created earlier in this session)

- [ ] **Step 4: Commit the agent definition**

```bash
cd ~/Projects/bolyra
# Agent def is outside the bolyra repo (in ~/.claude/agents/)
# So nothing to commit in bolyra — but commit the spec cleanup
git add docs/superpowers/specs/2026-06-18-pdlc-agentic-workflow-design.md
git commit -s -m "docs: clean up spec duplicate line"
```

---

## Chunk 2: Swarm Registry and Documentation

### Task 4: Update agent_swarm.md [parallel]

**Files:**
- Modify: `~/.claude/projects/-Users-lordviswa-Projects/memory/agent_swarm.md`

- [ ] **Step 1: Add bolyra-pdlc to the agent roster**

Add to the Bolyra Team table:
```
| `bolyra-pdlc` | PDLC orchestrator: 7-stage pipeline, 4 gates, worktree implementation | Created 2026-06-18 |
```

- [ ] **Step 2: Update agent count from 12 to 13**

- [ ] **Step 3: Add to swarm topology diagram**

Add `bolyra-pdlc` to the ON-DEMAND column.

### Task 5: Update MEMORY.md [sequential after Task 4]

**Files:**
- Modify: `~/.claude/projects/-Users-lordviswa-Projects/memory/MEMORY.md`

- [ ] **Step 1: Add PDLC checkpoint**

Add to Active Checkpoints:
```
- 2026-06-18 · Bolyra PDLC agentic workflow spec + orchestrator agent built. 13 agents, 5 triggers. Spec at `bolyra/docs/superpowers/specs/2026-06-18-pdlc-agentic-workflow-design.md`.
```

---

## Execution Order

```
Task 1 [parallel]  — Frontmatter + identity
Task 4 [parallel]  — Update swarm registry
        ↓
Task 2 [seq: 1]    — Pipeline stage logic (9 steps, the bulk of the work)
        ↓
Task 3 [seq: 2]    — Validate agent definition
        ↓
Task 5 [seq: 4]    — Update MEMORY.md
```

Tasks 1 and 4 run in parallel. Task 2 is the bulk (9 steps, ~200 lines of agent definition). Task 3 validates. Task 5 updates memory.

## Estimated Complexity

| Task | Complexity | Time |
|------|-----------|------|
| Task 1 | S | Frontmatter + identity |
| Task 2 | L | 9 steps, core pipeline logic |
| Task 3 | S | Validation checks |
| Task 4 | S | Registry update |
| Task 5 | S | Memory update |

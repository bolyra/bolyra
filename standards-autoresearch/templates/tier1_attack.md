# Tier 1 attack/scout template

You are one persona in the standards-autoresearch loop for Bolyra/EVC.

{program}

## Your persona

{persona_prompt}

## Inputs

### Current spec surfaces (pinned at {spec_commit})
{spec_excerpt}

### Conformance vector index (set {vector_set})
{vector_index}

### Reconciled boards (verified {reconcile_ts})
{boards_summary}

### Fresh signals (this iteration)
{signals}

### Rejected findings from the previous iteration (do not repeat; refine or drop)
{reject_findings}

## Task

Produce up to {max_candidates} candidates. Every candidate MUST have
evidence (quoted spec text, URL, repo, or runnable command) — candidates
without evidence are dropped unread (program.md rule 2k).

Return ONLY one JSON array (no fences, no prose):

```
[{"id": "<persona>-<slug>", "type": "spec_finding|vector_gap|evidence_opportunity|threat_update|adoption_target",
  "title": "...", "claim": "...", "evidence": ["..."],
  "proposed_artifact": "one sentence: what Tier 2 would build",
  "entity": {"name": "...", "repo": "...", "tracked_id": null}}]
```

The `entity` field is required only for threat_update/adoption_target; use
`tracked_id` when the entity is already in tracked_entities.json.

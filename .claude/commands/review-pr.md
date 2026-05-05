---
description: Multi-reviewer audit of an open PR (gstack /review + codex + bolyra subagents)
argument-hint: [pr-number]
---

Run a deep PR review against PR #$ARGUMENTS (or the current branch's open PR if no number given). Uses Claude MAX — no API keys needed.

Pipeline:

1. **Fetch the PR diff** via `gh pr diff $ARGUMENTS`.
2. **Layer 1 — gstack `/review`**: SQL safety, trust boundary, structural issues.
3. **Layer 2 — `/codex review`**: adversarial review via OpenAI Codex.
4. **Layer 3 — `circuit-auditor` subagent**: only if `circuits/src/*.circom` or `circuits/test/` changed. Audits soundness, public-signal binding, constraint efficiency, ceremony reuse.
5. **Layer 4 — `sdk-api-reviewer` subagent**: only if `sdk/src/`, `sdk-python/bolyra/`, or any public export changed. Audits TS/Python parity and breaking-change risk.
6. **Layer 5 — `protocol-reviewer` subagent**: only if `spec/`, `integrations/`, or DID/handshake wire format changed.
7. **Layer 6 — DCO check**: every commit in the PR must have `Signed-off-by:`. Flag any unsigned commit.
8. **Layer 7 — verifier sync check**: if a `.zkey` would change due to circuit edits, flag that `contracts/contracts/*Verifier.sol` needs regenerating.

After all layers complete, output a **combined verdict table** with per-reviewer status.

End with one of: **APPROVE**, **APPROVE WITH NITS**, **REQUEST CHANGES**, **BLOCK**. Justify in 1-2 sentences.

Skip subagents that don't apply and note "N/A — no relevant files".

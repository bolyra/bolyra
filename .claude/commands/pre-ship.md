---
description: Pre-ship gate — review uncommitted diff before /ship
---

Pre-ship gate for Bolyra. Runs reviewers on the uncommitted diff before creating a PR with `/ship`.

Pipeline:

1. **Show diff scope**: `git diff --stat` and `git status`.
2. **DCO check**: every commit since `main` must have `Signed-off-by:`. Run `git log main..HEAD --format=%B | grep -c Signed-off-by` and compare to commit count.
3. **Type check (TS SDK)**: `cd sdk && npm run typecheck`.
4. **Tests**: `npm run test:circuits:fast && npm run test:contracts`.
5. **gstack `/review`** on the diff.
6. **`/codex review`**: adversarial perspective.
7. **`circuit-auditor` subagent**: only if `circuits/src/*.circom` changed.
8. **`sdk-api-reviewer` subagent**: only if `sdk/src/` or `sdk-python/bolyra/` public exports changed.
9. **`protocol-reviewer` subagent**: only if `spec/` or `integrations/` changed.
10. **Verifier sync**: if a `.zkey` would change, flag that `contracts/contracts/*Verifier.sol` needs regenerating.

Output a **GO/NO-GO recommendation**. If GO, suggest `/ship`.

Do not actually run `/ship` — that's the user's call.

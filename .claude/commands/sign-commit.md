---
description: Amend the latest commit with a DCO sign-off if missing
---

Bolyra requires DCO sign-off (`Signed-off-by:`) on every commit. CI rejects unsigned.

1. Run `git log -1 --format=%B` to read the latest commit message.
2. If `Signed-off-by:` is already present, report and exit.
3. If missing, ask the user to confirm before running `git commit --amend -s --no-edit`.
4. After amending, show the new commit message and remind the user that pushing will require `--force-with-lease` if the commit was already pushed.

Going forward, suggest `git commit -s -m "..."` to sign every new commit automatically.

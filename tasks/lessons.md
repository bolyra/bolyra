
## 2026-07-10 — Codex agreement is a gate, not a suggestion
- Pattern: applied Codex's prescribed fixes to wave-1 DM drafts and treated the review as done without sending the FIXED text back for a confirming pass. User corrected: do not proceed with next steps until Claude and Codex agree.
- Rule: after applying review fixes, re-submit the final artifact until Codex returns a clean verdict. Agreement gates every outward step (send/post/push/publish).

## 2026-07-10 — `gh search prs --state closed` includes MERGED
- Pattern: reported "4 closed, none merged" from search state alone; two were actually MERGED (robinhood-ai-trading-bot#68, robinhood-for-agents#17). The "0/14 merged" strategy premise was stale since June 23.
- Rule: never report PR outcomes from search state; check `mergedAt`/`mergedBy` per PR. Merged ⊂ closed in GitHub search.

## 2026-07-10 — `git add <path> && git commit` commits the ENTIRE index
- Pattern: committed examples/openai-agents-wallet while a parallel agent had its hash-chain files staged; the pathspec-less commit swept 21 of its un-reviewed files onto main and out the door (f1647bc, fixed by 9ed4517 via `git restore --source=<base> --staged`).
- Rule: in a repo with parallel agents, ALWAYS commit with explicit pathspecs (`git commit -- <paths>`) — never rely on what you think is staged. `git rm --cached` is wrong for backing out MODIFIED tracked files (it deletes them from HEAD); use `git restore --source=<base> --staged`.

## 2026-07-12 — `npm pkg set` rewrites more than the key you set
- Pattern: during the Dependabot triage, `npm pkg set` silently normalized `integrations/mcp` `dependencies["@bolyra/sdk"]` from `^0.5.0` to the peer range `>=0.4.0` and alphabetized keys in 5 manifests — semantic dependency-range changes smuggled into what looked like an override-only edit.
- Rule: never use `npm pkg set` on a manifest that lists the same package in both `dependencies` and `peerDependencies` (or when key order matters for diffs). Edit `package.json` by hand with a minimal diff, then `npm install` to regenerate the lockfile, and diff-review the manifest before committing.

## 2026-07-13 — gateway sdk-floor loop
- **npm `overrides` edits do not restructure an existing node_modules/lockfile.** After changing an `overrides` block, `npm install` alone can leave the old resolution in place (nested @bolyra/sdk@0.5.3 survived). Fix: `rm -rf node_modules package-lock.json && npm install`, then verify the tree (`npm ls <pkg>` / scan for nested copies).
- **Registry is ground truth for publish status, not memory/checkpoints.** Assumed @bolyra/mcp 0.6.4 was unpublished (stale checkpoint); `npm view @bolyra/mcp versions` showed it live, which re-versioned the fix to 0.6.5 mid-review. Run `npm view` BEFORE reasoning about release ordering.
- **gateway test/receipts.test.ts "POSTs receipt to webhook URL" is flaky under full-suite load** (setTimeout + done, 5s budget). Passes isolated. Deflake when touched next.

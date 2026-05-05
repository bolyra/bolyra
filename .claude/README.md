# identityos / .claude/

Project-scoped Claude Code configuration for **Bolyra**. Workspace-wide settings live in `../../.claude/`.

## Subagents (`.claude/agents/`)

| Agent | When to use |
|---|---|
| `circuit-auditor` | Modifying circuits or before regenerating zkeys — soundness, public-signal binding, ceremony reuse, constraint efficiency |
| `sdk-api-reviewer` | Before publishing any SDK version — TS/Python parity, breaking-change risk, error-code alignment |
| `protocol-reviewer` | Modifying `spec/`, wire format, or `integrations/` adapters — drift, conformance gaps, compatibility |

## Slash commands (`.claude/commands/`)

| Command | Purpose |
|---|---|
| `/test-circuits [fast\|slow]` | Run circuit tests (fast = mocked, slow = real proofs) |
| `/compile-circuits` | Compile circuits and refresh `circuits/build/` artifacts |
| `/deploy-base-sepolia` | Deploy contracts to Base Sepolia testnet |
| `/sign-commit` | Amend latest commit with DCO sign-off if missing |
| `/pre-ship` | Pre-ship gate (DCO + tests + review + circuit-auditor + sdk-api-reviewer + protocol-reviewer) |
| `/review-pr` | Multi-reviewer audit of an open PR |

## Hooks (`.claude/settings.json`)

- **PostToolUse** on `Edit|Write|MultiEdit`:
  - `circuits/test/**/*.test.js` → backgrounds `npm run test:circuits:fast` to `.claude/last-test-run.log`
- **SessionStart**: prints recent commits, available circuit build artifacts, last test run summary

## Plugins enabled

- `frontend-design@claude-plugins-official` — for the `landing/` Next.js site

## MCP servers (`.mcp.json`)

| Server | Package | Required env |
|---|---|---|
| `bolyra-fs` | Local `examples/mcp-demo/dist/bolyra-proxy.js` — filesystem proxy that's circuit-aware (uses rapidsnark) | `BOLYRA_RAPIDSNARK` (hardcoded path) |
| `github` | `ghcr.io/github/github-mcp-server` (Docker, first-party) — issue/PR/repo awareness | `GITHUB_PERSONAL_ACCESS_TOKEN` + Docker daemon running |

## DCO reminder

Bolyra requires DCO sign-off on every commit. Use `git commit -s -m "..."` or fix with `/sign-commit`.

## Notes

- `settings.json` is team-shared, `settings.local.json` is per-user (gitignored).
- License canonical: Apache-2.0 (SDK READMEs say MIT — fix queued).

# Bolyra Replay Check

CI for agent behavior regressions. Replays receipt history against your policy and comments on PRs.

## Quick Start

```yaml
name: Bolyra Replay
on: [pull_request]

jobs:
  replay:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bolyra/bolyra/actions/replay-check@main
        with:
          receipt-path: .bolyra/receipts
          policy: shield.yaml
```

## What It Does

1. Finds receipt NDJSON files in your repo (from `bolyra observe --output`)
2. Replays each receipt against your `shield.yaml` policy
3. Posts a PR comment showing regressions and relaxations
4. Fails the check if any allow → deny regressions are found

## PR Comment

```
## 🛡️ Bolyra Replay Check

Replayed **14** agent receipts against `shield.yaml`.

**2** decision(s) would change:

### 🚫 Regressions (1 allow → deny)

| Tool | Reason |
|------|--------|
| `write_file` | score 88 < required 95 |

### ✅ Relaxations (1 deny → allow)

| Tool | Reason |
|------|--------|
| `search` | no tool policy |
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `receipt-path` | `.bolyra/receipts` | Path to receipt NDJSON files |
| `policy` | `shield.yaml` | Path to shield.yaml policy |
| `fail-on-regression` | `true` | Fail the check on allow→deny changes |
| `comment` | `true` | Post a PR comment with results |
| `github-token` | `github.token` | Token for PR comments |

## Outputs

| Output | Description |
|--------|-------------|
| `total` | Total receipts replayed |
| `changed` | Decisions that changed |
| `regressions` | allow → deny (policy tightened) |
| `relaxations` | deny → allow (policy relaxed) |

## How Receipts Get Into Your Repo

```bash
# 1. Run your server with bolyra
bolyra run --dev -- npx some-mcp-server 2> receipts.ndjson

# 2. Or use observe with --output
bolyra run ... 2>&1 | bolyra observe --output .bolyra/receipts/baseline.ndjson

# 3. Commit the receipts + policy
git add .bolyra/receipts/ shield.yaml
git commit -m "add bolyra receipts and policy"
```

Now every PR replays the baseline receipts against the current policy.

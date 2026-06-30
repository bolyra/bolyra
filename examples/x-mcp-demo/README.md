# Bolyra + X MCP Demo

Demonstrates [Bolyra Shield](../../integrations/shield/) wrapping X's MCP server with per-tool ZKP authorization.

## What it shows

| Scenario | Proof | Result |
|----------|-------|--------|
| Attacker | None | Both read and write tools rejected |
| Legit agent | Full permissions (all 8 bits) | Search, bookmark, article all succeed |
| Delegated agent | READ_DATA only (1-hop delegation) | Search succeeds, bookmark + article denied |

All tools not listed in `shield.yaml` are rejected (`defaultDeny: true`).

## Run

```bash
# From this directory
bash run-demo.sh

# Or individual scenarios
npx tsx src/attacker-client.ts
npx tsx src/legit-client.ts
npx tsx src/delegated-client.ts
```

## With real X API

Replace the mock server command with `xurl mcp`:

```bash
# Run shield with xurl instead of mock
bolyra-shield --server "xurl mcp" --config shield.yaml
```

Requires [xurl](https://docs.x.com/tools/mcp) installed and authenticated.

## Tool Policy

| Tool | Required Permission | Bitmask |
|------|-------------------|---------|
| `search_recent_posts` | READ_DATA | `1` |
| `get_user_by_username` | READ_DATA | `1` |
| `get_me` | READ_DATA | `1` |
| `get_bookmarks` | READ_DATA | `1` |
| `add_bookmark` | WRITE_DATA | `2` |
| `remove_bookmark` | WRITE_DATA | `2` |
| `create_article` | WRITE_DATA + SIGN_ON_BEHALF | `34` |

Unknown tools are rejected (`defaultDeny: true`).

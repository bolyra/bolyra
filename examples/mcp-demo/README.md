# Bolyra MCP Demo — broken vs fixed

90-second screencast script for `@bolyra/mcp`. Same MCP filesystem server, same MCP client protocol, one wrapper line. Watch a credential exfil attack succeed without Bolyra and fail with it.

## Setup

```bash
cd examples/mcp-demo
npm install
# from repo root, build the local @bolyra/sdk and @bolyra/mcp first if you
# haven't already:
#   (cd ../../sdk && npm run build)
#   (cd ../../integrations/mcp && npm install && npm run build)
```

## Run

```bash
./run-demo.sh
```

Or run scenes individually:

```bash
npx ts-node src/attacker-client.ts broken   # leaks ~/.ssh/id_rsa
npx ts-node src/attacker-client.ts fixed    # REJECTED
npx ts-node src/legit-client.ts fixed       # OK in ~100ms
```

Each client spawns its own server process via stdio, matching how Claude Desktop / Cursor / Cline launch real MCP servers.

## What's in here

| File | Role |
|---|---|
| `src/server-broken.ts` | Plain MCP filesystem server. No auth. |
| `src/server-fixed.ts` | Same server, wrapped with `withBolyraAuthStdio`. |
| `src/attacker-client.ts` | Speaks raw MCP, no credentials. |
| `src/legit-client.ts` | Generates a Bolyra handshake via `attachBolyraProof` and attaches it to every tool call. |
| `src/shared.ts` | In-memory credential registry the fixed server consults. |
| `run-demo.sh` | Runs all three scenes for screen-recording. |

## Recording notes (90s)

- **0–20s** Scene 1. Show the attacker leaking `~/.ssh/id_rsa`. Red border. "This is what stdio MCP looks like today."
- **20–45s** Scene 2. Same attacker, `server-fixed`. "Bolyra auth required: missing proof bundle." Green border.
- **45–75s** Scene 3. Legit client. Show the proof generation time print, then the file contents. "~100ms. The MCP protocol didn't change. One wrapper line did."
- **75–90s** Outro card with the wrapper line + npm install instruction. Link to `@bolyra/mcp` README.

## Production caveat

The demo's `~/.ssh/id_rsa` target is intentionally provocative — it represents the class of file that prompt-injected agents try to exfiltrate via overly-permissive MCP servers. In production, the broken server would never expose `read_file` without scoping to a sandbox directory. The point is that with Bolyra, you don't have to *also* trust the host's choice of caller.

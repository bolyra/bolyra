# Bolyra Wiki — Schema & Agent Instructions

## Purpose

This wiki is an LLM-maintained knowledge base synthesized from raw source
documents. It serves two audiences:
1. **Internal** — Claude Code agents and Viswa use it for fast context loading
2. **Public** — selected pages render to bolyra.ai/wiki/

## Three-Layer Architecture

| Layer | Path | Mutability |
|-------|------|------------|
| raw/ | `raw/` | Immutable symlinks to source dirs |
| wiki/ | `wiki/` | LLM-generated, LLM-maintained |
| schema | This file (`WIKI.md`) | Human-edited conventions |

## Operations

### ingest

Process new/changed sources into wiki pages. Run when:
- A source document is added or substantially changed
- A new integration, circuit, or spec lands
- Autoresearch produces new reports

Command: `claude -a .claude/agents/wiki-ingest.md "Ingest changes from the last week"`
Full rebuild: `claude -a .claude/agents/wiki-ingest.md "Full rebuild"`

### query

Answer questions using wiki/ directly. Agents should:
1. Check `wiki/_index.md` for topic -> page mapping
2. Read the relevant wiki page(s)
3. Follow `sources:` links to raw docs for detail
4. Use gbrain for semantic search across wiki + raw

### lint

Health checks. Run weekly or before public deploys.

Command: `claude -a .claude/agents/wiki-lint.md`

Checks:
- Staleness: pages past their `staleness-threshold`
- Coverage: source dirs with no corresponding wiki page
- Broken links: `sources:` references that don't resolve
- Metadata: missing required frontmatter fields

## Page Format

Every wiki page uses this frontmatter + body structure:

```yaml
---
title: <human-readable title>
visibility: internal | public
sources:
  - raw/protocol-spec/draft-bolyra-mutual-zkp-auth-01.md
  - raw/circuits/src/HumanUniqueness.circom
last-updated: YYYY-MM-DD
staleness-threshold: <N>d
tags: [tag1, tag2]
---
```

Body structure:

```markdown
# Title

Brief 1-2 sentence summary.

## Overview
...

## Key Concepts
...

## How It Works
...

## Current Status
...

## See Also
- [[wiki/protocol/zkp-handshake]] — related page
- [raw source](../raw/...) — primary source
```

## Source-to-Wiki Mapping

| Source(s) | Wiki Page | Visibility |
|-----------|-----------|------------|
| `spec/draft-*.md`, `circuits/src/HumanUniqueness.circom` | `wiki/protocol/zkp-handshake.md` | public |
| `circuits/src/`, `circuits/FORMAL-PROPERTIES.md` | `wiki/protocol/circuits-overview.md` | public |
| `CLAUDE.md` (permissions), `sdk/src/types.ts` | `wiki/protocol/permissions-model.md` | public |
| `circuits/src/Delegation.circom`, `sdk/src/delegation.ts` | `wiki/protocol/delegation.md` | public |
| `spec/did-method-bolyra.md` | `wiki/protocol/did-method.md` | public |
| `sdk/src/envelope.ts`, proof-envelope plan/spec | `wiki/protocol/proof-envelope.md` | public |
| `sdk/README.md`, `sdk/QUICKSTART.md`, `sdk/src/index.ts` | `wiki/sdk/typescript-sdk.md` | public |
| `sdk-python/README.md`, `sdk-python/bolyra/` | `wiki/sdk/python-sdk.md` | public |
| `docs/quickstart.md` | `wiki/sdk/quickstart.md` | public |
| `sdk/src/index.ts` (exports), `sdk/src/types.ts` | `wiki/sdk/api-reference.md` | public |
| `integrations/mcp/README.md` | `wiki/integrations/mcp.md` | public |
| `integrations/langchain/README.md` | `wiki/integrations/langchain.md` | public |
| `integrations/crewai/README.md` | `wiki/integrations/crewai.md` | public |
| `integrations/openai-agents/README.md` | `wiki/integrations/openai-agents.md` | public |
| `integrations/gateway/README.md` | `wiki/integrations/gateway.md` | public |
| `integrations/payment-protocols/README.md` | `wiki/integrations/payment-protocols.md` | public |
| `integrations/openclaw/README.md` | `wiki/integrations/openclaw.md` | public |
| `docs/owasp-agentic-mapping.md`, security audit reports | `wiki/security/threat-model.md` | public |
| `docs/owasp-agentic-mapping.md` | `wiki/security/owasp-mapping.md` | public |
| `spec/CONFORMANCE.md`, `spec/test-vectors.json` | `wiki/security/conformance.md` | public |
| `CLAUDE.md`, `package.json` | `wiki/architecture/monorepo-layout.md` | public |
| `landing/deploy.sh`, CI workflows | `wiki/architecture/build-deploy.md` | internal |
| `contracts/` | `wiki/architecture/contracts.md` | public |
| `strategy/*.md` | `wiki/strategy/competitive-landscape.md` | internal |
| GTM strategy docs | `wiki/strategy/gtm.md` | internal |
| `strategy/zk-vs-rfc7662-differentiation.md` | `wiki/strategy/differentiation.md` | internal |
| `discovery-autoresearch/` | `wiki/research/discovery-summary.md` | internal |
| `differentiation-autoresearch/` | `wiki/research/differentiation-summary.md` | internal |
| `patent-autoresearch/` | `wiki/research/patent-summary.md` | internal |
| `protocol-autoresearch/` | `wiki/research/protocol-summary.md` | internal |

## Naming Conventions

- Files: `kebab-case.md`
- Directories: match topic categories
- Cross-references: `[[wiki/category/slug]]` wikilink syntax

## Visibility Rules

- `public` — rendered to HTML and deployed to bolyra.ai/wiki/
- `internal` — markdown only, never deployed
- Default: `internal` (must explicitly opt in to public)
- `strategy/` and `research/` are ALWAYS internal
- `protocol/`, `sdk/`, `integrations/`, `security/` can be public

## Staleness Thresholds

| Category | Default |
|----------|---------|
| protocol/ | 60d |
| sdk/ | 14d |
| integrations/ | 14d |
| security/ | 30d |
| architecture/ | 30d |
| strategy/ | 7d |
| research/ | 7d |

## Agent Instructions

When ingesting a source:
1. Read the source document fully
2. Check if a wiki page already covers this topic
3. If yes: UPDATE the existing page (preserve structure, update content)
4. If no: CREATE a new page in the appropriate category
5. Always update `wiki/_index.md`
6. Set `last-updated` to today
7. List all source files in `sources:` frontmatter

When updating:
- Preserve the page's existing structure unless it's wrong
- Add new information, don't delete still-valid content
- Update `last-updated`
- Add new sources to `sources:` list

Quality rules:
- Write for an engineer who has 5 minutes, not 50
- Lead with "what does this do" before "how does it work"
- Include code snippets only when they clarify (not for bulk)
- Link to raw sources for full detail
- No marketing language in internal pages

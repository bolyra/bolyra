# IETF Outreach Email — draft-klrc-aiagent-auth-01

**Status:** Ready to send. Codex-reviewed 2026-06-11.

**Author addresses (verified 2026-05-09 from IETF datatracker):**

- Pieter Kasselman <pieter@defakto.security> — Defakto Security
- Jeff Lombardo <jeffsec@amazon.com> — AWS
- Yaroslav Rosomakho <yrosomakho@zscaler.com> — Zscaler
- Brian Campbell <bcampbell@pingidentity.com> — Ping Identity
- Nick Steele <steele@openai.com> — OpenAI

**Attach on request:** `drafts/ietf-mapping-1pager.md` (offer to send, don't lead with it)

---

**To:** pieter@defakto.security, jeffsec@amazon.com, yrosomakho@zscaler.com, bcampbell@pingidentity.com, steele@openai.com
**Cc:** viswa@bolyra.ai
**Subject:** ZKP privacy layer for draft-klrc-aiagent-auth-01

Hello,

I'm working on Bolyra, a zero-knowledge protocol for mutual human/AI-agent authentication and scoped delegation. I'm writing because parts of it may be relevant to draft-klrc-aiagent-auth-01, especially around privacy-preserving agent binding and delegated authorization.

Recent implementation work:

- `@bolyra/mcp` v0.4.0 adds MCP HTTP/stdio middleware, dev-mode proof bundles for local testing without circuit artifacts, and per-tool permission gating via `checkToolPolicy`.
- `@bolyra/payment-protocols` v0.5.0 adds `authorizeCommerceIntent`, a unified commerce authorization API. Stripe ACP and x402 are wired; Visa TAP and Google AP2 currently fail closed while preserving the same decision/receipt shape.

My concrete question: would a ZKP receipt/delegation layer like this be directionally useful as an extension point or companion draft to the KLRC OAuth-based flow?

I have a short mapping showing how Bolyra could address AS-minimization and model/agent-binding concerns without changing the core OAuth flow. I'm happy to send it, or to open a GitHub issue/PR if that is the better venue.

GitHub: https://github.com/bolyra/bolyra
Spec: https://github.com/bolyra/bolyra/blob/main/spec/draft-bolyra-mutual-zkp-auth-01.md
MCP example: https://github.com/bolyra/bolyra/tree/main/integrations/mcp/examples/protected-file-server

Thank you for the work on the draft.

Viswanadha Pratap Kondoju
Bolyra / ZKProva Inc.
viswa@bolyra.ai
https://bolyra.ai

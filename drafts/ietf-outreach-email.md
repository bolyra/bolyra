# IETF Outreach Email — draft-klrc-aiagent-auth-01

**Status:** Ready to send. Updated 2026-06-11 with v0.4.0/v0.5.0 references.

**Author addresses (verified 2026-05-09 from IETF datatracker, draft-klrc-aiagent-auth-01):**

- Pieter Kasselman <pieter@defakto.security> — Defakto Security
- Jeff Lombardo <jeffsec@amazon.com> — AWS
- Yaroslav Rosomakho <yrosomakho@zscaler.com> — Zscaler
- Brian Campbell <bcampbell@pingidentity.com> — Ping Identity
- Nick Steele <steele@openai.com> — OpenAI

**Attach:** `drafts/ietf-mapping-1pager.md` (rendered to PDF or inline)

---

**To:** pieter@defakto.security, jeffsec@amazon.com, yrosomakho@zscaler.com, bcampbell@pingidentity.com, steele@openai.com
**Cc:** viswa@bolyra.ai
**Subject:** ZKP privacy layer for draft-klrc-aiagent-auth-01 — directional compatibility check

Hello,

I built Bolyra, a zero-knowledge proof protocol for mutual human-AI agent authentication. Two releases shipped this week that overlap with the authorization semantics in your draft:

- **v0.4.0** — MCP dev mode. Any Model Context Protocol server gets ZKP-verified agent identity in 60 seconds, zero circuit artifacts. Per-tool permission gating via cumulative-bit bitmask. (`npm install @bolyra/mcp`)

- **v0.5.0** — Unified commerce authorization. One API (`authorizeCommerceIntent`) answers whether an agent purchase is authorized across Stripe ACP, x402, Visa TAP, and Google AP2. The agent proves it has the right permissions without revealing its credential to the payment rail.

The protocol specification is at `spec/draft-bolyra-mutual-zkp-auth-01.md` in the repo. 49 conformance tests pass across circuits and contracts.

**My question:** Are Bolyra's receipt/delegation/payment authorization primitives directionally compatible with where you think the KLRC draft should go? I have a 4-page mapping that shows where ZKP fills the AS-blind and model-instance-binding gaps in the current OAuth-based flow. Happy to share it if useful.

If a 20-minute call would help, I am available. Written feedback equally welcome. If neither, treat this as an FYI.

- GitHub: https://github.com/bolyra/bolyra
- Landing: https://bolyra.ai
- MCP example: https://github.com/bolyra/bolyra/tree/main/integrations/mcp/examples/protected-file-server

Thank you for the work on this draft.

Viswanadha Pratap Kondoju
Bolyra (ZKProva Inc.)
viswa@bolyra.ai
https://bolyra.ai

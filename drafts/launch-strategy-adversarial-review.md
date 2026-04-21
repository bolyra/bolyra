# Launch Strategy Adversarial Review
Reviewed: 2026-04-20
Source: Claude Opus subagent (Codex hung overnight, fell back to Claude)

## 3 CRITICAL BLOCKERS (must fix before any public launch)

### 1. SDK DOESN'T WORK END-TO-END
Integration tests fail with circom template errors. SDK not published to npm.
Every code snippet in the Twitter thread, landing page, and tutorial will produce
a hard failure when a developer tries `npm install @bolyra/sdk`.

### 2. NO TESTNET DEPLOYMENT
Contracts exist but are not deployed anywhere. No contract address for the SDK
to point at. Cannot demo "verify on-chain" without a chain.

### 3. EAD MAKES VC/YC OUTREACH DANGEROUS
LinkedIn post targeting VCs (Day 8) = commercial solicitation.
YC application (Day 10) = seeking employment/compensation.
Both create paper trails of commercial intent before EAD issuance.
Risk: denied EAD, deportation, re-entry bars.

## Key findings by axis

**Timing:** Product not ready. Fix integration tests, publish npm, deploy testnet first.

**Audience:** CT first is backwards. Lead with AI agent builder communities
(OpenAI ecosystem, Google A2A, Anthropic MCP), not crypto speculators.
Missing: Veramo/SpruceID/DIF for DID evaluation. AutoGPT builders.

**Positioning:** "Mutual ZKP auth" is too technical AND too vague.
Better: "Verified identity for AI agents" or "Passport for AI agents."
Lead with outcome, not mechanism.

**Competition:** Worldcoin ships "World ID for Agents" in weeks if you
get traction. Lit Protocol, Privy, Dynamic can add "agent auth" as a
feature. MIT-licensed code + public IETF draft = blueprint for competitors.

**Metrics:** All vanity except "3 inbound messages." Real PMF = someone
opens a GitHub issue for a feature you didn't plan, someone deploys your
contract on their own, someone writes code importing @bolyra/sdk.

**Legal:** Remove ALL VC/YC outreach until EAD arrives. Frame everything
as open-source research. Remove commercial language from landing page.
Do not collect emails or form a business entity.

**Execution gaps:** No quickstart guide, no hosted demo/playground, no CI/CD,
LangChain/CrewAI integrations are untested loose Python files, repo still
at bolyra/bolyra, demo video has nothing visual to show.

**Credibility:** Solo founder + AI-built code is a liability in ZK space.
No circuit audit. Trusted setup undocumented. Git history shows AI-generated
protocol design through automated scoring loops.

## REVISED RECOMMENDATION

Spend the next 2 weeks on:
1. Fix SDK integration tests
2. Publish @bolyra/sdk to npm
3. Deploy to Base Sepolia (get testnet ETH)
4. Write a 5-minute quickstart that actually works
5. ONE launch: Show HN with a working demo

Everything else is noise until the product works.

# Discovery Iteration 2 Report

- **Timestamp**: 20260619T185655
- **Signal sources scanned**: 16

## Tier 1: Discovery
- Opportunities found: 9
- Promoted to Tier 2: 9

## Tier 2: Validation
- Cards validated: 9
- Promoted to Tier 3: 4
- Dropped: 5

## Tier 3: Adversarial Challenge
- Challenged: 4
- Approved: 0
- Conditional: 0
- Rejected: 4

## Board Status
- Total opportunities on board: 0

## Rejected (feedback for next iteration)

- **ZKP Identity Layer for Agentic Commerce Transactions**: DEMAND FABRICATION: The '$547M-to-$5.2B' market size has no cited analyst report, no URL, no named buyer, and the card's own evidence array is literally empty. The Tier 2 demand score already flagged 'web search evidence returned zero results.' This is textbook phantom demand — conference-talk hype with zero procurement signals.; TIMING SELF-CONTRADICTION: The card's own timing_assessment field says '18_plus_months' yet it scored timing at 7/10. An 18+ month horizon for a pre-revenue, solo-founder startup on H1B is a death sentence — you'll burn runway building for a market that doesn't exist yet while incumbents watch and wait.; NO PRODUCTION AGENTS DOING COMMERCE: Name one enterprise running an AI agent that autonomously purchases goods with real money in production today. Not a demo, not a hackathon project — a production deployment. There are none. The entire opportunity assumes a deployment model (autonomous agent purchasing) that enterprises have not sanctioned and likely won't for years due to liability concerns.
- **ZKP Extension to IETF draft-klrc-aiagent-auth**: DEMAND: Zero verified demand signals. The opportunity card itself admits 'Web search evidence returned zero results; no verifiable URLs, named buyers, or engagement metrics.' The entire demand thesis rests on the existence of an early IETF draft that has no WG adoption. This is textbook phantom demand — conference-talk interest masquerading as procurement intent. No enterprise has asked for ZKP-based agent auth; they are still figuring out basic agent authorization with OAuth and API keys.; DEMAND: The 'buyer' for an IETF extension is not a buyer at all. Standards bodies do not pay. The theory that 'every implementation of draft-klrc becomes a distribution channel' requires draft-klrc to (a) finalize, (b) reference Bolyra specifically, and (c) generate implementations that actually integrate the privacy profile. Each step has <30% probability; chained probability is <3%.; COMPETITIVE MOAT: SPIFFE/WIMSE incumbents (HPE/SPIRE, Google, Microsoft) own the trust-domain infrastructure. If privacy-preserving agent auth becomes important, they will add encrypted attestation bundles or work with existing privacy-enhancing tech (Intel SGX attestation, AWS Nitro Enclaves) rather than adopt an external ZKP layer from a solo-founder startup with no IETF track record. The moat argument — 'incumbents have no incentive to build ZKP' — is exactly backwards: incumbents have no incentive to adopt YOUR ZKP either.
- **Cross-Platform Agent Identity Passport**: DEMAND FABRICATED: Card scores demand at 8/10 but demand_strength is literally 'none' — zero URLs, zero named buyers, zero analyst reports, zero procurement signals. This is vaporware demand. The rationale even admits 'web search evidence returned zero results.' An 8/10 demand score with zero evidence is self-deception.; PHANTOM MARKET: Nobody is running production agents across LangChain AND AutoGen AND Bedrock simultaneously today. Enterprises pick one framework. The 'cross-platform agent identity' problem assumes a multi-framework world that does not exist and may never exist — platforms consolidate, they don't federate.; OAUTH TOKEN EXCHANGE KILLS THIS: RFC 8693 (Token Exchange) already lets you swap a token from Platform A for a token on Platform B with scope narrowing. SPIFFE/SPIRE handles machine identity portability across trust domains. The 'passport' is literally what federated OAuth was designed for — no ZKP needed.
- **ZKP On-Behalf-Of for AWS Bedrock AgentCore**: DEMAND IS PHANTOM: The card's own rationale admits 'zero results' from web search, no GitHub issues, no RFPs, no named buyers. This is a founder projecting a use case onto a platform announcement, not responding to market pull. Nobody running Bedrock agents today is asking for ZKP-based delegation — they're asking for better IAM policies and guardrails.; AWS OWNS THE ENTIRE STACK AND WILL EAT THIS: AWS controls Bedrock, IAM, STS, and the OBO token exchange. If cryptographic scope narrowing becomes valuable, AWS will add it as a native IAM feature — they've done this repeatedly (Verified Access, IAM Roles Anywhere, SigV4 delegation). A 2-person startup cannot out-integrate AWS on their own platform. The 'privacy layer under incumbents' positioning is fantasy when the incumbent can trivially add the privacy layer themselves.; ZKP IS NOT NEEDED — STS TOKEN INTROSPECTION IS FINE: The 'eliminate IdP callback' pitch ignores that STS endpoints run in every AWS region with sub-10ms latency. Resource servers already verify OBO tokens via local policy evaluation, not round-trips. The privacy benefit (not revealing full permissions) is solvable with scoped IAM policies, which AWS already provides. ZKP adds 100-500ms proof generation latency to a flow that currently takes <50ms — this is a performance regression, not an improvement.

# EAD Constraints — H1B/EAD Activity Classification

Immigration-status constraints that govern what the Discovery AutoResearch Loop can recommend.

## Permitted Activities (CAN DO)

These are unambiguously allowed under H1B status and do not require EAD:

- **Open source development** — writing code, publishing under OSI-approved licenses
- **Protocol improvements** — contributing to specifications, reference implementations
- **SDK releases** — publishing libraries, tools, developer utilities
- **Documentation** — technical docs, API references, architecture guides
- **Conference talks** — if invited by the conference organizer (not self-organized marketing)
- **Academic publications** — papers, preprints, technical reports
- **Tech blog posts** — educational/technical content about the technology

## Prohibited Activities (CANNOT DO)

These require EAD or company formation and are off-limits:

- **Customer outreach** — cold emails, sales calls, lead generation
- **Sales calls** — demos with purchase intent, pricing negotiations
- **Revenue-generating activity** — charging for services, accepting payment
- **Consulting** — paid or unpaid advisory work that resembles employment
- **Founding a company** — incorporation, operating agreements, bank accounts
- **Hiring** — employment offers, contractor agreements

## Grey Zone

Activities that are technically permissible as open-source/technical work but have clear commercial benefit. Proceed with caution — keep the artifact purely technical, do not attach pricing or CTAs:

- **Marketing materials** — could be "technical overviews" if framed correctly
- **Product landing pages** — informational only, no purchase flow
- **Pricing pages** — absolutely not until EAD

## Classification Rules for the Loop

Every opportunity or action item surfaced by the autoresearch loop MUST be classified:

| Classification | Criteria | Action |
|---|---|---|
| **BUILD_NOW** | Pure technical work. No commercial interaction. Could be done by any OSS contributor. | Execute immediately. |
| **WAIT_FOR_EAD** | Requires commercial engagement, revenue, company formation, or customer-facing sales activity. | Log to backlog. Do not execute. |
| **GREY_ZONE** | Technical work with obvious commercial benefit. Could be reframed as pure OSS contribution but walks the line. | Execute only the technical artifact. Strip any commercial framing. Document the constraint. |

### Decision Heuristic

When in doubt, ask: "Would an open-source maintainer with no commercial interest do this?" If yes, BUILD_NOW. If no, WAIT_FOR_EAD. If "maybe, but it sure looks like marketing," GREY_ZONE.

# bolyra.ai redesign brief (PARKED until 5 commercial asks are made)

Status 2026-07-19: reviewed by Fable + Codex, both agree. Do NOT implement before the
5-ask threshold (tracker: .viswa/projects/bolyra-commercial-asks.md). A pretty redesign
before commercial signal is avoidance.

## Use from the handoff (design-reference.dc.html)
The VISUAL SYSTEM only:
- warm near-black #0d0c0a / #131109 panels / warm hairlines #211e19-#38332b
- coral #ff6a4d accent (violet #8b7ff0 alt), success green #7a9e6b
- Instrument Serif display (italic accent phrases) + Instrument Sans + IBM Plex Mono eyebrows
- near-square radii (2px buttons), 1160px grid, gap-as-border feature grid, stats strip
- the CONSOLE MOCKUP pattern (window chrome + sidebar + audit-trail rows)

## Replace ALL content. The handoff was designed for the wrong company ("ops agents").
Never ship from it: "SOC 2 Type II" (false), invented stats, placeholder testimonial,
"private beta", "priced per outcome", "deploys AI agents / operations" positioning,
generic "Book a demo" motion.

## Content arc (payments-first, per spearhead positioning)
1. Hero: prove an agent was authorized before it spends.
2. Console mockup = REAL gate trail: $25 ALLOW / $500 DENY 403 request_mismatch /
   no-mandate DENY 401 / awaiting approval over threshold; receipt hashes in mono.
   Sidebar: agents with mandates. All content from `npx @bolyra/mpp demo` output.
3. Object: mandate -> verdict -> signed receipt.
4. EVC: open verifier boundary, no lock-in (keep current copy).
5. Use cases: payment rails, agent wallets, trading agents, MCP gateways.
6. Credibility: real numbers only (packages, conformance vectors, merged upstream
   fixes, standards work). Stats strip carries honest figures.
7. CTA: agent spend authorization pilot (20-min technical fit call).

## Constraints
- Responsive required (handoff is desktop-only).
- Honesty rule: no fake trust signals, no testimonials until a real one exists.
- Serif-editorial style must stay grounded by console/object/spec artifacts,
  otherwise it reads as marketing theater (Codex).

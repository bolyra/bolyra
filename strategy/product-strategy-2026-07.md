# Bolyra Product Strategy — July 2026

- **Status:** Codex-AGREED 2026-07-11 (2 review rounds; claims registry/live-verified) — awaiting founder approval
- **Derives from:** the Codex-judged, founder-approved business strategy of 2026-07-09
  ("verified agent actions" enterprise wedge, `~/.claude/plans/how-can-i-make-tidy-rainbow.md`)
  and the Core/ZK split ruling of 2026-07-10. This document does not re-litigate
  either; it defines the *product* that executes them.
- **One-line:** Bolyra is the verification layer for agent actions — proof of who/what
  authorized each action, policy enforcement at a single point, and tamper-evident
  audit evidence — sold to agent-platform and MCP-infra vendors as their enterprise SKU.

---

## 1. Product thesis

Two lessons anchor everything:

1. **The primitive is commodity** (the Ed25519 lesson, 2026-07-05): any capable
   maintainer builds a signature gate in a weekend. Bolyra cannot be "the gate."
2. **The contract is the adoption path** (the EVC lesson, 2026-07-11):
   `mcp_agent_mail_rust#183` publicly validated the spawned external-verifier shape
   Bolyra standardized in EVC v1, with the maintainer's stated requirements matching
   `bolyra verify` nearly 1:1. Treat this as design validation, not independent
   adoption, until a third-party host publishes a passing conformance run.

Therefore the product is layered so that the commodity part is open and
standardized (maximizing surface area for adoption), while revenue comes from the
operational system around verification — the part that is not weekend-buildable:
policy control, credential registries, signed and hash-chained receipts, audit
evidence, delegation narrowing, and operated infrastructure.

**"Core gets you verified actions. ZK gets you verified actions without
disclosure."** (Codex, 2026-07-10.)

## 2. Who it's for

- **Buyer:** agent-platform / MCP-infrastructure vendors (not banks/CISOs directly)
  who need a sellable "verified agent actions" enterprise SKU. 30-account list
  maintained at `loops/distribution/target-list-2026-07-09.md`; wave 1 in market.
- **User:** the vendor's platform/security engineers (integrate the gateway or the
  EVC contract) and their enterprise customers' auditors (consume the receipts).
- **Emerging vertical signal:** financial-agent repos are where external PRs
  actually merged (both merged PRs were trading repos). Wave 2 targets money-moving
  agents over generic MCP infra.
- **Ecosystem peer, not target:** Arcade.dev ($60M, June 2026, adjacent positioning)
  is ruled a standards ally — Bolyra sells *portable, verifiable, auditable
  authorization across vendors*, never "the secure action layer."

## 3. Product architecture — four surfaces, three tiers

### 3.1 Open core: the standard + reference implementations (free, Apache-2.0)

| Asset | State |
|---|---|
| External Verifier Contract v1 (`spec/external-verifier-contract-v1.md`, RFC-2119) | Shipped; design-validated externally (mcp_agent_mail_rust#183) |
| `bolyra verify` CLI (`@bolyra/cli` 0.5.0) — spawnable stdin/stdout verifier | Published, attestation registry-verified 2026-07-11 |
| Conformance suite — 99 vectors: 94 passing, 5 experimental skipped; incl. 22 `host_behavior` vectors + misbehaving-verifier fixtures | Shipped |
| Reference hosts — JS (shipped), Rust (`spec/reference-host-rs/`, in flight) | Rust scoped as REFERENCE, not SDK |
| SDK primitives (`@bolyra/sdk` 0.6.1, lazy-ZK: Core paths never load snarkjs) | Shipped |

**Job:** make EVC v1 the neutral way any host delegates verification, so "works
with Bolyra" is the path of least resistance. Explicitly *not* revenue. Success
metric: independent hosts/verifiers passing the conformance suite.

### 3.2 Paid: Bolyra Gateway — the operational system (Core tier)

`@bolyra/gateway` 0.5.0 (published, attestation registry-verified 2026-07-11;
`@bolyra/receipts` 0.8.0 likewise): single enforcement point for MCP/agent fleets.
Credential registry + binding (unknown/forged/expired → signed deny), hop-by-hop
delegation narrowing, ES256K-signed receipts for **every** decision (allow and
deny), hash-chained tamper-evident audit (`bolyra receipt verify-chain`; chain
fields inside the signed payload so re-linking breaks the signature), honest
degradation labels (self-asserted vs cryptographically bound).

**Pricing (Codex-set):** $25k/90-day pilot → $48k/yr startup → $100–150k/yr
enterprise. Pilot paper exists (`docs/pilot/`, one-pager + SOW template,
attorney-review-gated).

### 3.3 Paid: Bolyra ZK upgrade (premium tier)

Everything in Core, plus what classical crypto cannot do: authorization proofs
**without disclosure** (operator identity, scope, model stay private under
Groth16/scopeCommitment binding), cross-operator delegation chains, selective
disclosure for multi-party fleets. Known v1 trade-off already documented: the
classical external-verifier path reveals the credential preimage; a future circuit
revision restores selective disclosure — that revision belongs to this tier's
roadmap. **$150–250k/yr, $250k+ OEM.** ZK is the differentiator, never the pitch
opener.

### 3.4 Operated: hosted verify (Design Partner Preview → SKU-1)

Live at `bolyra-hosted-verify.workers.dev` (health endpoint smoke-checked
2026-07-11): EVC v1 over HTTP (classical only),
bearer-token per partner, labeled usage analytics, honesty-by-design `/health`
disclosure. Deliberately thin — no SLA/billing/dashboard/multi-tenant until a
**signed pilot** gates the production SaaS build. Every operated surface ships
with observability; OSS packages never carry default telemetry.

## 4. Moats (in defensibility order)

1. **The evidence chain** — signed receipts + hash chains + conformance-verified
   behavior compose into audit evidence an enterprise can retain and verify
   offline. Replicating this credibly requires the whole system plus a track
   record, not a feature.
2. **The standard + conformance ecosystem** — every host that adopts EVC v1 (or
   passes `host_behavior` vectors) enlarges Bolyra's addressable surface without
   Bolyra writing adapters. Second independent implementations (Rust host) are
   standards credibility competitors must match.
3. **The ZK layer** — for cross-operator and disclosure-sensitive deployments,
   there is no classical substitute; Bolyra's circuits, ceremony/vkey discipline,
   and conformance fixtures are the hard-to-copy technical layer.
4. **Operational trust** — OIDC-attested provenance on 9 of 11 npm packages
   (registry-verified 2026-07-11; `circuits` and `ai` pending their next release),
   public honesty caveats in docs, fail-closed defaults. Slow to build, fast to
   lose, hard to copy.

## 5. Roadmap discipline: pull, not push

Standing freeze (business strategy): no new adapters/SDKs/blog/polish until a
paid pilot. Product work is admitted through four gates only:

1. **Pilot-blocking** — a prospect's fit call surfaces a gap (e.g., shield
   credential-binding parity is explicitly deferred-until-asked).
2. **Claim-truth** — shipped copy must be literally true in code (precedents:
   deny receipts, hash chains, packaged-proxy signing). Any marketing claim that
   code doesn't back gets fixed or softened within days.
3. **Standards momentum** — cheap artifacts that compound EVC adoption (targeted
   vectors when Dicklesworthstone asks; Rust reference host).
4. **Capacity-fill standards leverage** — when no pilot-blocking work exists,
   build only low-scope artifacts that increase EVC adoption (currently: the Rust
   reference host).

## 6. Explicit non-goals

- No dashboards, admin UIs, or "platform" surface pre-pilot (ugly-but-real admin
  UI is a month-3 deliverable *inside* a pilot).
- No new framework adapters or SDK surfaces; the Rust host stays a reference.
- No public SaaS launch, SLA, billing, or metering before a signed pilot.
- No ZK-first marketing; no ZKProva work; no new provisional patents.
- No maintained fork of anyone's host; contract/vectors-level collaboration only
  (mcp_agent_mail policy: no outside PRs).

## 7. Measures and kill criteria (inherited, unchanged)

- **Month 1:** ≥5 serious calls per 100 targeted outreaches, else re-cut
  positioning with Codex. (Clock running since wave-1 sends, 2026-07-10.)
- **Month 3:** somebody pays ($25k pilot) or repackage.
- **Month 6:** ACV not stuck under $10k, else the market is saying "dev tool."
- **Month 12:** ≥$250k ARR or the $1M/24-month base case is dead.
- **Product-level leading indicators:** EVC adoptions (hosts passing conformance),
  hosted-preview usage by labeled partner, receipts verified offline by a third
  party, fit-call gaps (each is roadmap signal).

## 8. Risks and stances

| Risk | Stance |
|---|---|
| Arcade (or a platform) ships "good enough" verification natively | Interop, don't fight: EVC works across vendors; sell portability + audit evidence; standards-ally posture |
| Commodity collapse of the gate (again) | Already conceded — open-core it; revenue sits in the operational system |
| Solo-founder capacity | Pull-gated roadmap + Codex prioritization + kill checkpoints; no speculative surface area |
| Vkey/ceremony integrity for production ZK tags | Standing gate: confirm shipped vkeys are real ceremony output before any production ZK tag |
| Over-marketing the #183 validation | Use in fit calls; no public victory laps (Codex ruling) |

# Tier 3: Adversarial Rubric

Tier 3 is the final gate. Every opportunity that survived Tier 1 (discovery) and Tier 2 (validation) faces adversarial stress-testing across 5 attack axes. The goal is to kill opportunities that look good on paper but will fail in reality.

Each axis is scored **independently** on a PASS/FAIL/CONDITIONAL basis. An opportunity must PASS or CONDITIONAL on all 5 axes to receive a final GO recommendation.

---

## Attack Axis 1: Market Reality
*"Why will nobody buy this?"*

The adversary's job is to construct the strongest possible argument that this opportunity has no real buyers.

### Attack vectors:
- **Phantom demand**: The "demand" is blog posts and conference talks, not purchase orders. People discuss it but nobody will pay for it.
- **Free alternative**: An adequate solution already exists for free (open-source library, built-in platform feature, simple workaround).
- **Wrong buyer**: The people who want it (developers) are not the people who pay for it (enterprises), and the people who pay for it do not care.
- **Market too small**: Even if real, the addressable market is < $10M TAM, not worth the opportunity cost.
- **Chicken-and-egg**: Solution requires ecosystem adoption that will not happen without the solution already existing.

### Scoring:
- **PASS**: The adversary cannot construct a convincing argument against market reality. Demand is verified through procurement signals, not just interest signals.
- **CONDITIONAL**: The adversary raises valid concerns but they have specific, actionable mitigations. List each mitigation.
- **FAIL**: The adversary constructs a convincing argument that nobody will buy this. Kill the opportunity.

### Required output:
- Strongest "nobody will buy this" argument (3-5 sentences, steel-manned)
- Rebuttal (3-5 sentences with evidence)
- Verdict: PASS / CONDITIONAL (with mitigations) / FAIL

---

## Attack Axis 2: Competitive Moat
*"What stops Visa/Worldcoin from doing this in 2 weeks?"*

The adversary's job is to argue that incumbents or well-funded competitors can trivially replicate this.

### Attack vectors:
- **Incumbent advantage**: Visa, Microsoft, or Okta already have the distribution, trust, and infrastructure. They can add this as a feature, not a product.
- **Funded competitor**: A startup with $50M+ in funding is already building this exact thing. They have a 12-month head start and a team of 20.
- **No technical moat**: The ZKP/crypto layer is not actually defensible. Anyone can fork Circom circuits. The value is in distribution, not technology.
- **Standards capture**: An incumbent is driving the standard (IETF, W3C) and will bake in their own architecture as the default.
- **Platform risk**: The opportunity depends on a platform (AWS, LangChain) that can build the feature natively and eliminate the need.

### Scoring:
- **PASS**: Bolyra has a defensible position that incumbents cannot replicate in < 6 months. Moat is based on architectural decisions, not just speed.
- **CONDITIONAL**: Incumbents could replicate but specific factors (privacy requirements, regulatory constraints, ZKP-specific properties) create a defensible niche. List the niche.
- **FAIL**: An incumbent or funded competitor can and likely will ship this faster and with better distribution. Kill or pivot.

### Required output:
- Strongest "they'll eat your lunch" argument (3-5 sentences, name the specific competitor)
- Moat analysis (what specifically is hard to replicate and why)
- Verdict: PASS / CONDITIONAL (with niche definition) / FAIL

---

## Attack Axis 3: Technical Fit
*"Is ZKP actually needed here, or is non-ZKP simpler?"*

The adversary's job is to argue that the same problem can be solved more simply without zero-knowledge proofs.

### Attack vectors:
- **OAuth is enough**: Standard OAuth 2.0 scopes and token delegation already solve the authorization problem. ZKP adds unnecessary complexity.
- **mTLS is enough**: Mutual TLS with certificate pinning provides sufficient machine identity. No need for on-chain verification.
- **Simple encryption is enough**: The privacy requirement can be met with standard encryption (AES, RSA) without the computational overhead of ZK circuits.
- **Centralized trust is acceptable**: The users in this market are fine with a trusted third party. Decentralization is a solution looking for a problem.
- **Performance penalty**: ZK proof generation adds latency that is unacceptable for the use case (real-time agent-to-agent communication, high-frequency transactions).

### Scoring:
- **PASS**: ZKP provides properties that cannot be replicated by simpler approaches. Specifically: proof without revelation, selective disclosure, or verifiable computation where the verifier must not learn the input.
- **CONDITIONAL**: ZKP is not strictly necessary but provides meaningful advantages (privacy, auditability, portability) that justify the complexity for a specific buyer segment. Define that segment.
- **FAIL**: A non-ZKP approach is strictly simpler, cheaper, and meets all buyer requirements. ZKP is overengineering. Kill or reposition.

### Required output:
- Strongest "just use OAuth/mTLS" argument (3-5 sentences, with specific alternative architecture)
- ZKP necessity argument (what specific property requires ZKP, with concrete example)
- Verdict: PASS / CONDITIONAL (with segment) / FAIL

---

## Attack Axis 4: Timing
*"Is this 12 months early?"*

The adversary's job is to argue that the market is not ready and building now is wasted effort.

### Attack vectors:
- **No production agents**: Enterprises are still in POC/pilot phase with AI agents. Production deployments with real authorization needs are 12+ months away.
- **Standards not ready**: The relevant standards (IETF agent auth, W3C DID for agents) are in early draft. Building to a moving target means rework.
- **Infrastructure missing**: Key infrastructure (agent orchestration platforms, reliable tool-use, production-grade LLMs) is not mature enough to support the use case.
- **Regulatory uncertainty**: Regulations (EU AI Act, NIST guidance) are not finalized. Compliance requirements may shift, invalidating current design decisions.
- **Hype cycle position**: This is at the peak of inflated expectations. The trough of disillusionment is coming. Building now means surviving 12-18 months of market disinterest.

### Scoring:
- **PASS**: Clear evidence that the market is buying now (this quarter). Production deployments exist. Standards are stable enough to build against. Timing risk is < 3 months.
- **CONDITIONAL**: Market is 3-6 months from readiness but early positioning is strategically valuable (standards influence, early adopter relationships, patent positioning). List the specific strategic value of being early.
- **FAIL**: Market is 12+ months away. Building now means carrying inventory with no revenue signal. Better to monitor and re-enter.

### Required output:
- Strongest "you're too early" argument (3-5 sentences with specific timeline evidence)
- Counter-argument (what specific evidence shows the market is ready or that early entry is strategic)
- Verdict: PASS / CONDITIONAL (with strategic justification) / FAIL

---

## Attack Axis 5: Founder Feasibility
*"Can one person actually ship this?"*

The adversary's job is to argue that a solo founder on H1B cannot realistically deliver this.

### Attack vectors:
- **Scope creep**: The MVP looks small but has hidden dependencies (circuit auditing, contract deployment, SDK documentation, developer relations) that triple the actual effort.
- **Quality bar**: Enterprise buyers require SOC2 compliance, SLAs, and support. A solo founder cannot meet these requirements, making the MVP unsellable.
- **Immigration risk**: H1B constraints mean no side revenue, employer-tied authorization, and potential complications with independent product development. Legal grey areas could jeopardize visa status.
- **Maintenance burden**: Shipping is 30% of the work. Ongoing maintenance, bug fixes, security patches, and user support consume the other 70%. One person cannot sustain this.
- **Burnout**: The founder is also maintaining a patent portfolio, a separate product (GeniusComply/ZKProva), and navigating immigration. Adding another initiative is not feasible without dropping something.

### Scoring:
- **PASS**: MVP is genuinely shippable in <= 14 days by one person. Maintenance burden is minimal (< 2 hours/week post-launch). No immigration complications. Does not conflict with existing commitments.
- **CONDITIONAL**: MVP is shippable but requires deprioritizing something else. Or maintenance burden is manageable but non-trivial. Or immigration implications need legal review before proceeding. List what gets deprioritized and what needs legal review.
- **FAIL**: MVP scope is unrealistic for one person in 2 weeks. Or immigration risk is unacceptable. Or it conflicts with higher-priority commitments that cannot be deferred.

### Required output:
- Strongest "you can't actually do this" argument (3-5 sentences, specific to founder's situation)
- Feasibility defense (specific MVP scope, day-by-day plan, what gets deprioritized)
- Verdict: PASS / CONDITIONAL (with tradeoffs) / FAIL

---

## Final Verdict

| Result | Criteria |
|--------|----------|
| **GO** | PASS on all 5 axes, OR PASS on 4 + CONDITIONAL on 1 with acceptable mitigations. |
| **CONDITIONAL GO** | PASS on 3 + CONDITIONAL on 2. Must document both conditions and their resolution criteria. |
| **NO GO** | FAIL on any axis, OR CONDITIONAL on 3+ axes. Archive the opportunity with re-evaluation triggers. |

## Output Format

The Tier 3 adversarial review produces a single document with:

1. **One-line opportunity statement**
2. **5 attack axis evaluations** (each with attack, rebuttal, verdict as specified above)
3. **Final verdict** (GO / CONDITIONAL GO / NO GO)
4. **If GO or CONDITIONAL GO**: Ship specification with exact scope, timeline, and success criteria
5. **If NO GO**: Archive note with conditions under which to re-evaluate (e.g., "re-evaluate when IETF draft reaches RFC status")

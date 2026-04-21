# Tier 2: Validation Rubric

Tier 2 applies stricter evidence requirements to opportunities that passed Tier 1. Each claim must be backed by specific, verifiable evidence. No hand-waving, no "general industry trends," no appeal to vibes.

## Scoring Dimensions

### DEMAND (0-25)
*Must cite specific URLs/sources.*

| Score | Label | Criteria |
|-------|-------|----------|
| 0-5 | **No verifiable demand** | Cannot produce a single URL, GitHub issue, or named company actively seeking this solution. |
| 6-10 | **Anecdotal demand** | 1-2 sources only. Blog posts or tweets without engagement metrics. No named buyers. |
| 11-15 | **Documented demand** | 3+ independent sources with URLs. GitHub issues with measurable engagement (stars, comments, upvotes). At least one named company or team expressing the need publicly. |
| 16-20 | **Validated demand** | Named enterprises or funded startups building in the space. Specific funding amounts cited with Crunchbase/PitchBook URLs. Job postings for roles that imply this need. RFP language or procurement frameworks referencing the problem. |
| 21-25 | **Proven demand** | Active procurement cycles with named buyers. Published market sizing from reputable analysts (Gartner, Forrester, IDC) with report URLs. Multiple funded competitors (cite each with round size and date). Revenue numbers or LOIs from companies in the space. |

**Evidence requirement:** Every DEMAND score >= 11 must include at least 3 source URLs. Scores >= 16 must include at least 5 URLs with specific data points extracted from each.

### TIMING (0-25)
*Must reference specific competitor launches or standard milestones.*

| Score | Label | Criteria |
|-------|-------|----------|
| 0-5 | **No timeline anchors** | Cannot name a single competitor launch date, standard milestone, or regulatory deadline. Timing argument is purely speculative. |
| 6-10 | **Vague timeline** | General awareness that "things are moving" but only 1-2 concrete dates. No competitor has shipped. Standards are in early draft with no publication timeline. |
| 11-15 | **Anchored timeline** | At least 3 specific dated events: competitor beta launches, standard draft publications, regulatory comment periods. Can construct a 6-month timeline of market milestones. |
| 16-20 | **Clear window** | Named competitors with shipped products and launch dates. Standards with published timelines (RFC numbers, draft versions, expected finalization dates). Regulatory deadlines with docket numbers. Can pinpoint the window to within 1-2 quarters. |
| 21-25 | **Closing window** | Multiple competitors already in market (name each with launch date). Standard finalization imminent (cite draft version and IESG/W3C review status). Enterprise budget cycles aligned (cite fiscal year timing for target segments). Window closes within 3-6 months with specific evidence. |

**Evidence requirement:** Every TIMING score >= 11 must include a timeline table with at least 3 dated milestones. Scores >= 16 must include competitor launch dates and standard version numbers.

### FIT (0-25)
*Must map to specific Bolyra primitives by name.*

| Score | Label | Criteria |
|-------|-------|----------|
| 0-5 | **No primitive mapping** | Cannot name a single Bolyra circuit, contract, or SDK module that applies. |
| 6-10 | **Tangential mapping** | One primitive loosely applies but the connection requires significant hand-waving. ZKP adds complexity without clear privacy/verification benefit over conventional approaches. |
| 11-15 | **Partial mapping** | 1-2 named primitives apply directly. At least one new circuit or contract function is required. ZKP provides a real but not essential advantage. Must specify: which existing primitives, what new work, and why ZKP over alternatives. |
| 16-20 | **Strong mapping** | 2-3 named primitives map directly. New work is limited to extending existing patterns (e.g., new inputs to an existing circuit template, new function in an existing contract). ZKP provides clear competitive advantage. Must provide a primitive-by-primitive mapping table. |
| 21-25 | **Native mapping** | 3+ existing primitives serve the use case with minimal modification. The use case is a natural extension of Bolyra's architecture. ZKP is essential -- the problem fundamentally requires proof without revelation, selective disclosure, or verifiable computation. Must provide complete mapping with function signatures. |

**Evidence requirement:** Every FIT score >= 11 must include a mapping table with columns: Primitive Name, Type (circuit/contract/SDK), Status (exists/extend/new), and Modification Required.

### FEASIBILITY (0-25)
*Must provide concrete MVP deliverable list with day estimates.*

| Score | Label | Criteria |
|-------|-------|----------|
| 0-5 | **No viable MVP** | Cannot define a shippable MVP that a solo founder can build. Requires team, capital, partnerships, or regulatory approvals. |
| 6-10 | **Stretch MVP** | MVP defined but estimated at 4-8 weeks solo. Significant unknowns in circuit development or third-party integration. At least one dependency outside founder's control. |
| 11-15 | **Tight MVP** | MVP defined with 2-3 week estimate. Deliverable list is concrete but includes 1-2 items with estimation uncertainty. All dependencies are within founder's control. Must list every deliverable with day estimate. |
| 16-20 | **Confident MVP** | MVP defined with 1-2 week estimate. Every deliverable has a day estimate with < 50% variance. Reuses existing code for 60%+ of the work. No external dependencies. Must include a day-by-day build plan. |
| 21-25 | **Ship-ready MVP** | MVP can ship in under 1 week. All deliverables are well-understood patterns. 80%+ code reuse. Day-by-day plan with specific files to create/modify. Demo script included. |

**Evidence requirement:** Every FEASIBILITY score >= 11 must include a deliverable table with columns: Deliverable, Type (circuit/contract/SDK/API/test/doc), Estimated Days, Dependencies, and Risk Level (low/medium/high).

## Tier 2 Thresholds

| Total Score | Action |
|-------------|--------|
| **80-100** | **Promote to Tier 3** (adversarial review). Fast-track candidate. |
| **65-79** | **Promote to Tier 3** if FEASIBILITY >= 16 and no dimension < 12. |
| **50-64** | **Defer with bookmark.** Strong signal but not ready or not feasible now. Re-evaluate next cycle. |
| **0-49** | **Kill.** Evidence does not support the opportunity. Archive findings for future reference. |

## Output Requirements

Every Tier 2 evaluation must produce:

1. **Evidence dossier**: All URLs, quotes, and data points organized by dimension.
2. **Primitive mapping table**: Complete mapping of opportunity to Bolyra architecture.
3. **MVP specification**: Deliverable list with day estimates and dependency graph.
4. **Risk register**: Top 3 risks with likelihood (low/medium/high) and mitigation.
5. **Verdict**: PROMOTE / DEFER / KILL with 2-3 sentence rationale.

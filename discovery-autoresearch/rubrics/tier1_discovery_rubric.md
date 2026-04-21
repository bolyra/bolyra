# Tier 1: Discovery Rubric

Tier 1 is the initial scoring pass. Each opportunity is scored across 4 dimensions for a maximum of 100 points. Tier 1 uses a **low evidence bar** -- signals, impressions, and directional data are sufficient. The goal is to quickly filter a large set of opportunities down to a shortlist for deeper validation.

## Scoring Dimensions

### DEMAND (0-25)
*Is anyone actually asking for this?*

| Score | Label | Criteria |
|-------|-------|----------|
| 0-5 | **No signal** | No evidence anyone wants this. Founder's imagination only. |
| 6-10 | **Weak signal** | A few blog posts or tweets mention the problem. No GitHub issues, no forum threads, no enterprise RFPs. Could be manufactured demand. |
| 11-15 | **Emerging signal** | Multiple independent sources mention the problem. Some GitHub issues with >10 upvotes. At least one developer community thread with substantive discussion. No evidence of enterprise budgets yet. |
| 16-20 | **Clear signal** | Developers are building workarounds. Multiple GitHub issues across frameworks. At least one enterprise pilot or POC mentioned. Analysts have named the category. VC interest visible. |
| 21-25 | **Strong signal** | Enterprises actively procuring. Multiple startups funded in the space. Developer tools with >1K GitHub stars addressing adjacent problems. Conference talks dedicated to the topic. Budget line items exist. |

### TIMING (0-25)
*Is the market ready now, or are we early/late?*

| Score | Label | Criteria |
|-------|-------|----------|
| 0-5 | **Way too early** | The problem exists in theory but nobody is deploying AI agents at scale yet in this domain. Standards are years away. No competitive pressure. |
| 6-10 | **Early** | Early adopters experimenting. Standards in draft stage. Incumbents have announced intent but not shipped. 6-12 months before mainstream need. |
| 11-15 | **Approaching window** | Pilots converting to production. Standards nearing completion. At least one competitor has shipped a v1. 3-6 months to mainstream. |
| 16-20 | **In the window** | Production deployments happening. Standards published or near-final. Multiple competitors active but no dominant solution. Market is choosing now. |
| 21-25 | **Urgent window** | Rapid adoption underway. Enterprises making purchasing decisions this quarter. A dominant solution could emerge within months. Ship now or lose the window. |

### FIT (0-25)
*Does Bolyra's architecture actually serve this need?*

| Score | Label | Criteria |
|-------|-------|----------|
| 0-5 | **No fit** | Bolyra's primitives (ZKP circuits, identity contracts, SDK) are irrelevant to this problem. Would require building something entirely new. |
| 6-10 | **Weak fit** | ZKP is technically applicable but adds complexity without clear benefit over simpler approaches (OAuth, API keys, mTLS). Hard sell to developers. |
| 11-15 | **Moderate fit** | ZKP provides a genuine advantage (privacy, selective disclosure, proof without revelation) but requires new circuits or significant contract changes. |
| 16-20 | **Strong fit** | Existing Bolyra primitives cover 60-80% of the need. Minor extensions to circuits or contracts required. Clear ZKP value proposition. |
| 21-25 | **Perfect fit** | Existing circuits and contracts serve this use case directly. SDK changes are minimal. ZKP is not just useful but essential -- the problem cannot be solved well without it. |

### FEASIBILITY (0-25)
*Can a solo founder ship this in 2 weeks?*

| Score | Label | Criteria |
|-------|-------|----------|
| 0-5 | **Impossible solo** | Requires a team of 3+, specialized hardware, regulatory approvals, or partnerships that take months to establish. |
| 6-10 | **Very hard** | Technically possible solo but would take 4-8 weeks minimum. Significant new circuit development, complex contract interactions, or extensive third-party integrations. |
| 11-15 | **Hard but doable** | Achievable solo in 2-3 weeks with intense focus. Requires one new circuit or one significant contract change plus SDK work. Some integration risk. |
| 16-20 | **Doable** | Achievable solo in 1-2 weeks. Uses mostly existing primitives. One or two days of circuit/contract work, rest is SDK and API surface. Clear path to MVP. |
| 21-25 | **Easy ship** | Can ship in under a week. Purely SDK/API work on top of existing circuits and contracts. Demo-ready quickly. Low integration risk. |

## Tier 1 Thresholds

| Total Score | Action |
|-------------|--------|
| **75-100** | **Promote to Tier 2** immediately. High-priority opportunity. |
| **55-74** | **Promote to Tier 2** if at least 2 dimensions score >= 18. Otherwise defer. |
| **35-54** | **Defer.** Revisit in next research cycle. Log the signal for trend tracking. |
| **0-34** | **Kill.** Not worth further analysis. Archive the finding. |

## Usage Notes

- Each persona scores only the dimensions in their `focus` array.
- Final Tier 1 score is the **median** across all persona scores for each dimension (not the mean -- this prevents one enthusiastic persona from inflating scores).
- Ties at the promotion threshold are broken by FEASIBILITY (solo founder constraint is the hardest filter).
- All scores must include a 1-2 sentence justification. No bare numbers.

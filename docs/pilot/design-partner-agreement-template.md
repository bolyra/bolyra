# Design Partner Pilot Agreement — TEMPLATE

> **⚠️ ATTORNEY REVIEW REQUIRED BEFORE ANY SIGNATURE.** This is a working
> template drafted for speed, not legal advice. Have counsel review before
> sending to any counterparty. Do not represent it as attorney-drafted.

**Between:** ZKProva Inc. ("Bolyra") and ______________________ ("Design Partner")
**Effective date:** ____________  **Term:** 90 days from effective date.

## 1. Scope of work

Bolyra will integrate one (1) Bolyra enforcement point into one (1) Design
Partner workflow, agreed in writing during week 1 ("Pilot Workflow"). The
enforcement point is chosen jointly from: (a) gateway proxy, (b) embedded
gateway middleware, or (c) shield (stdio). Controls provided depend on the
chosen enforcement point: per-tool-call authorization policy, nonce replay
protection, and ES256K-signed receipts on every allow and deny decision in
all modes; credential binding against a registry supplied by Design Partner
in gateway proxy and middleware modes. Receipts are written to an audit log
retrievable by Design Partner.

Phases: integration (weeks 1-2), pilot workflow live (weeks 3-4),
hardening and expansion scoping (weeks 5-12).

## 2. Deliverables

1. Working integration of the chosen Bolyra enforcement point (gateway
   proxy, embedded middleware, or shield) in Design Partner's staging
   environment, and in production or a production-like environment for the
   Pilot Workflow.
2. Enforcement configuration: tool policy + credential registry for the
   Pilot Workflow.
3. Audit artifacts: signed receipt log + offline verification procedure
   Design Partner can run independently.
4. Weekly working session (up to 1 hour) and asynchronous integration
   support with a 2-business-day response target.
5. End-of-pilot summary: what was enforced, receipt/verification statistics,
   and a proposed production expansion plan.

## 3. Success criteria (agreed week 1)

- 100% of Pilot Workflow tool calls routed through the agreed enforcement
  point are policy-checked and receipted.
- Receipts verify independently of Bolyra infrastructure.
- [Design-Partner-specific criterion agreed in week 1.]

## 4. Design Partner responsibilities

- A technical point of contact with ≤2-business-day turnaround.
- Access to the staging environment and the Pilot Workflow needed for
  integration (no production credentials handed to Bolyra; enforcement
  runs in Design Partner's environment).
- Good-faith participation in weekly sessions and the end-of-pilot review.

## 5. Fees

US $25,000 fixed. 50% due on signature; 50% due at day 45. Net 15.
Fees credit toward the first-year license fee only (not services, usage
fees, taxes, or pass-through costs) if Design Partner converts to a paid
license within 90 days after the pilot ends.

## 6. Intellectual property

- Bolyra retains all right, title, and interest in the Bolyra software,
  protocol, specifications, and any improvements to them, including
  improvements informed by pilot feedback.
- Design Partner retains all right, title, and interest in its own
  platform, data, configurations, and credentials. Enforcement
  configuration written for the Pilot Workflow is assigned to Design
  Partner on final payment.
- Open-source components remain under Apache-2.0; nothing here restricts
  Design Partner's rights under that license.
- Feedback license: Design Partner grants Bolyra a perpetual,
  royalty-free license to use feedback and usage learnings to improve its
  products, excluding Design Partner Confidential Information.

## 7. Confidentiality

Mutual. Each party protects the other's non-public information with
reasonable care and uses it only for the pilot. Survives 2 years.
Receipts and audit logs generated from Design Partner traffic are Design
Partner Confidential Information.

## 8. Publicity

Neither party names the other publicly without written consent. Bolyra
may request a case study / logo use at pilot end; Design Partner may
decline.

## 9. Security & support assumptions

- Bolyra software runs inside Design Partner's environment; Bolyra
  receives no production secrets or end-user data.
- Support is business hours (ET), best effort, no SLA during pilot;
  production SLAs are a license-agreement matter.
- No warranty beyond good-faith professional effort; pilot software is
  provided "as is." Liability capped at fees paid. [Attorney: standard
  warranty/liability/indemnity language needed here.]

## 10. Termination

Either party may terminate for material breach on 10 business days'
written notice with a cure period. If Design Partner terminates without
cause before day 45, the day-45 payment is waived; fees already paid are
non-refundable. Sections 6-9 survive.

---
Signatures: ____________________ (ZKProva Inc.) ____________________ (Design Partner)

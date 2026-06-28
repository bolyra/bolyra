The construction is ready. The single gap closed this iteration:

**Theorem 3 (Adversarial-AS predicate proof impossibility)** added to Section 4, stated as: *"No AS-side filter can produce a predicate proof over inputs the AS does not observe at filter time."* 

The theorem proves that any assertion-based system (RFC 7662, BBS+, token exchange) must have *some* entity observe the full permission bitmask `b` to produce a verifiable assertion of `P(b, m) = true`. This is information-theoretic, not implementational — no future OAuth extension can fix it. Bolyra's ZK construction breaks this impossibility by replacing assertion-based trust with computation-integrity trust.

Changes made:
- **Section 4**: New Theorem 3 with formal statement (`F` cannot simultaneously achieve RS-verifiable predicate assertion AND operate without knowledge of `b`), proof sketch covering all baseline components (RFC 7662, jwt-introspection, BBS+, RFC 8693), two corollaries (suppression resistance, escalation resistance), and connection to Theorems 1+2
- **Section 8 Failure 1**: Rewritten to lead with Theorem 3 as the headline result, explicitly stating this is a structural impossibility of the assertion-based trust model
- **Section 8 summary table**: Added Theorem column linking each property to its formal backing

All other sections preserved. No new gadgets, no expanded claims. Could you grant write permission to save the file?

The file write needs permission. Here's a summary of what the construction addresses for each of the six judge gaps:

1. **"Strictly dominates" retracted** — Replaced with "Pareto-dominates on the privacy-sovereignty axis" with explicit latency (20-30x), trust distribution, and audit carve-outs stated in §1.

2. **AS-adversary elevated to first-class** — §1 includes a dedicated subsection arguing that multi-tenant AS sharing, cross-vendor handoff, and subpoena surface make the AS-adversary assumption the default topology in agent-economy MCP (not a regulated niche).

3. **Groth16 HVZK addressed** — §2.5 adds trust assumption A10 (RS-honest-verifier for Groth16) with justification that Groth16 verification is deterministic with no verifier-chosen challenges. PLONK leg uses simulation-extractable NIZK (no assumption needed).

4. **Intra-epoch linkability closed** — §2.2 implements per-session Pedersen re-randomization (~2,100 constraints) of `agentMerkleRoot` plus blinded `scopeCommitment`. Game 4 (SESSION-LINK) proves advantage ≤ negl(λ). No longer deferred.

5. **AS scope_id control bounded** — Trust assumption A7 added with three enforcement mechanisms (on-chain RS address, DNSSEC, CT-logged). Game 5 (NAMESPACE-FORGE) formalizes the attack and shows resilience even if A7 is violated.

6. **SRS subversion conditioned in theorems** — Every theorem invoking A4 states "conditional on SRS integrity" in the theorem statement itself. Game 6 honestly states soundness fails with advantage 1 under subversion and compares blast radius to OAuth.

Would you like to grant write permission so I can save the file?

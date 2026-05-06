The construction is ready. Here's what was refined to close the six judge-identified gaps:

**Gap 1 (H1–H5 overstatement):** All five hypotheses rewritten with `-narrowed` suffixes. Each now claims only the proven residual: H1=AS-blind binding (not mutual binding generally), H2=operator-credential binding (not runtime model identity), H3=unlinkable client_id (with SRS blast-radius tradeoff), H4=cross-epoch forward secrecy only (explicitly disclaims intra-epoch), H5=AS-blind delegation (explicitly concedes latency regression vs RFC 8693 and SPIRE/WIMSE).

**Gap 2 (MANIFEST-INTEGRITY):** Game 5 formalized with adversary controlling network position. Mandatory manifest signature verification (no longer optional). A9 added as trust assumption for manifest signing key bootstrap. Three bootstrap mechanisms specified (DNS-bound, CT-logged, on-chain anchor). TOFU resolved via pinning.

**Gap 3 (ERASE oracle):** Game 2 now includes a full Bellare-Yee style erasure oracle with `Session()`, `Reveal()`, and `Challenge()` oracles. Erasure trust (A8) explicitly separated from the Theorem 2 reduction. The construction states: "Theorem 2 proves that IF erasure works, THEN cross-epoch linkage breaks Poseidon PRF. Whether erasure works is operational."

**Gap 4 (Constraint counts + latency benchmarks):** §6 now includes AgentPolicyV2-Ratcheted at ~12,483 constraints (lighter than iter_001 due to removing longTermSecret from circuit). Full latency comparison table: Bolyra vs OAuth DPoP vs SPIRE/WIMSE across initial auth, per-hop delegation, and 3-hop chains. The 20-30× latency cost is explicitly acknowledged.

**Gap 5 (H4 precision):** H4 defined as "cross-epoch forward secrecy only." Intra-epoch linkability via constant `agentMerkleRoot` is explicitly called out. Per-session Pedersen re-randomization identified as the close (~2K constraints) but deferred.

**Gap 6 (Universal SRS blast radius):** Game 4 includes a dedicated "Blast radius under H3 portability" section analyzing the systemic failure mode. Graceful degradation, detection, and re-ceremony mitigations specified. Per-domain SRS isolation offered as fallback. Direct comparison: "OAuth distributes trust across N independent ASes; Bolyra concentrates in one SRS."

Would you like me to try the file write again with permissions granted?

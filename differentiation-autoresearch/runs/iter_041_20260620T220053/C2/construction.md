The construction is ready. Key refinement for this iteration:

**Gap closed: IND-UNL-RS and IND-UNL-(AS∧RS) games (§3 + §4)**

Three new formal objects added:

1. **Game 2 (IND-UNL-RS)** — RS-collusion adversary without AS control. Adversary sees pseudonyms and anchors at multiple colluding RSes. Both are unlinkable via POS-PRF since the adversary lacks AS enrollment secrets (`sbs`, `cc`, `permBitmask`). **Theorem 4.2** proves `Adv ≤ 2·Adv^PRF + Adv^ZK = negl(λ)`.

2. **Game 3a (IND-UNL-(AS∧RS)-auth)** — Joint AS+RS collusion, non-delegation case. AS knows `cc` and `permBitmask` but NOT `sbs`. Pseudonym remains unlinkable. **Theorem 4.3** proves `Adv ≤ Adv^PRF + Adv^ZK = negl(λ)`.

3. **Game 3b (IND-UNL-(AS∧RS)-deleg)** — Joint AS+RS collusion with active delegation. Honest acknowledgment: the delegation anchor `Poseidon3(scopeId, permBitmask, cc)` is deterministic from AS-known values, so a colluding AS+RS can identify agents via brute-force matching. **Proposition 4.4** proves `Adv = 1/2`. Mitigation: anchor visibility gating — anchors sealed until delegation is exercised.

4. **Corollary 4.6** — Summary table showing Bolyra beats baseline in Games 1 and 3a (gap `1/2 - negl(λ)`), matches in Game 2, and honestly ties in Game 3b.

Section 1 preserved verbatim. Section 7 extended with IND-UNL-RS and IND-UNL-(AS∧RS) deployment implications for both credit union and healthcare scenarios.

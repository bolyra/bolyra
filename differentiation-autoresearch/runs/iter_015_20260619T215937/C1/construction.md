The file write is awaiting your permission approval. The construction covers all 8 required sections:

1. **Claim**: 5-property selective scope proof (AS-blind, constant-size, adversarial-AS-resilient, runtime-adaptive, model-identity-bound)
2. **Construction**: Uses the existing `AgentPolicy` circuit unchanged — no new primitives. Private `permissionBitmask`, public `requiredScopeMask`, predicate enforced by `reqBits[i] * (1 - permBits[i]) === 0`
3. **Threat model**: Two formal games — SSF (forgery) and SP (privacy) — with adversary controlling the AS, network, and colluding RSes
4. **Security argument**: Reduces to KS-Groth16, CR-Poseidon, EUF-CMA-EdDSA via 3-case reduction sketch
5. **Primitive mapping**: All Bolyra-native (Poseidon, BabyJubjub EdDSA, Groth16/PLONK, depth-20 Merkle)
6. **Cost**: ~38,500 constraints, <0.8s rapidsnark proving, 128-byte proof
7. **Scenario**: Pacific Federal Credit Union with 3 agent types across 3 external RSes, NCUA/GENIUS Act compliance
8. **Why baseline fails**: 5 structural impossibility axes — attestation-based vs. proof-based category difference

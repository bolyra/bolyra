The write permission keeps getting denied. Could you please approve the file write permission so I can save `construction.md`? The file is ready — it contains the full IssuerBlindPredicate PLONK circuit construction for C4 with:

- **IND-ISS game** formally defined (adversary picks two issuers, challenger flips coin, adversary guesses which issuer signed)
- **IssuerBlindPredicate circuit** (~42K constraints): issuer key as private witness in a Merkle tree, EdDSA signature verification inside the circuit, 32-gate Boolean predicate evaluator over hidden attributes
- **Security reductions**: IND-ISS from PLONK zero-knowledge (A4), UNF-CRED from knowledge soundness + Poseidon CR + DLP on Baby Jubjub
- **Deployment scenario**: CO-OP Shared Branch network — Mountain America member proves NCUA membership at Navy Federal without revealing home CU
- **Why BBS+ cannot match**: 4 structural impossibilities (issuer key in verification equation, no constant-size predicates, no IND-ISS reduction, verifier-side key enumeration)

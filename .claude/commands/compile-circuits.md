---
description: Compile circuits and refresh build artifacts
---

Run `npm run compile:circuits` (which calls `circuits/scripts/compile.js`).

After completion, verify `circuits/build/` contains, for each circuit:
- `<name>.r1cs`
- `<name>.sym`
- `<name>_js/` (witness generator)
- `<name>_vkey.json` (Groth16 verifying key)
- For Agent + Delegation: `<name>_plonk.zkey` and `<name>_groth16_vkey.json` (dual builds)

Report:
1. Constraint counts per circuit (delta vs prior compile if known).
2. Any artifacts missing.
3. Whether Solidity verifier contracts in `contracts/contracts/` need regenerating (if any vkey changed).

Do not regenerate the trusted setup unless explicitly asked — `pot16.ptau` is reused.

---
description: Run circuit tests (fast or full proof)
argument-hint: [fast|slow]
---

Run Bolyra circuit tests. Default to `fast` if no arg.

- **fast** (witness-only, mocks proofs): `npm run test:circuits:fast`
- **slow** (real Groth16/PLONK proving, ~2min): `npm run test:circuits:slow`

After the run, report:
1. Test pass/fail counts per circuit (HumanUniqueness, AgentPolicy, Delegation).
2. Any constraint count regressions if visible in output.
3. If failures occurred, group them: assertion failures vs witness errors vs missing build artifacts.

If a build artifact is missing (`circuits/build/*.zkey`), suggest running `npm run compile:circuits` first.

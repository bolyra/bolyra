# Teaching Session: 2026-06-21 Full Build Session

## The Bar
Every item below must be checked off with YOUR demonstration of understanding (restate, answer a quiz, or explain why). Checked = you proved it, not I explained it.

---

## 1. The Problem Space

- [x] **1a.** Why CrewAI needed its own adapter (vs reusing LangChain's)
- [x] **1b.** Why conformance test vectors needed a v3 upgrade
- [x] **1c.** Why a proof envelope wire format is needed at all
- [x] **1d.** What the autoresearch loops are and why there are 5 separate ones

## 2. CrewAI Adapter Design Decisions

- [x] **2a.** Why CrewAI tools return strings (not dicts) and what that means for the design
- [x] **2b.** Why permissions use comma-separated strings instead of JSON arrays
- [x] **2c.** The SD-JWT receipt vaulting pattern and WHY raw receipts can't appear in tool output
- [x] **2d.** Why BolyraGuard needed guard_tools() (pre-execution) in addition to step_callback (post-execution)
- [x] **2e.** The operator_key=0 security bug and why it matters

## 3. Review Process

- [x] **3a.** How the /review specialist dispatch works (which specialists, why parallel)
- [x] **3b.** Fix-First heuristic: what gets auto-fixed vs what gets asked
- [x] **3c.** Why the adversarial review found things the structured review missed

## 4. Conformance Vectors v3

- [x] **4a.** What JSON Schema buys us that plain JSON files don't
- [x] **4b.** Why session token vectors are marked "experimental"
- [x] **4c.** What the normative prose section adds that the schema can't express

## 5. Proof Envelope

- [x] **5a.** Why field elements use decimal strings (not hex, not bare numbers)
- [x] **5b.** The BigInt DoS guard (78-char limit) and why it exists
- [x] **5c.** Why v1 is groth16-only even though Bolyra supports PLONK
- [x] **5d.** Why the media type uses `vnd.` prefix

## 6. Broader Context

- [x] **6a.** How the three things shipped today (adapter, vectors, envelope) compound on each other
- [x] **6b.** What the discovery autoresearch found and why it matters for Bolyra's strategy
- [x] **6c.** The gap between what's built (12 packages) and what's missing (0 users)

---

Progress: 16/16 items mastered ✓ COMPLETE

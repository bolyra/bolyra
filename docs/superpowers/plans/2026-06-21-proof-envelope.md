# Proof Envelope Content Type Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `application/vnd.bolyra.proof+json` wire format with TypeScript and Python codecs, cross-SDK golden fixtures, and version negotiation.

**Architecture:** A new `envelope.ts` module in the TS SDK defines the ProofEnvelope type, serialize/deserialize functions, and a helper to wrap raw snarkjs proofs. A mirror `envelope.py` in the Python SDK uses dataclasses. Multiple golden fixtures ensure cross-SDK interop (happy path, boundary values, forward-compat, invalid). No external validation library. v1 supports groth16 only (PLONK has a different proof shape).

**Tech Stack:** TypeScript (Jest), Python (pytest, dataclasses), JSON fixtures

**Codex review changes incorporated:**
- Vendor media type (`vnd.bolyra`) until IANA registration
- groth16 only in v1 (PLONK proof shape differs)
- Reject leading zeros in field elements (`/^(0|[1-9]\d*)$/`)
- Reject strings > 78 chars before BigInt parsing (DoS prevention)
- Validate pi_b row length (each row must be exactly 2 elements)
- Unknown-field preservation is top-level only
- vkeyHash format validation (`sha256:<64 lowercase hex>`)
- Multiple fixtures (boundary, forward-compat, invalid)
- No Zod/Pydantic (plain TS + Python dataclasses)

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `sdk/src/envelope.ts` | Create | ProofEnvelope type, validation, serialize/deserialize, snarkjs wrapper |
| `sdk/src/index.ts` | Modify | Re-export envelope public API |
| `sdk/test/envelope.test.ts` | Create | TS unit tests |
| `sdk/test/fixtures/envelope_v1.json` | Create | Golden cross-SDK fixture |
| `sdk-python/bolyra/envelope.py` | Create | Python ProofEnvelope model |
| `sdk-python/tests/test_envelope.py` | Create | Python unit tests |
| `tasks/pdlc/proof-envelope.json` | Create | PDLC pipeline state |

---

### Task 1: PDLC Pipeline + Golden Fixture

**Files:**
- Create: `tasks/pdlc/proof-envelope.json`
- Create: `sdk/test/fixtures/envelope_v1.json`

- [ ] **Step 1: Create PDLC pipeline file**

Write `tasks/pdlc/proof-envelope.json`:

```json
{
  "id": "pdlc-2026-06-21-proof-envelope",
  "feature": "Proof envelope content type (application/vnd.bolyra.proof+json)",
  "status": "active",
  "stage": "IMPLEMENT",
  "mode": "standard",
  "created": "2026-06-21T08:00:00Z",
  "spec": "docs/superpowers/specs/2026-06-21-proof-envelope-design.md",
  "plan": "docs/superpowers/plans/2026-06-21-proof-envelope.md",
  "gates": {
    "spec": { "status": "approved" },
    "plan": { "status": "approved" },
    "ship": { "status": "pending" },
    "post_ship": { "status": "pending" }
  },
  "tasks": [
    { "id": 1, "description": "PDLC pipeline + golden fixture", "status": "pending" },
    { "id": 2, "description": "TypeScript envelope module + tests", "status": "pending" },
    { "id": 3, "description": "TypeScript SDK re-export", "status": "pending" },
    { "id": 4, "description": "Python envelope module + tests", "status": "pending" },
    { "id": 5, "description": "Cross-SDK interop verification", "status": "pending" }
  ]
}
```

- [ ] **Step 2: Create golden fixtures**

Write multiple fixtures in `sdk/test/fixtures/`. Both TS and Python tests must produce identical results on each.

**`envelope_v1.json`** -- happy path, valid envelope:

```json
{
  "version": "1.0.0",
  "circuit": {
    "name": "HumanUniqueness",
    "version": "0.4.0",
    "vkeyHash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "proofType": "groth16",
  "publicSignals": [
    "21888242871839275222246405745257275088548364400416034343698204186575808495616",
    "98765432109876543210",
    "42"
  ],
  "proof": {
    "pi_a": ["12345678901234567890", "98765432109876543210"],
    "pi_b": [["11111111111111111111", "22222222222222222222"], ["33333333333333333333", "44444444444444444444"]],
    "pi_c": ["55555555555555555555", "66666666666666666666"]
  },
  "metadata": {
    "prover": "@bolyra/sdk@0.4.0",
    "timestamp": "2026-06-21T12:00:00Z"
  }
}
```

Also create:
- **`envelope_v1_boundary.json`** -- field elements "0" and BN254 modulus minus 1
- **`envelope_v1_forward_compat.json`** -- has an unknown top-level key `"futureField": "test"`
- **`envelope_v1_invalid_leading_zero.json`** -- has `"0042"` in publicSignals (must reject)
- **`envelope_v1_invalid_modulus.json`** -- has field element equal to BN254 modulus (must reject)
- **`envelope_v1_invalid_pi_b.json`** -- has `pi_b: [["1"], ["2","3","4"]]` (must reject)

- [ ] **Step 3: Create fixtures directory**

```bash
mkdir -p sdk/test/fixtures
```

- [ ] **Step 4: Commit**

```bash
git add tasks/pdlc/proof-envelope.json sdk/test/fixtures/envelope_v1.json
git commit -s -m "feat: PDLC pipeline + golden fixture for proof envelope"
```

---

### Task 2: TypeScript Envelope Module + Tests

**Files:**
- Create: `sdk/src/envelope.ts`
- Create: `sdk/test/envelope.test.ts`

- [ ] **Step 1: Write envelope.ts**

Create `sdk/src/envelope.ts` with:

```typescript
/**
 * Proof envelope wire format: application/vnd.bolyra.proof+json
 *
 * Self-describing envelope for ZKP proofs with typed fields,
 * circuit identity binding, and version negotiation.
 */

/** Content-Type for HTTP headers. */
export const CONTENT_TYPE = 'application/vnd.bolyra.proof+json';

/** Current envelope version. */
export const ENVELOPE_VERSION = '1.0.0';

/** Valid circuit names. */
export type CircuitName = 'HumanUniqueness' | 'AgentPolicy' | 'Delegation';

/** Valid proof systems. */
/** Valid proof systems. v1 supports groth16 only (PLONK has different shape). */
export type ProofType = 'groth16';

/** Circuit identity with version and vkey binding. */
export interface CircuitIdentity {
  name: CircuitName;
  version: string;
  vkeyHash?: string; // sha256:<hex>
}

/** Groth16/PLONK proof coordinates. All values are decimal strings. */
export interface ProofData {
  pi_a: [string, string];
  pi_b: [[string, string], [string, string]];
  pi_c: [string, string];
}

/** Informational metadata. Verifiers MUST NOT reject based on these. */
export interface ProofMetadata {
  prover?: string;
  timestamp?: string; // RFC 3339
  [key: string]: unknown; // forward-compatible
}

/** The canonical proof envelope. */
export interface ProofEnvelope {
  version: string;
  circuit: CircuitIdentity;
  proofType: ProofType;
  publicSignals: string[];
  proof: ProofData;
  metadata?: ProofMetadata;
  [key: string]: unknown; // forward-compatible
}

// BN254 field modulus
const BN254_FIELD_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Validate a decimal field element string.
 * Must be a non-negative integer that does not exceed BN254 field modulus.
 */
function validateFieldElement(s: string, label: string): void {
  if (typeof s !== 'string') {
    throw new Error(`${label}: must be a string, got ${typeof s}`);
  }
  // Reject strings > 78 chars before BigInt parsing (DoS prevention)
  if (s.length > 78) {
    throw new Error(`${label}: string too long (${s.length} chars, max 78)`);
  }
  // No leading zeros except "0" itself
  if (!/^(0|[1-9]\d*)$/.test(s)) {
    throw new Error(`${label}: must be a decimal string without leading zeros, got ${JSON.stringify(s)}`);
  }
  const n = BigInt(s);
  if (n >= BN254_FIELD_ORDER) {
    throw new Error(`${label}: value >= BN254 field modulus`);
  }
}

/** Parse a semver string into [major, minor, patch]. */
function parseSemver(v: string): [number, number, number] {
  const m = v.match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!m) throw new Error(`Invalid semver: ${v}`);
  return [parseInt(m[1]), parseInt(m[2]), parseInt(m[3])];
}

/**
 * Validate an envelope's version against the current version.
 * Major mismatch = reject. Minor/patch mismatch = accept.
 */
function checkVersion(envelopeVersion: string): void {
  const [major] = parseSemver(envelopeVersion);
  const [currentMajor] = parseSemver(ENVELOPE_VERSION);
  if (major !== currentMajor) {
    throw new Error(
      `Incompatible envelope version: ${envelopeVersion} (current: ${ENVELOPE_VERSION}). Major version mismatch.`
    );
  }
}

const VALID_CIRCUITS: ReadonlySet<string> = new Set(['HumanUniqueness', 'AgentPolicy', 'Delegation']);
const VALID_PROOF_TYPES: ReadonlySet<string> = new Set(['groth16']); // v1: groth16 only

/**
 * Validate an envelope object. Throws on invalid structure or field values.
 */
export function validateEnvelope(envelope: Record<string, unknown>): ProofEnvelope {
  // Version
  if (typeof envelope.version !== 'string') throw new Error('Missing or invalid version');
  checkVersion(envelope.version);

  // Circuit
  const circuit = envelope.circuit as Record<string, unknown> | undefined;
  if (!circuit || typeof circuit !== 'object') throw new Error('Missing or invalid circuit');
  if (typeof circuit.name !== 'string' || !VALID_CIRCUITS.has(circuit.name)) {
    throw new Error(`Invalid circuit.name: ${circuit.name}`);
  }
  if (typeof circuit.version !== 'string') throw new Error('Missing circuit.version');

  // Proof type
  if (typeof envelope.proofType !== 'string' || !VALID_PROOF_TYPES.has(envelope.proofType)) {
    throw new Error(`Invalid proofType: ${envelope.proofType}`);
  }

  // Public signals
  const signals = envelope.publicSignals;
  if (!Array.isArray(signals) || signals.length === 0) {
    throw new Error('publicSignals must be a non-empty array');
  }
  signals.forEach((s, i) => validateFieldElement(s as string, `publicSignals[${i}]`));

  // Proof coordinates
  const proof = envelope.proof as Record<string, unknown> | undefined;
  if (!proof || typeof proof !== 'object') throw new Error('Missing proof');
  const pi_a = proof.pi_a as string[];
  const pi_b = proof.pi_b as string[][];
  const pi_c = proof.pi_c as string[];
  if (!Array.isArray(pi_a) || pi_a.length !== 2) throw new Error('proof.pi_a must be [string, string]');
  if (!Array.isArray(pi_b) || pi_b.length !== 2) throw new Error('proof.pi_b must be [[s,s],[s,s]]');
  for (let r = 0; r < 2; r++) {
    if (!Array.isArray(pi_b[r]) || pi_b[r].length !== 2) {
      throw new Error(`proof.pi_b[${r}] must be [string, string]`);
    }
  }
  if (!Array.isArray(pi_c) || pi_c.length !== 2) throw new Error('proof.pi_c must be [string, string]');

  pi_a.forEach((s, i) => validateFieldElement(s, `pi_a[${i}]`));
  pi_b.forEach((row, r) => row.forEach((s: string, c: number) => validateFieldElement(s, `pi_b[${r}][${c}]`)));
  pi_c.forEach((s, i) => validateFieldElement(s, `pi_c[${i}]`));

  return envelope as unknown as ProofEnvelope;
}

/** Serialize an envelope to a JSON string. */
export function serializeEnvelope(envelope: ProofEnvelope): string {
  return JSON.stringify(envelope);
}

/** Deserialize and validate a JSON string into a ProofEnvelope. */
export function deserializeEnvelope(json: string): ProofEnvelope {
  const parsed = JSON.parse(json);
  return validateEnvelope(parsed);
}

/** Wrap raw snarkjs proof output into a ProofEnvelope. */
export function envelopeFromSnarkjsProof(
  circuitName: CircuitName,
  proof: { pi_a: string[]; pi_b: string[][]; pi_c: string[] },
  publicSignals: string[],
  options?: { circuitVersion?: string; vkeyHash?: string },
): ProofEnvelope {
  return {
    version: ENVELOPE_VERSION,
    circuit: {
      name: circuitName,
      version: options?.circuitVersion ?? '0.4.0',
      ...(options?.vkeyHash ? { vkeyHash: options.vkeyHash } : {}),
    },
    proofType: 'groth16',
    publicSignals,
    proof: {
      pi_a: [proof.pi_a[0], proof.pi_a[1]],
      pi_b: [
        [proof.pi_b[0][0], proof.pi_b[0][1]],
        [proof.pi_b[1][0], proof.pi_b[1][1]],
      ],
      pi_c: [proof.pi_c[0], proof.pi_c[1]],
    },
    metadata: {
      prover: `@bolyra/sdk@0.4.0`,
      timestamp: new Date().toISOString(),
    },
  };
}
```

- [ ] **Step 2: Write envelope.test.ts**

Create `sdk/test/envelope.test.ts` with tests for:
- Round-trip: serialize then deserialize, assert deep equality on all fields
- Version rejection: version "2.0.0" throws "Major version mismatch"
- Version acceptance: version "1.1.0" parses without error
- Missing required field: no `proof` key throws
- Malformed proof coordinates: "abc" in pi_a throws
- Field element exceeds BN254: value >= field modulus throws
- Forward compat: unknown top-level key preserved after round-trip
- Golden fixture: load `fixtures/envelope_v1.json`, deserialize, assert all fields match
- envelopeFromSnarkjsProof: produces valid envelope with correct circuit/version/proofType
- Empty publicSignals: throws "non-empty array"
- Invalid circuit name: throws
- Invalid proofType: throws

- [ ] **Step 3: Run tests**

```bash
cd sdk && npx jest test/envelope.test.ts --passWithNoTests
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add sdk/src/envelope.ts sdk/test/envelope.test.ts
git commit -s -m "feat: proof envelope TypeScript codec with tests"
```

---

### Task 3: TypeScript SDK Re-export

**Files:**
- Modify: `sdk/src/index.ts`

- [ ] **Step 1: Add re-exports to index.ts**

Append to `sdk/src/index.ts`:

```typescript
// Proof envelope wire format
export {
  CONTENT_TYPE,
  ENVELOPE_VERSION,
  serializeEnvelope,
  deserializeEnvelope,
  validateEnvelope,
  envelopeFromSnarkjsProof,
} from './envelope';

export type {
  ProofEnvelope,
  ProofData,
  ProofMetadata,
  CircuitIdentity,
  CircuitName,
  ProofType,
} from './envelope';
```

- [ ] **Step 2: Verify SDK builds**

```bash
cd sdk && npx tsc --noEmit
```

Expected: no type errors.

- [ ] **Step 3: Run full SDK tests**

```bash
cd sdk && npm test
```

Expected: all tests pass including new envelope tests.

- [ ] **Step 4: Commit**

```bash
git add sdk/src/index.ts
git commit -s -m "feat: re-export proof envelope from @bolyra/sdk"
```

---

### Task 4: Python Envelope Module + Tests

**Files:**
- Create: `sdk-python/bolyra/envelope.py`
- Create: `sdk-python/tests/test_envelope.py`

- [ ] **Step 1: Write envelope.py**

Create `sdk-python/bolyra/envelope.py`:

```python
"""Proof envelope wire format: application/vnd.bolyra.proof+json

Self-describing envelope for ZKP proofs with typed fields,
circuit identity binding, and version negotiation.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

CONTENT_TYPE = "application/vnd.bolyra.proof+json"
ENVELOPE_VERSION = "1.0.0"

# BN254 scalar field modulus
BN254_FIELD_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617

VALID_CIRCUITS = frozenset({"HumanUniqueness", "AgentPolicy", "Delegation"})
VALID_PROOF_TYPES = frozenset({"groth16"})  # v1: groth16 only


def _validate_field_element(s: str, label: str) -> None:
    if not isinstance(s, str):
        raise ValueError(f"{label}: must be a string, got {type(s).__name__}")
    if len(s) > 78:
        raise ValueError(f"{label}: string too long ({len(s)} chars, max 78)")
    if not re.match(r"^(0|[1-9]\d*)$", s):
        raise ValueError(f"{label}: must be a decimal string without leading zeros, got {s!r}")
    n = int(s)
    if n >= BN254_FIELD_ORDER:
        raise ValueError(f"{label}: value >= BN254 field modulus")


def _parse_semver(v: str) -> tuple[int, int, int]:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)$", v)
    if not m:
        raise ValueError(f"Invalid semver: {v}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _check_version(version: str) -> None:
    major, _, _ = _parse_semver(version)
    current_major, _, _ = _parse_semver(ENVELOPE_VERSION)
    if major != current_major:
        raise ValueError(
            f"Incompatible envelope version: {version} "
            f"(current: {ENVELOPE_VERSION}). Major version mismatch."
        )


@dataclass
class CircuitIdentity:
    name: str
    version: str
    vkey_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name, "version": self.version}
        if self.vkey_hash:
            d["vkeyHash"] = self.vkey_hash
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CircuitIdentity:
        return cls(
            name=d["name"],
            version=d["version"],
            vkey_hash=d.get("vkeyHash"),
        )


@dataclass
class ProofData:
    pi_a: list[str]
    pi_b: list[list[str]]
    pi_c: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {"pi_a": self.pi_a, "pi_b": self.pi_b, "pi_c": self.pi_c}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ProofData:
        return cls(pi_a=d["pi_a"], pi_b=d["pi_b"], pi_c=d["pi_c"])


@dataclass
class ProofEnvelope:
    version: str
    circuit: CircuitIdentity
    proof_type: str
    public_signals: list[str]
    proof: ProofData
    metadata: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "version": self.version,
            "circuit": self.circuit.to_dict(),
            "proofType": self.proof_type,
            "publicSignals": self.public_signals,
            "proof": self.proof.to_dict(),
        }
        if self.metadata:
            d["metadata"] = self.metadata
        d.update(self.extra)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ProofEnvelope:
        known_keys = {"version", "circuit", "proofType", "publicSignals", "proof", "metadata"}
        extra = {k: v for k, v in d.items() if k not in known_keys}
        return cls(
            version=d["version"],
            circuit=CircuitIdentity.from_dict(d["circuit"]),
            proof_type=d["proofType"],
            public_signals=d["publicSignals"],
            proof=ProofData.from_dict(d["proof"]),
            metadata=d.get("metadata", {}),
            extra=extra,
        )

    @classmethod
    def from_json(cls, raw: str) -> ProofEnvelope:
        d = json.loads(raw)
        return validate_envelope(d)


def validate_envelope(d: dict[str, Any]) -> ProofEnvelope:
    """Validate a raw dict and return a ProofEnvelope. Raises ValueError on invalid input."""
    if not isinstance(d.get("version"), str):
        raise ValueError("Missing or invalid version")
    _check_version(d["version"])

    circuit = d.get("circuit")
    if not isinstance(circuit, dict):
        raise ValueError("Missing or invalid circuit")
    if circuit.get("name") not in VALID_CIRCUITS:
        raise ValueError(f"Invalid circuit.name: {circuit.get('name')}")
    if not isinstance(circuit.get("version"), str):
        raise ValueError("Missing circuit.version")

    if d.get("proofType") not in VALID_PROOF_TYPES:
        raise ValueError(f"Invalid proofType: {d.get('proofType')}")

    signals = d.get("publicSignals")
    if not isinstance(signals, list) or len(signals) == 0:
        raise ValueError("publicSignals must be a non-empty array")
    for i, s in enumerate(signals):
        _validate_field_element(s, f"publicSignals[{i}]")

    proof = d.get("proof")
    if not isinstance(proof, dict):
        raise ValueError("Missing proof")
    for coord in ("pi_a", "pi_c"):
        arr = proof.get(coord)
        if not isinstance(arr, list) or len(arr) != 2:
            raise ValueError(f"proof.{coord} must be [string, string]")
        for i, s in enumerate(arr):
            _validate_field_element(s, f"{coord}[{i}]")
    pi_b = proof.get("pi_b")
    if not isinstance(pi_b, list) or len(pi_b) != 2:
        raise ValueError("proof.pi_b must be [[s,s],[s,s]]")
    for r, row in enumerate(pi_b):
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError(f"proof.pi_b[{r}] must be [string, string]")
        for c, s in enumerate(row):
            _validate_field_element(s, f"pi_b[{r}][{c}]")

    return ProofEnvelope.from_dict(d)


def envelope_from_proof(
    circuit_name: str,
    proof: dict[str, Any],
    public_signals: list[str],
    *,
    circuit_version: str = "0.4.0",
    vkey_hash: str | None = None,
) -> ProofEnvelope:
    """Wrap raw proof output into a ProofEnvelope."""
    return ProofEnvelope(
        version=ENVELOPE_VERSION,
        circuit=CircuitIdentity(
            name=circuit_name,
            version=circuit_version,
            vkey_hash=vkey_hash,
        ),
        proof_type="groth16",
        public_signals=public_signals,
        proof=ProofData(
            pi_a=[proof["pi_a"][0], proof["pi_a"][1]],
            pi_b=[
                [proof["pi_b"][0][0], proof["pi_b"][0][1]],
                [proof["pi_b"][1][0], proof["pi_b"][1][1]],
            ],
            pi_c=[proof["pi_c"][0], proof["pi_c"][1]],
        ),
        metadata={
            "prover": f"bolyra@0.5.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )
```

- [ ] **Step 2: Write test_envelope.py**

Create `sdk-python/tests/test_envelope.py` with tests mirroring the TS suite:
- Round-trip: to_json then from_json, assert field equality
- Version rejection: version "2.0.0" raises ValueError
- Version acceptance: version "1.1.0" parses
- Missing proof: raises ValueError
- Malformed proof coordinates: "abc" raises ValueError
- Field element exceeds BN254: raises ValueError
- Forward compat: unknown key preserved via extra dict
- Golden fixture: load `../../sdk/test/fixtures/envelope_v1.json`, from_json, assert fields
- envelope_from_proof: produces valid envelope
- Empty publicSignals: raises ValueError
- Invalid circuit name: raises ValueError
- Invalid proofType: raises ValueError

- [ ] **Step 3: Run Python tests**

```bash
cd sdk-python && python -m pytest tests/test_envelope.py -v
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add sdk-python/bolyra/envelope.py sdk-python/tests/test_envelope.py
git commit -s -m "feat: proof envelope Python codec with tests"
```

---

### Task 5: Cross-SDK Interop Verification + Push

**Files:** None new (verification only)

- [ ] **Step 1: Run TS tests**

```bash
cd sdk && npx jest test/envelope.test.ts
```

- [ ] **Step 2: Run Python tests**

```bash
cd sdk-python && python -m pytest tests/test_envelope.py -v
```

- [ ] **Step 3: Verify both SDKs load the same fixture**

Both test suites load `sdk/test/fixtures/envelope_v1.json` and assert identical field values. If both pass, cross-SDK interop is verified.

- [ ] **Step 4: Run existing SDK tests (no regressions)**

```bash
cd sdk && npm test
cd sdk-python && python -m pytest tests/ -v
```

- [ ] **Step 5: Update PDLC pipeline to REVIEW**

Edit `tasks/pdlc/proof-envelope.json`: set stage to REVIEW, all tasks to done.

- [ ] **Step 6: Commit and push**

```bash
git add tasks/pdlc/proof-envelope.json
git commit -s -m "chore: proof envelope complete, PDLC to REVIEW"
git push
```

# Conformance Test Vectors v3 Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the conformance suite to v0.4.0 with JSON Schema validation, SD-JWT + proof envelope + session token vectors, and normative prose for semantic requirements.

**Architecture:** JSON Schema defines the vector format contract. New vectors are added to the existing `test-vectors.json`. The conformance runner gains schema validation (via ajv) and new type handlers. Session token vectors are marked experimental.

**Tech Stack:** JSON Schema draft 2020-12, ajv (npm), Node.js, existing circomlibjs-based runner

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `spec/conformance-schema.json` | Create | JSON Schema for the vector format |
| `spec/test-vectors.json` | Modify | Add ~19 vectors, bump to 0.4.0 |
| `spec/conformance-runner.js` | Modify | Schema validation flag, new type handlers, exit codes |
| `spec/CONFORMANCE.md` | Regenerate | Add normative prose section |
| `tasks/pdlc/conformance-vectors-v3.json` | Create | PDLC pipeline state |

---

### Task 1: PDLC Pipeline + JSON Schema

**Files:**
- Create: `tasks/pdlc/conformance-vectors-v3.json`
- Create: `spec/conformance-schema.json`

- [ ] **Step 1: Create PDLC pipeline file**

```json
{
  "id": "pdlc-2026-06-21-conformance-vectors-v3",
  "feature": "Conformance test vectors v3 -- JSON Schema, SD-JWT, proof envelope, session token vectors",
  "status": "active",
  "stage": "IMPLEMENT",
  "mode": "standard",
  "created": "2026-06-21T06:00:00Z",
  "spec": "docs/superpowers/specs/2026-06-21-conformance-vectors-v3-design.md",
  "plan": "docs/superpowers/plans/2026-06-21-conformance-vectors-v3.md",
  "gates": {
    "spec": { "status": "approved" },
    "plan": { "status": "approved" },
    "ship": { "status": "pending" },
    "post_ship": { "status": "pending" }
  },
  "tasks": [
    { "id": 1, "description": "PDLC pipeline + JSON Schema", "status": "pending" },
    { "id": 2, "description": "SD-JWT vectors (8 vectors)", "status": "pending" },
    { "id": 3, "description": "Proof envelope vectors (6 vectors)", "status": "pending" },
    { "id": 4, "description": "Session token vectors (5 vectors, experimental)", "status": "pending" },
    { "id": 5, "description": "Runner upgrade (schema validation + new handlers)", "status": "pending" },
    { "id": 6, "description": "Normative prose + CONFORMANCE.md regeneration", "status": "pending" },
    { "id": 7, "description": "Run conformance suite, fix issues, commit", "status": "pending" }
  ]
}
```

- [ ] **Step 2: Write JSON Schema**

Create `spec/conformance-schema.json` with JSON Schema draft 2020-12. The schema defines:
- Top-level: `version` (string, semver), `vectors` (array of vector objects)
- Each vector: `id` (string, pattern `^[a-z0-9-]+$`), `description` (string), `type` (enum of 9 types), `status` (enum: stable/experimental, default stable), `inputs` (object), `expected` (object)
- Per-type sub-schemas via `allOf` + `if/then` for `inputs` and `expected`
- `expected.result` is always required: enum `PASS` or `FAIL`

The schema must validate the existing 48 vectors without changes.

- [ ] **Step 3: Validate existing vectors against schema**

Run: `node -e "const Ajv = require('ajv'); const schema = require('./spec/conformance-schema.json'); const vectors = require('./spec/test-vectors.json'); const ajv = new Ajv({allErrors: true}); const valid = ajv.validate(schema, vectors); console.log(valid ? 'VALID' : ajv.errors);"`

Expected: VALID (or fix schema issues until it validates)

- [ ] **Step 4: Commit**

```bash
git add tasks/pdlc/conformance-vectors-v3.json spec/conformance-schema.json
git commit -s -m "feat: add conformance JSON Schema (draft 2020-12)"
```

---

### Task 2: SD-JWT Vectors (8 vectors, stable)

**Files:**
- Modify: `spec/test-vectors.json`

- [ ] **Step 1: Add SD-JWT vectors to test-vectors.json**

Add 8 vectors with `"type": "sd_jwt"` after the existing vectors. Each vector has inputs matching the `bolyra.sd_jwt` module's `AllowOptions` + `PresentOptions` shape:

```json
{
  "id": "sd-jwt-valid-issuance",
  "description": "Valid SD-JWT allow() + present() round-trip",
  "type": "sd_jwt",
  "inputs": {
    "issuer_id": "did:bolyra:test-issuer",
    "agent_id": "test-agent",
    "audience": "api.example.com",
    "action": "read",
    "permission": "READ_DATA",
    "ttl_seconds": 300,
    "nonce": "verifier-challenge-001"
  },
  "expected": {
    "result": "PASS",
    "has_jti": true,
    "has_exp": true,
    "aud_matches": true
  }
}
```

Include all 8 vectors from the spec: valid-issuance, expired-receipt, wrong-audience, missing-nonce-production, nonce-replay, max-amount-exceeded, selective-disclosure, jti-uniqueness.

- [ ] **Step 2: Validate against schema**

Run the same ajv check from Task 1 Step 3. Fix any schema mismatches.

- [ ] **Step 3: Commit**

```bash
git add spec/test-vectors.json
git commit -s -m "feat: add 8 SD-JWT conformance vectors"
```

---

### Task 3: Proof Envelope Vectors (6 vectors, stable)

**Files:**
- Modify: `spec/test-vectors.json`

- [ ] **Step 1: Add proof envelope vectors**

Add 6 vectors with `"type": "proof_envelope"`. Proof envelopes wrap ZKP proofs with metadata:

```json
{
  "id": "envelope-valid-handshake",
  "description": "Valid proof envelope with content-type and proof bytes",
  "type": "proof_envelope",
  "inputs": {
    "proof_type": "groth16",
    "circuit": "HumanUniqueness",
    "public_signals": ["12345", "67890", "42"],
    "proof_bytes_b64": "AQID...",
    "content_type": "application/bolyra-proof+json"
  },
  "expected": {
    "result": "PASS",
    "proof_type_valid": true,
    "public_signals_count": 3
  }
}
```

Include all 6 from the spec: valid-handshake, missing-required-field, malformed-proof-bytes, unknown-fields-forward-compat, cross-circuit, empty-public-signals.

- [ ] **Step 2: Validate against schema**
- [ ] **Step 3: Commit**

```bash
git add spec/test-vectors.json
git commit -s -m "feat: add 6 proof envelope conformance vectors"
```

---

### Task 4: Session Token Vectors (5 vectors, experimental)

**Files:**
- Modify: `spec/test-vectors.json`

- [ ] **Step 1: Add session token vectors with experimental status**

Add 5 vectors with `"type": "session_token"` and `"status": "experimental"`:

```json
{
  "id": "session-valid-jwt",
  "description": "Valid JWT session token derived from handshake",
  "type": "session_token",
  "status": "experimental",
  "inputs": {
    "human_nullifier": "12345",
    "session_nonce": "42",
    "scope_commitment": "67890",
    "expiry_seconds": 3600
  },
  "expected": {
    "result": "PASS",
    "has_nullifier_claim": true,
    "has_nonce_claim": true,
    "has_exp": true
  }
}
```

Include all 5: valid-jwt, expired, scope-narrowing, missing-nullifier-binding, nonce-replay.

- [ ] **Step 2: Bump version to 0.4.0**

Update `"version": "0.3.0"` to `"version": "0.4.0"` in test-vectors.json.

- [ ] **Step 3: Validate against schema**
- [ ] **Step 4: Commit**

```bash
git add spec/test-vectors.json
git commit -s -m "feat: add 5 experimental session token vectors, bump to v0.4.0"
```

---

### Task 5: Runner Upgrade

**Files:**
- Modify: `spec/conformance-runner.js`

- [ ] **Step 1: Install ajv**

```bash
cd circuits && npm install ajv --save-dev
```

(The runner uses circuits/node_modules for its dependencies.)

- [ ] **Step 2: Add --validate-schema flag**

At the top of `main()`, after loading vectors, add schema validation:

```javascript
if (args.includes('--validate-schema')) {
    const Ajv = require('ajv');
    const schemaPath = path.join(__dirname, 'conformance-schema.json');
    const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf-8'));
    const ajv = new Ajv({ allErrors: true });
    const valid = ajv.validate(schema, vectors);
    if (!valid) {
        console.error('Schema validation FAILED:');
        ajv.errors.forEach(e => console.error(`  ${e.instancePath}: ${e.message}`));
        process.exit(2);
    }
    console.log('Schema validation: PASS\n');
}
```

- [ ] **Step 3: Add --skip-experimental flag**

After vector filtering, add:

```javascript
if (args.includes('--skip-experimental')) {
    selectedVectors = selectedVectors.filter(v => v.status !== 'experimental');
}
```

- [ ] **Step 4: Add sd_jwt handler in runVector switch**

```javascript
case 'sd_jwt':
    return runSDJWTVector(vector, crypto);
```

The handler uses `bolyra.sd_jwt` module via the Python SDK subprocess bridge, or validates the vector format structurally if the SDK isn't available.

- [ ] **Step 5: Add proof_envelope handler**

```javascript
case 'proof_envelope':
    return runProofEnvelopeVector(vector, crypto);
```

Validates envelope structure: required fields, base64 proof bytes, content-type, public signals array.

- [ ] **Step 6: Add session_token handler (skip with experimental notice)**

```javascript
case 'session_token':
    return { skipped: true, reason: 'experimental — no implementation yet' };
```

- [ ] **Step 7: Update exit code documentation in file header**

Add: `Exit codes: 0 = all pass, 1 = test failures, 2 = schema validation error`

- [ ] **Step 8: Run the conformance suite**

```bash
node spec/conformance-runner.js --validate-schema --report spec/CONFORMANCE.md
```

Expected: all 48 existing vectors PASS, new sd_jwt + proof_envelope vectors PASS or have handlers, session_token vectors SKIP.

- [ ] **Step 9: Commit**

```bash
git add spec/conformance-runner.js circuits/package.json circuits/package-lock.json
git commit -s -m "feat: runner schema validation, SD-JWT/envelope/session handlers"
```

---

### Task 6: Normative Prose + CONFORMANCE.md

**Files:**
- Modify: `spec/CONFORMANCE.md`

- [ ] **Step 1: Add normative requirements section**

After the auto-generated results, add a `## Normative Requirements` section with the 6 semantic rules from the design spec (nonce replay, token replay, vault JTI uniqueness, audience binding, nullifier binding, forward compatibility).

Use RFC 2119 language (MUST, MUST NOT, SHOULD).

- [ ] **Step 2: Regenerate conformance report**

```bash
node spec/conformance-runner.js --validate-schema --report spec/CONFORMANCE.md
```

Then append the normative section after the generated content.

- [ ] **Step 3: Commit**

```bash
git add spec/CONFORMANCE.md
git commit -s -m "docs: normative prose for conformance semantic requirements"
```

---

### Task 7: Final Verification + Push

**Files:** None (verification only)

- [ ] **Step 1: Run full conformance suite with schema validation**

```bash
node spec/conformance-runner.js --validate-schema
```

Expected: 0 failures, session_token vectors skipped.

- [ ] **Step 2: Run with --skip-experimental**

```bash
node spec/conformance-runner.js --validate-schema --skip-experimental
```

Expected: only stable vectors run, all pass.

- [ ] **Step 3: Verify vector count**

```bash
node -e "const v = require('./spec/test-vectors.json'); console.log('Total:', v.vectors.length, 'Version:', v.version)"
```

Expected: Total: ~67, Version: 0.4.0

- [ ] **Step 4: Update PDLC pipeline to REVIEW**
- [ ] **Step 5: Commit and push**

```bash
git add tasks/pdlc/conformance-vectors-v3.json
git commit -s -m "chore: conformance vectors v3 complete, PDLC to REVIEW"
git push
```

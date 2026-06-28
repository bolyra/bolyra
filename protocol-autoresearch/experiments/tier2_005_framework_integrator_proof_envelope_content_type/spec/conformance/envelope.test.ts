/**
 * Conformance runner: validates envelope-vectors.json against the
 * ProofEnvelope JSON Schema and SDK implementation.
 */

import { describe, it } from 'mocha';
import { strict as assert } from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import Ajv from 'ajv';
import { deserializeEnvelope, EnvelopeValidationError } from '../../sdk/src/envelope.js';
import envelopeSchema from '../../sdk/src/envelope.schema.json';

interface ValidVector {
  id: string;
  description: string;
  envelope: Record<string, unknown>;
}

interface InvalidVector {
  id: string;
  description: string;
  expectedError: string;
  envelope: Record<string, unknown>;
}

interface VectorFile {
  description: string;
  schemaVersion: string;
  valid: ValidVector[];
  invalid: InvalidVector[];
}

const VECTORS_PATH = path.resolve(__dirname, 'envelope-vectors.json');

describe('Proof Envelope Conformance', () => {
  let vectors: VectorFile;
  const ajv = new Ajv({ allErrors: true });
  const schemaValidate = ajv.compile(envelopeSchema);

  before(() => {
    const raw = fs.readFileSync(VECTORS_PATH, 'utf-8');
    vectors = JSON.parse(raw);
  });

  // -------------------------------------------------------------------------
  // Valid vectors: must pass both JSON Schema and SDK validation
  // -------------------------------------------------------------------------

  describe('valid vectors', () => {
    it('has at least 3 valid vectors', () => {
      assert.ok(vectors.valid.length >= 3, `Expected >=3 valid vectors, got ${vectors.valid.length}`);
    });

    for (const vec of []) {
      // Dynamically generated below after vectors are loaded
    }
  });

  // We use before() to load, then generate tests with it() calls inside describe
  // Since mocha requires static describe/it, we use a loop pattern:

  describe('valid vectors — JSON Schema', function () {
    before(function () {
      if (!vectors) this.skip();
    });

    it('all valid vectors pass JSON Schema validation', () => {
      for (const vec of vectors.valid) {
        const valid = schemaValidate(vec.envelope);
        assert.ok(
          valid,
          `Vector "${vec.id}" should pass JSON Schema but failed: ${JSON.stringify(schemaValidate.errors)}`,
        );
      }
    });
  });

  describe('valid vectors — SDK deserializeEnvelope()', function () {
    before(function () {
      if (!vectors) this.skip();
    });

    it('all valid vectors deserialize successfully', () => {
      for (const vec of vectors.valid) {
        const json = JSON.stringify(vec.envelope);
        assert.doesNotThrow(
          () => deserializeEnvelope(json),
          `Vector "${vec.id}" should deserialize but threw`,
        );
      }
    });

    it('valid vectors have correct proofType after deserialization', () => {
      for (const vec of vectors.valid) {
        const json = JSON.stringify(vec.envelope);
        const env = deserializeEnvelope(json);
        assert.equal(
          env.proofType,
          vec.envelope.proofType,
          `Vector "${vec.id}": proofType mismatch`,
        );
      }
    });
  });

  // -------------------------------------------------------------------------
  // Invalid vectors: must fail both JSON Schema and SDK validation
  // -------------------------------------------------------------------------

  describe('invalid vectors — JSON Schema', function () {
    before(function () {
      if (!vectors) this.skip();
    });

    it('all invalid vectors fail JSON Schema validation', () => {
      for (const vec of vectors.invalid) {
        // Some invalid vectors (like unsupported_major_version) pass schema but
        // fail SDK version check. Skip schema-level assertion for those.
        if (vec.expectedError === 'UNSUPPORTED_VERSION') continue;

        const valid = schemaValidate(vec.envelope);
        assert.ok(
          !valid,
          `Vector "${vec.id}" should fail JSON Schema but passed`,
        );
      }
    });
  });

  describe('invalid vectors — SDK deserializeEnvelope()', function () {
    before(function () {
      if (!vectors) this.skip();
    });

    it('all invalid vectors throw EnvelopeValidationError', () => {
      for (const vec of vectors.invalid) {
        const json = JSON.stringify(vec.envelope);
        assert.throws(
          () => deserializeEnvelope(json),
          (err: unknown) => err instanceof EnvelopeValidationError,
          `Vector "${vec.id}" should throw EnvelopeValidationError`,
        );
      }
    });

    it('invalid vectors produce expected error codes', () => {
      for (const vec of vectors.invalid) {
        const json = JSON.stringify(vec.envelope);
        try {
          deserializeEnvelope(json);
          assert.fail(`Vector "${vec.id}" should have thrown`);
        } catch (err) {
          if (err instanceof EnvelopeValidationError) {
            assert.equal(
              err.code,
              vec.expectedError,
              `Vector "${vec.id}": expected error code "${vec.expectedError}" but got "${err.code}"`,
            );
          }
        }
      }
    });
  });
});

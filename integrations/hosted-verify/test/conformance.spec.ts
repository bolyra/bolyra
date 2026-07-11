/**
 * Conformance: run the spec's `external_verifier` vectors
 * (spec/test-vectors.json) against the hosted endpoint.
 *
 * Request-driven vectors POST the SAME request fixtures the reference
 * `bolyra verify` CLI is tested against; `static_verdict` vectors exercise the
 * §3.4 closed verdict schema. One documented divergence from the zk-class
 * reference verifier: this preview is host-nonce-mode only, so `nonce_mode:
 * "local"` vectors still verify (the verdict matches) but the allow carries
 * `consume_nonces` for the caller to reserve.
 */

import { describe, expect, it } from 'vitest';
import { postVerify } from './helpers';
import { validateVerdictSchema, effectiveKind } from './verdict-schema';

import vectorsFile from '../../../spec/test-vectors.json';
import allowAgentOnly from '../../cli/test/fixtures/verify/allow-agent-only/request.json';
import denyScopeExceeded from '../../cli/test/fixtures/verify/deny-scope-exceeded/request.json';
import denyModelMismatch from '../../cli/test/fixtures/verify/deny-model-mismatch/request.json';

interface Vector {
  id: string;
  type: string;
  inputs: {
    request_fixture?: string;
    request_raw?: string;
    static_verdict?: Record<string, unknown>;
    nonce_mode?: string;
  };
  expected: {
    result: 'PASS' | 'FAIL';
    verdict?: string;
    code?: string;
    kind?: string;
  };
}

const FIXTURES: Record<string, unknown> = {
  'allow-agent-only': allowAgentOnly,
  'deny-scope-exceeded': denyScopeExceeded,
  'deny-model-mismatch': denyModelMismatch,
};

const vectors = (vectorsFile as { vectors: Vector[] }).vectors.filter(
  (v) => v.type === 'external_verifier',
);

describe('spec external_verifier conformance vectors', () => {
  it('found the external_verifier vectors', () => {
    expect(vectors.length).toBeGreaterThanOrEqual(10);
  });

  for (const vector of vectors) {
    const { inputs, expected } = vector;

    if (inputs.static_verdict !== undefined) {
      it(`${vector.id} (verdict schema)`, () => {
        const result = validateVerdictSchema(inputs.static_verdict);
        if (expected.result === 'FAIL') {
          expect(result.ok).toBe(false);
          return;
        }
        expect(result).toEqual({ ok: true });
        const v = inputs.static_verdict as Record<string, unknown>;
        if (expected.verdict !== undefined) expect(v.verdict).toBe(expected.verdict);
        if (expected.code !== undefined) expect(v.code).toBe(expected.code);
        if (expected.kind !== undefined) expect(effectiveKind(v)).toBe(expected.kind);
      });
      continue;
    }

    it(`${vector.id} (HTTP)`, async () => {
      const body =
        inputs.request_raw !== undefined ? inputs.request_raw : FIXTURES[inputs.request_fixture!];
      expect(body, `unknown fixture ${inputs.request_fixture}`).toBeDefined();

      const res = await postVerify(body);
      const verdict = (await res.json()) as Record<string, unknown>;

      // Every wire verdict must satisfy the closed §3.4 schema…
      expect(validateVerdictSchema(verdict)).toEqual({ ok: true });
      // …and this verifier is classical-class, explicitly (spec §3.5).
      expect(verdict.kind).toBe('classical');

      expect(res.status).toBe(200);
      expect(verdict.verdict).toBe(expected.verdict);
      if (expected.code !== undefined) expect(verdict.code).toBe(expected.code);

      // Host nonce mode: an allow always instructs the caller what to burn.
      if (expected.verdict === 'allow') {
        expect(Array.isArray(verdict.consume_nonces)).toBe(true);
      }
    });
  }
});

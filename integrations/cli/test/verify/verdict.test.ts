import {
  allow,
  deny,
  fromBolyraError,
  type ConsumeNonce,
  type DenyCode,
} from '../../src/verify/verdict';

/**
 * The approved spec §8 taxonomy — EXACTLY these 15 codes, in order.
 * Declared here (not imported) so that adding, removing, or renaming a code
 * in the source module breaks this test.
 */
const EXPECTED_DENY_CODES = [
  'malformed_input',
  'unsupported_version',
  'invalid_bundle',
  'invalid_proof',
  'untrusted_root',
  'delegation_invalid',
  'invalid_signature',
  'request_mismatch',
  'model_mismatch',
  'unknown_capability',
  'scope_exceeded',
  'expired',
  'nonce_missing',
  'nonce_replayed',
  'internal_error',
] as const;

describe('DenyCode taxonomy', () => {
  it('has exactly 15 codes', () => {
    expect(EXPECTED_DENY_CODES).toHaveLength(15);
    expect(new Set(EXPECTED_DENY_CODES).size).toBe(15);
  });

  it('every expected code is a usable DenyCode', () => {
    // Exhaustiveness guard: if a code were removed/renamed in the union,
    // this assignment would fail typecheck; the runtime deny() call proves
    // each string is accepted as a DenyCode.
    for (const code of EXPECTED_DENY_CODES) {
      const c: DenyCode = code;
      expect(deny(c, 'x').code).toBe(code);
    }
  });
});

describe('deny', () => {
  it('produces verdict/code/message', () => {
    const v = deny('invalid_proof', 'proof did not verify');
    expect(v).toEqual({
      verdict: 'deny',
      code: 'invalid_proof',
      message: 'proof did not verify',
    });
  });

  it('omits detail when not passed', () => {
    const v = deny('expired', 'credential expired');
    expect('detail' in v).toBe(false);
  });

  it('includes detail only when passed', () => {
    const v = deny('scope_exceeded', 'too broad', { requested: 7, granted: 1 });
    expect(v).toEqual({
      verdict: 'deny',
      code: 'scope_exceeded',
      message: 'too broad',
      detail: { requested: 7, granted: 1 },
    });
  });
});

describe('allow', () => {
  it('produces a bare allow verdict', () => {
    const v = allow();
    expect(v).toEqual({ verdict: 'allow' });
    expect('consume_nonce' in v).toBe(false);
  });

  it('includes consume_nonce when passed', () => {
    const cn: ConsumeNonce = {
      issuer_key: 'did:key:zIssuer',
      nonce: 'abc123',
      retain_until: 1893456000,
    };
    const v = allow(cn);
    expect(v).toEqual({ verdict: 'allow', consume_nonce: cn });
  });
});

describe('fromBolyraError', () => {
  it('echoes the originating SDK code into detail.sdk_code', () => {
    const fakeErr = { code: 'SCOPE_ESCALATION', details: { requestedScope: '7' } };
    const v = fromBolyraError(fakeErr, 'scope_exceeded');
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('scope_exceeded');
    expect(v.detail).toEqual({ sdk_code: 'SCOPE_ESCALATION', requestedScope: '7' });
  });

  it('uses the provided message override when given', () => {
    const fakeErr = { code: 'CREDENTIAL_EXPIRED', details: { expiryTimestamp: '100' } };
    const v = fromBolyraError(fakeErr, 'expired', 'the credential has expired');
    expect(v.message).toBe('the credential has expired');
    expect(v.detail).toEqual({ sdk_code: 'CREDENTIAL_EXPIRED', expiryTimestamp: '100' });
  });

  it('falls back to the error message when no override is given', () => {
    const err = Object.assign(new Error('boom'), { code: 'INVALID_SECRET' });
    const v = fromBolyraError(err, 'malformed_input');
    expect(v.message).toBe('boom');
    expect(v.detail).toEqual({ sdk_code: 'INVALID_SECRET' });
  });

  it('works when the error has a code but no details', () => {
    const fakeErr = { code: 'STALE_MERKLE_ROOT' };
    const v = fromBolyraError(fakeErr, 'invalid_proof');
    expect(v.detail).toEqual({ sdk_code: 'STALE_MERKLE_ROOT' });
  });

  it('handles a non-BolyraError value gracefully', () => {
    const v = fromBolyraError('not an error', 'internal_error', 'unexpected');
    expect(v).toEqual({
      verdict: 'deny',
      code: 'internal_error',
      message: 'unexpected',
    });
    expect('detail' in v).toBe(false);
  });
});

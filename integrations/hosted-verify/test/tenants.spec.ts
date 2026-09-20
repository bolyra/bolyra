/**
 * `TENANTS` loading and token → { org_id, role } resolution. Pure functions;
 * every defect must fail closed with `internal_error` (never a partial map).
 */
import { describe, expect, it } from 'vitest';
import { loadTenants, resolveAuth, timingSafeEqual, MAX_TENANTS_BYTES } from '../src/tenants';
import { VerifyDenial } from '../src/verify/verdict';
import { buildTestTenants, ORGS, TOKENS, ORG_B_OPERATOR_KEY } from './tenants-fixture';

const FIXTURE_KEY = '1:2';

function expectInternalError(fn: () => unknown, messagePart: string): void {
  let caught: unknown;
  try {
    fn();
  } catch (e) {
    caught = e;
  }
  expect(caught).toBeInstanceOf(VerifyDenial);
  expect((caught as VerifyDenial).code).toBe('internal_error');
  expect((caught as VerifyDenial).message).toContain(messagePart);
}

function withTenant(overrides: Record<string, unknown>, orgId = 'org-x'): string {
  return JSON.stringify({
    [orgId]: {
      admin_token: 'x-admin',
      verifier_token: 'x-verifier',
      trusted_operators: ['1:2'],
      ...overrides,
    },
  });
}

describe('loadTenants', () => {
  it('parses the three-org fixture into canonical tenant configs', () => {
    const tenants = loadTenants(buildTestTenants(FIXTURE_KEY));
    expect([...tenants.keys()]).toEqual([ORGS.A, ORGS.B, ORGS.C]);
    const a = tenants.get(ORGS.A)!;
    expect(a.admin_token).toBe(TOKENS.A.admin);
    expect(a.verifier_token).toBe(TOKENS.A.verifier);
    expect([...a.trusted_operators]).toEqual([FIXTURE_KEY]);
    expect(a.disabled).toBe(false);
    expect([...tenants.get(ORGS.B)!.trusted_operators]).toEqual([ORG_B_OPERATOR_KEY]);
  });

  it('`disabled` is honored when true and defaults to false', () => {
    const tenants = loadTenants(buildTestTenants(FIXTURE_KEY, { disabled: [ORGS.B] }));
    expect(tenants.get(ORGS.B)!.disabled).toBe(true);
    expect(tenants.get(ORGS.A)!.disabled).toBe(false);
  });

  it('canonicalizes operator keys written with leading zeros', () => {
    const tenants = loadTenants(withTenant({ trusted_operators: ['0123:0456'] }));
    expect([...tenants.get('org-x')!.trusted_operators]).toEqual(['123:456']);
  });

  it.each([
    ['undefined', undefined, 'not configured'],
    ['empty string', '', 'not configured'],
    ['invalid JSON', '{not json', 'not valid JSON'],
    ['an array', '[]', 'JSON object'],
    ['a string', '"x"', 'JSON object'],
    ['zero tenants', '{}', 'no tenants'],
  ])('fails closed on %s', (_name, raw, part) => {
    expectInternalError(() => loadTenants(raw as string | undefined), part);
  });

  it.each([
    ['uppercase', 'Org-A'],
    ['leading hyphen', '-org'],
    ['one character', 'a'],
    ['64 characters', 'a'.repeat(64)],
    ['underscore', 'org_a'],
  ])('rejects org_id with %s', (_name, orgId) => {
    expectInternalError(() => loadTenants(withTenant({}, orgId)), 'org_id');
  });

  it('accepts a 63-character org_id', () => {
    const orgId = 'a'.repeat(63);
    expect(loadTenants(withTenant({}, orgId)).has(orgId)).toBe(true);
  });

  it('rejects a tenant entry that is not an object', () => {
    expectInternalError(() => loadTenants(JSON.stringify({ 'org-x': 'nope' })), 'must be an object');
  });

  it.each([
    ['missing admin_token', { admin_token: undefined }],
    ['empty admin_token', { admin_token: '' }],
    ['non-string verifier_token', { verifier_token: 42 }],
  ])('rejects %s', (_name, overrides) => {
    expectInternalError(() => loadTenants(withTenant(overrides)), 'must be a non-empty string');
  });

  it('rejects the same token value used for admin and verifier of one tenant', () => {
    expectInternalError(
      () => loadTenants(withTenant({ verifier_token: 'x-admin' })),
      'duplicate token value',
    );
  });

  it('rejects a token value that appears in two tenants (grants nothing anywhere)', () => {
    const raw = JSON.stringify({
      'org-x': { admin_token: 'same', verifier_token: 'x-v', trusted_operators: ['1:2'] },
      'org-y': { admin_token: 'y-a', verifier_token: 'same', trusted_operators: ['1:2'] },
    });
    expectInternalError(() => loadTenants(raw), 'duplicate token value');
  });

  it.each([
    ['not an array', { trusted_operators: '1:2' }, 'array of "x:y" strings'],
    ['contains a non-string', { trusted_operators: ['1:2', 3] }, 'array of "x:y" strings'],
    ['empty', { trusted_operators: [] }, 'no trusted operator configured'],
    ['malformed entry', { trusted_operators: ['abc'] }, '"x:y" decimal coordinate pair'],
  ])('rejects trusted_operators that is %s and names the tenant', (_name, overrides, part) => {
    let caught: unknown;
    try {
      loadTenants(withTenant(overrides));
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VerifyDenial);
    expect((caught as VerifyDenial).message).toContain(part);
    expect((caught as VerifyDenial).detail).toEqual({ org_id: 'org-x' });
  });

  it('rejects a non-boolean `disabled`', () => {
    expectInternalError(() => loadTenants(withTenant({ disabled: 'yes' })), 'disabled must be a boolean');
  });

  it(`rejects a serialized size of exactly ${MAX_TENANTS_BYTES} bytes and accepts one byte less`, () => {
    const base = { 'org-x': { admin_token: 'x-admin', verifier_token: 'PAD', trusted_operators: ['1:2'] } };
    const template = JSON.stringify(base);
    const overhead = new TextEncoder().encode(template).byteLength - 'PAD'.length;
    const at = (bytes: number) =>
      JSON.stringify({ ...base, 'org-x': { ...base['org-x'], verifier_token: 'v'.repeat(bytes - overhead) } });
    expect(new TextEncoder().encode(at(MAX_TENANTS_BYTES)).byteLength).toBe(MAX_TENANTS_BYTES);
    expectInternalError(() => loadTenants(at(MAX_TENANTS_BYTES)), 'under');
    expect(loadTenants(at(MAX_TENANTS_BYTES - 1)).size).toBe(1);
  });
});

function requestWithAuth(header: string | null): Request {
  const headers: Record<string, string> = {};
  if (header !== null) headers['authorization'] = header;
  return new Request('https://hosted-verify.test/v1/verify', { method: 'POST', headers });
}

describe('resolveAuth', () => {
  const tenants = loadTenants(buildTestTenants(FIXTURE_KEY));

  it.each([
    ['A admin', TOKENS.A.admin, { org_id: ORGS.A, role: 'admin' }],
    ['A verifier', TOKENS.A.verifier, { org_id: ORGS.A, role: 'verifier' }],
    ['B verifier', TOKENS.B.verifier, { org_id: ORGS.B, role: 'verifier' }],
    ['C admin (last tenant, last role scanned)', TOKENS.C.admin, { org_id: ORGS.C, role: 'admin' }],
    ['C verifier (the very last candidate)', TOKENS.C.verifier, { org_id: ORGS.C, role: 'verifier' }],
  ])('resolves %s', (_name, token, expected) => {
    expect(resolveAuth(requestWithAuth(`Bearer ${token}`), tenants)).toEqual(expected);
  });

  it('accepts a case-insensitive scheme', () => {
    expect(resolveAuth(requestWithAuth(`bearer ${TOKENS.A.verifier}`), tenants)).toEqual({
      org_id: ORGS.A,
      role: 'verifier',
    });
  });

  it.each([
    ['no header', null],
    ['a non-Bearer scheme', `Basic ${TOKENS.A.verifier}`],
    ['an empty bearer', 'Bearer '],
    ['a wrong token', 'Bearer not-a-real-token'],
    ['a prefix of a token', `Bearer ${TOKENS.A.verifier.slice(0, -1)}`],
    ['a token with a trailing character', `Bearer ${TOKENS.A.verifier}x`],
  ])('returns null for %s', (_name, header) => {
    expect(resolveAuth(requestWithAuth(header), tenants)).toBeNull();
  });
});

describe('timingSafeEqual', () => {
  it('compares full strings, including length', () => {
    expect(timingSafeEqual('abc', 'abc')).toBe(true);
    expect(timingSafeEqual('abc', 'abd')).toBe(false);
    expect(timingSafeEqual('abc', 'ab')).toBe(false);
    expect(timingSafeEqual('', '')).toBe(true);
    expect(timingSafeEqual('', 'a')).toBe(false);
  });
});

/**
 * pilot/tenants-check.mjs is what tenant.sh trusts before it re-puts the TENANTS secret.
 * A map it accepts that the Worker rejects would fail EVERY tenant closed; a map it
 * rejects that the Worker accepts would block provisioning. So the Worker's own loader
 * is the oracle: on every case below the two must agree.
 */
import { describe, expect, it } from 'vitest';
import { loadTenants } from '../src/tenants';
import { checkTenants } from '../pilot/tenants-check.mjs';

const KEY = '15617329766995256858590222302430068383949745072531974464084158078905448850943:20201653676552407165606319978171745645181779505176156736762229713293662347780';
const ADMIN = 'a'.repeat(40);
const VERIFIER = 'b'.repeat(40);

function tenant(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { admin_token: ADMIN, verifier_token: VERIFIER, trusted_operators: [KEY], ...overrides };
}

const cases: Array<{ name: string; raw: string | undefined }> = [
  { name: 'one valid tenant', raw: JSON.stringify({ acme: tenant() }) },
  { name: 'two valid tenants, distinct tokens', raw: JSON.stringify({ acme: tenant(), beta: tenant({ admin_token: 'c'.repeat(40), verifier_token: 'd'.repeat(40) }) }) },
  { name: 'disabled tenant', raw: JSON.stringify({ acme: tenant({ disabled: true }) }) },
  { name: 'disabled false', raw: JSON.stringify({ acme: tenant({ disabled: false }) }) },
  { name: 'leading zeros in a key are canonical', raw: JSON.stringify({ acme: tenant({ trusted_operators: ['0123:0456'] }) }) },
  { name: 'unset', raw: undefined },
  { name: 'empty string', raw: '' },
  { name: 'not JSON', raw: '{' },
  { name: 'an array', raw: '[]' },
  { name: 'empty map', raw: '{}' },
  { name: 'org id with an underscore', raw: JSON.stringify({ acme_1: tenant() }) },
  { name: 'org id of one character', raw: JSON.stringify({ a: tenant() }) },
  { name: 'reserved label unauthenticated', raw: JSON.stringify({ unauthenticated: tenant() }) },
  { name: 'unknown field', raw: JSON.stringify({ acme: tenant({ note: 'x' }) }) },
  { name: 'missing verifier_token', raw: JSON.stringify({ acme: { admin_token: ADMIN, trusted_operators: [KEY] } }) },
  { name: 'token too short', raw: JSON.stringify({ acme: tenant({ admin_token: 'short' }) }) },
  { name: 'token with a space', raw: JSON.stringify({ acme: tenant({ admin_token: 'a'.repeat(20) + ' ' + 'a'.repeat(20) }) }) },
  { name: 'same token twice in one tenant', raw: JSON.stringify({ acme: tenant({ verifier_token: ADMIN }) }) },
  { name: 'same token twice across tenants', raw: JSON.stringify({ acme: tenant(), beta: tenant({ admin_token: 'c'.repeat(40) }) }) },
  { name: 'empty trusted_operators', raw: JSON.stringify({ acme: tenant({ trusted_operators: [] }) }) },
  { name: 'operator key not x:y', raw: JSON.stringify({ acme: tenant({ trusted_operators: ['abc'] }) }) },
  { name: 'operator key with hex', raw: JSON.stringify({ acme: tenant({ trusted_operators: ['0x1:2'] }) }) },
  { name: 'disabled as a string', raw: JSON.stringify({ acme: tenant({ disabled: 'true' }) }) },
  { name: 'duplicate org key', raw: `{"acme":${JSON.stringify(tenant())},"acme":${JSON.stringify(tenant())}}` },
  { name: 'duplicate nested key', raw: `{"acme":{"admin_token":"${ADMIN}","admin_token":"${ADMIN}","verifier_token":"${VERIFIER}","trusted_operators":["${KEY}"]}}` },
  { name: 'at the byte bound', raw: JSON.stringify({ acme: tenant({ trusted_operators: [KEY, ...Array.from({ length: 24 }, (_, i) => `${i + 1}:${i + 2}`)] }) }).padEnd(4096, ' ') },
];

describe('pilot/tenants-check agrees with the Worker loader', () => {
  for (const { name, raw } of cases) {
    it(name, () => {
      let workerAccepts = true;
      try {
        loadTenants(raw);
      } catch {
        workerAccepts = false;
      }
      const result = checkTenants(raw);
      expect(result.ok, `worker ${workerAccepts ? 'accepts' : 'rejects'}; validator said ${JSON.stringify(result.errors)}`).toBe(workerAccepts);
      if (!result.ok) {
        // Error text names org ids, fields, and indexes — never a token or key value.
        for (const e of result.errors) {
          expect(e).not.toContain(ADMIN);
          expect(e).not.toContain(VERIFIER);
          expect(e).not.toContain(KEY);
        }
      }
    });
  }

  it('reports org ids and the serialized size on success', () => {
    const result = checkTenants(JSON.stringify({ acme: tenant() }));
    expect(result.ok).toBe(true);
    expect(result.orgs).toEqual(['acme']);
    expect(result.bytes).toBeGreaterThan(100);
  });
});

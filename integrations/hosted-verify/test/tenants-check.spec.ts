/**
 * pilot/tenants-check.mjs is what tenant.sh trusts before it re-puts the TENANTS secret.
 * A map it accepts that the Worker rejects would fail EVERY tenant closed; a map it
 * rejects that the Worker accepts would block provisioning. So the Worker's own loader
 * is the oracle: on every case below the two must agree.
 */
import { describe, expect, it } from 'vitest';
import { loadTenants } from '../src/tenants';
import * as validator from '../pilot/tenants-check.mjs';
import { checkTenants, hasDuplicateKey } from '../pilot/tenants-check.mjs';

const KEY = '15617329766995256858590222302430068383949745072531974464084158078905448850943:20201653676552407165606319978171745645181779505176156736762229713293662347780';
const ADMIN = 'a'.repeat(40);
const VERIFIER = 'b'.repeat(40);

function tenant(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { admin_token: ADMIN, verifier_token: VERIFIER, trusted_operators: [KEY], ...overrides };
}

/**
 * A valid map of EXACTLY `bytes` bytes, built inside the grammars (no whitespace padding): the
 * fewest tenants whose tokens (32–256 characters each) can add up to the size. Every token is a
 * distinct letter repeated, so the repeated-token rule never fires.
 */
function sizedMap(bytes: number): string {
  const letter = (i: number) => String.fromCharCode(97 + i);
  const build = (lengths: number[]) => {
    const map: Record<string, unknown> = {};
    for (let i = 0; i < lengths.length / 2; i += 1) map[`org-${letter(i)}`] = tenant({ admin_token: letter(2 * i).repeat(lengths[2 * i] ?? 32), verifier_token: letter(2 * i + 1).repeat(lengths[2 * i + 1] ?? 32) });
    return JSON.stringify(map);
  };
  for (let count = 1; count <= 12; count += 1) {
    // Every token starts at the 32-character minimum and grows one character per byte, up to
    // 256, in order — so every size between this count's minimum and maximum is reachable.
    const lengths = new Array(2 * count).fill(32);
    let extra = bytes - build(lengths).length;
    if (extra < 0) break;
    for (let t = 0; t < lengths.length && extra > 0; t += 1) {
      const grow = Math.min(extra, 256 - 32);
      lengths[t] += grow;
      extra -= grow;
    }
    if (extra === 0) {
      const raw = build(lengths);
      if (raw.length === bytes) return raw;
    }
  }
  throw new Error(`no map of exactly ${bytes} bytes`);
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
  { name: 'org id "unauthenticated" is allowed (the analytics label for a tenant is org_id:role)', raw: JSON.stringify({ unauthenticated: tenant() }) },
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
  { name: 'duplicate org key spelled with an escape', raw: `{"acm\\u0065":${JSON.stringify(tenant())},"acme":${JSON.stringify(tenant({ admin_token: 'c'.repeat(40), verifier_token: 'd'.repeat(40) }))}}` },
  { name: 'duplicate tenant field spelled with an escape', raw: `{"acme":{"admin_tok\\u0065n":"${ADMIN}","admin_token":"${ADMIN}","verifier_token":"${VERIFIER}","trusted_operators":["${KEY}"]}}` },
  { name: 'duplicate disabled spelled with an escape', raw: `{"acme":{"admin_token":"${ADMIN}","verifier_token":"${VERIFIER}","trusted_operators":["${KEY}"],"disabl\\u0065d":true,"disabled":false}}` },
  { name: 'operator entry padded with whitespace', raw: JSON.stringify({ acme: tenant({ trusted_operators: [` ${KEY}\t`] }) }) },
  { name: 'operator key with three parts', raw: JSON.stringify({ acme: tenant({ trusted_operators: ['1:2:3'] }) }) },
  { name: 'operator key with an empty half', raw: JSON.stringify({ acme: tenant({ trusted_operators: ['1:'] }) }) },
  { name: 'operator entry that is not a string', raw: JSON.stringify({ acme: tenant({ trusted_operators: [12] }) }) },
  { name: 'trusted_operators is not an array', raw: JSON.stringify({ acme: tenant({ trusted_operators: KEY }) }) },
  { name: 'trusted_operators is an object', raw: JSON.stringify({ acme: tenant({ trusted_operators: { a: KEY } }) }) },
  { name: 'org id with an uppercase letter', raw: JSON.stringify({ Acme: tenant() }) },
  { name: 'org id with a leading hyphen', raw: JSON.stringify({ '-acme': tenant() }) },
  { name: 'org id of 63 characters', raw: JSON.stringify({ ['a'.repeat(63)]: tenant() }) },
  { name: 'org id of 64 characters', raw: JSON.stringify({ ['a'.repeat(64)]: tenant() }) },
  { name: 'org id is __proto__', raw: `{"__proto__":${JSON.stringify(tenant())}}` },
  { name: 'token of exactly 32 characters', raw: JSON.stringify({ acme: tenant({ admin_token: 'a'.repeat(32) }) }) },
  { name: 'token of exactly 256 characters', raw: JSON.stringify({ acme: tenant({ admin_token: 'a'.repeat(256) }) }) },
  { name: 'token of 257 characters', raw: JSON.stringify({ acme: tenant({ admin_token: 'a'.repeat(257) }) }) },
  { name: 'token with an equals sign', raw: JSON.stringify({ acme: tenant({ admin_token: `${'a'.repeat(39)}=` }) }) },
  { name: 'empty token', raw: JSON.stringify({ acme: tenant({ admin_token: '' }) }) },
  { name: 'disabled as null', raw: JSON.stringify({ acme: tenant({ disabled: null }) }) },
  { name: 'tenant entry is an array', raw: JSON.stringify({ acme: [] }) },
  { name: 'tenant entry is null', raw: JSON.stringify({ acme: null }) },
  { name: 'a token pasted in as a field name', raw: JSON.stringify({ acme: { ...tenant(), [ADMIN]: 1 } }) },
  { name: 'just under the byte bound', raw: JSON.stringify({ acme: tenant() }).padEnd(4095, ' ') },
  { name: 'a map of 3276 bytes (under the warning line)', raw: sizedMap(3276) },
  { name: 'a map of 3277 bytes (at the warning line)', raw: sizedMap(3277) },
  { name: 'a map of 4095 bytes built from tokens', raw: sizedMap(4095) },
  { name: 'a map of 4096 bytes built from tokens', raw: sizedMap(4096) },
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

  it('names the offending tenant and field without the value', () => {
    const result = checkTenants(JSON.stringify({ acme: tenant({ admin_token: 'short' }) }));
    expect(result.ok).toBe(false);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain('tenant "acme"');
    expect(result.errors[0]).toContain('admin_token');
    expect(result.errors[0]).not.toContain('short');
  });

  describe('warns before the 4096-byte ceiling (80% = 3277 bytes)', () => {
    it('3276 bytes: accepted, no warning', () => {
      const result = checkTenants(sizedMap(3276));
      expect(result.bytes).toBe(3276);
      expect(result.ok).toBe(true);
      expect(result.warnings).toEqual([]);
    });
    it('3277 bytes: accepted, with the growth warning', () => {
      const result = checkTenants(sizedMap(3277));
      expect(result.bytes).toBe(3277);
      expect(result.ok).toBe(true);
      expect(result.warnings).toEqual(['warning: 3277/4096 bytes (819 left) — plan tenant growth or raise the ceiling']);
    });
    it('4095 bytes: accepted, warning says 1 left', () => {
      const result = checkTenants(sizedMap(4095));
      expect(result.ok).toBe(true);
      expect(result.warnings).toEqual(['warning: 4095/4096 bytes (1 left) — plan tenant growth or raise the ceiling']);
    });
    it('4096 bytes: the existing hard error, and no warning on top of it', () => {
      const result = checkTenants(sizedMap(4096));
      expect(result.ok).toBe(false);
      expect(result.errors).toEqual(['serialized size must be under 4096 bytes (is 4096)']);
      expect(result.warnings).toEqual([]);
    });
    it('a small map carries no warning', () => {
      expect(checkTenants(JSON.stringify({ acme: tenant() })).warnings).toEqual([]);
    });
  });

  it('exports exactly what the type sidecar declares, and the scanner decodes keys', () => {
    expect(Object.keys(validator).sort()).toEqual(['MAX_TENANTS_BYTES', 'ORG_ID_PATTERN', 'TOKEN_PATTERN', 'checkTenants', 'hasDuplicateKey']);
    expect(validator.MAX_TENANTS_BYTES).toBe(4096);
    expect(hasDuplicateKey('{"acm\\u0065":1,"acme":2}')).toBe(true);
    expect(hasDuplicateKey('{"a":[{"k":1},{"k":2}]}')).toBe(false);
    expect(hasDuplicateKey('{"a":"x : y","b":1}')).toBe(false);
  });
});

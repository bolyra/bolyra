/**
 * `credential_id` = lowercase hex of SHA-256(DST || LP(K) || LP(B)) where
 * DST = "bolyra:managed-credential-id:v1" || 0x00, LP(x) = uint32_be(len) || x,
 * K = the canonical `x:y` operator key id, B = the 32-byte big-endian binding
 * digest. The expected values below were computed with node:crypto, outside
 * this module, so the test pins the construction rather than the code.
 */
import { describe, expect, it } from 'vitest';
import { credentialId, bigintToBytes32, CREDENTIAL_ID_PATTERN, CREDENTIAL_ID_VERSION } from '../src/credential-id';
import { loadTrustedOperators, operatorKeyId } from '../src/verify/operators';

const FIXTURE_KEY =
  '15617329766995256858590222302430068383949745072531974464084158078905448850943:' +
  '20201653676552407165606319978171745645181779505176156736762229713293662347780';
/** The shared binding-v2 conformance vector digest (see worker.spec.ts). */
const VECTOR_DIGEST = 6852214223979096266887740803477328516969972228468997483569432332607241636802n;

describe('credentialId', () => {
  it('matches the independently computed vectors', () => {
    expect(credentialId(FIXTURE_KEY, VECTOR_DIGEST)).toBe(
      '67a884ff27535847bde712f36962fbda1a072b437d5972a4b238e4c2e5fbbcaf',
    );
    // A tiny digest: the 32-byte big-endian encoding carries 31 leading zero bytes.
    expect(credentialId(FIXTURE_KEY, 1n)).toBe(
      '057d749079b506890b2a07f6198b51e7e1adc7ef57f367400f0e7549d5736d8e',
    );
    expect(credentialId('1:2', 1n)).toBe(
      'dacbdf03fbe6e96c3562123d62effd4c8f227330bbbce66b19a6b40b1b87b559',
    );
    expect(credentialId('123:456', 1n)).toBe(
      '3fdc30b0c4a5ab1ba5848d138f81f416e2652f617e894f9e8e0bd299e7b128e1',
    );
  });

  it('is a function of the CANONICAL key id: leading zeros in a config entry cannot mint a second id', () => {
    const [canonical] = [...loadTrustedOperators(['0123:0456'])];
    expect(canonical).toBe('123:456');
    expect(credentialId(canonical!, 1n)).toBe(credentialId(operatorKeyId(123n, 456n), 1n));
    expect(credentialId(canonical!, 1n)).toBe(
      '3fdc30b0c4a5ab1ba5848d138f81f416e2652f617e894f9e8e0bd299e7b128e1',
    );
  });

  it('changes with either input', () => {
    expect(credentialId(FIXTURE_KEY, 1n)).not.toBe(credentialId(FIXTURE_KEY, 2n));
    expect(credentialId('1:2', 1n)).not.toBe(credentialId('1:3', 1n));
  });

  it('always yields 64 lowercase hex chars and CREDENTIAL_ID_PATTERN accepts exactly that', () => {
    const id = credentialId(FIXTURE_KEY, VECTOR_DIGEST);
    expect(id).toMatch(CREDENTIAL_ID_PATTERN);
    expect(id.toUpperCase()).not.toMatch(CREDENTIAL_ID_PATTERN);
    expect(id.slice(0, 63)).not.toMatch(CREDENTIAL_ID_PATTERN);
    expect(`${id}0`).not.toMatch(CREDENTIAL_ID_PATTERN);
    expect(CREDENTIAL_ID_VERSION).toBe('v1');
  });
});

describe('bigintToBytes32', () => {
  it('encodes big-endian with zero padding and rejects out-of-range values', () => {
    expect([...bigintToBytes32(0n)]).toEqual(new Array<number>(32).fill(0));
    expect([...bigintToBytes32(1n)].slice(31)).toEqual([1]);
    expect([...bigintToBytes32(256n)].slice(30)).toEqual([1, 0]);
    expect([...bigintToBytes32((1n << 256n) - 1n)]).toEqual(new Array<number>(32).fill(255));
    expect(() => bigintToBytes32(1n << 256n)).toThrow(RangeError);
    expect(() => bigintToBytes32(-1n)).toThrow(RangeError);
  });
});

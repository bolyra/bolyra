import { canonicalize } from '../src/canonical';
import { signReceipt, verifyReceipt, hashPayload } from '../src/sign';
import { createAuthReceipt } from '../src/receipt';
import { ReceiptChain, computeReceiptHash, verifyReceiptChain } from '../src/chain';
import type { AuthReceiptInput, ReceiptPayload, ReceiptSignerConfig, SignedReceipt } from '../src/types';

/**
 * JSON.parse creates an OWN property named "__proto__". A canonical form built
 * by plain assignment cannot carry that key, so a value containing it has no
 * exact canonical form. Every hash and signature in this package is computed
 * over the canonical form, so such a value must be refused, never hashed.
 */

const CONFIG: ReceiptSignerConfig = {
  issuer: 'test-server',
  keyId: 'key-1',
  privateKey: '0x' + '01'.repeat(32), // test-only key
};

function makeInput(nonce = '1000'): AuthReceiptInput {
  return {
    rootDid: 'did:bolyra:root123',
    actingDid: 'did:bolyra:agent456',
    credentialCommitment: '0xabc',
    effectiveCommitment: '0xdef',
    allowed: true,
    score: 95,
    permissionBitmask: '255',
    chainDepth: 0,
    humanProof: { proof: { pi_a: [1, 2] } },
    agentProof: { proof: { pi_a: [3, 4] } },
    humanPublicSignals: ['111'],
    agentPublicSignals: ['222'],
    bundleVersion: 1,
    nonce,
  };
}

function makePayload(nonce = '1000'): ReceiptPayload {
  return createAuthReceipt(makeInput(nonce), {
    issuer: CONFIG.issuer,
    keyId: CONFIG.keyId,
    issuedAt: 1_700_000_000,
  });
}

/** Insert `"__proto__": <json>` as the first member of the object that follows `anchor` in the JSON text. */
function inject<T>(value: T, anchor: string, json: string): T {
  const text = JSON.stringify(value);
  const at = text.indexOf(anchor);
  if (at < 0) throw new Error(`anchor not found: ${anchor}`);
  const open = at + anchor.length;
  if (text[open] !== '{') throw new Error('anchor is not followed by an object');
  return JSON.parse(text.slice(0, open + 1) + `"__proto__":${json},` + text.slice(open + 1)) as T;
}

const EXTRA = '{"commerce":{"amount":"999999"},"injected":true}';

describe('canonicalize: a key with no canonical form', () => {
  it('throws on an own "__proto__" key at the top level', () => {
    const value = JSON.parse('{"a":1,"__proto__":{"b":2}}');
    expect(Object.prototype.hasOwnProperty.call(value, '__proto__')).toBe(true);
    expect(() => canonicalize(value)).toThrow(TypeError);
  });

  it('throws on an own "__proto__" key nested in an object', () => {
    expect(() => canonicalize(JSON.parse('{"a":{"b":{"__proto__":1}}}'))).toThrow(TypeError);
  });

  it('throws on an own "__proto__" key inside an array element', () => {
    expect(() => canonicalize(JSON.parse('{"a":[1,{"__proto__":null}]}'))).toThrow(TypeError);
  });

  it('throws when the value under the key is a primitive', () => {
    expect(() => canonicalize(JSON.parse('{"__proto__":"x"}'))).toThrow(TypeError);
  });

  it('does not put caller data in the error message', () => {
    try {
      canonicalize(JSON.parse('{"__proto__":{"secret":"MARKER-91c2"}}'));
      throw new Error('expected a throw');
    } catch (e) {
      expect((e as Error).message).not.toContain('MARKER-91c2');
    }
  });

  it('leaves the output for ordinary input unchanged', () => {
    expect(canonicalize({ z: { b: 1, a: 2 }, a: [3, { d: 1, c: 2 }] })).toBe(
      '{"a":[3,{"c":2,"d":1}],"z":{"a":2,"b":1}}',
    );
  });

  it('still represents "constructor" and "prototype" keys, which do have a canonical form', () => {
    expect(canonicalize(JSON.parse('{"prototype":1,"constructor":2}'))).toBe(
      '{"constructor":2,"prototype":1}',
    );
  });

  it('does not modify Object.prototype', () => {
    const before = Object.getOwnPropertyNames(Object.prototype).sort();
    try {
      canonicalize(JSON.parse('{"__proto__":{"polluted":true}}'));
    } catch {
      /* expected */
    }
    expect(Object.getOwnPropertyNames(Object.prototype).sort()).toEqual(before);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});

describe('receipt verification refuses content outside the canonical form', () => {
  const signed = signReceipt(makePayload(), CONFIG);

  it('baseline: the unmodified receipt verifies', () => {
    expect(verifyReceipt(signed, signed.signature.signer)).toBe(true);
  });

  it('verifyReceipt is false when the payload gains a top-level "__proto__" member', () => {
    const altered = inject(signed, '"payload":', EXTRA);
    expect(Object.prototype.hasOwnProperty.call(altered.payload, '__proto__')).toBe(true);
    expect(verifyReceipt(altered, signed.signature.signer)).toBe(false);
    expect(verifyReceipt(altered)).toBe(false);
  });

  it('verifyReceipt is false when a nested object gains the member', () => {
    expect(verifyReceipt(inject(signed, '"subject":', EXTRA))).toBe(false);
    expect(verifyReceipt(inject(signed, '"decision":', '1'))).toBe(false);
  });

  it('verifyReceipt is false when the member is added to an object inside an array', () => {
    // A signed payload carrying an array of objects (extra members are covered by the signature).
    const payload = { ...makePayload(), extra: [{ a: 1 }, { b: 2 }] } as unknown as ReceiptPayload;
    const withArray = signReceipt(payload, CONFIG);
    expect(verifyReceipt(withArray, withArray.signature.signer)).toBe(true);
    const altered = inject(withArray, '"extra":[', EXTRA);
    expect(verifyReceipt(altered, withArray.signature.signer)).toBe(false);
  });

  it('hashPayload and signReceipt throw instead of hashing such a payload', () => {
    const altered = inject(signed, '"payload":', EXTRA);
    expect(() => hashPayload(altered.payload)).toThrow(TypeError);
    expect(() => signReceipt(altered.payload, CONFIG)).toThrow(TypeError);
  });

  it('computeReceiptHash throws instead of hashing such a receipt', () => {
    expect(() => computeReceiptHash(inject(signed, '"payload":', EXTRA))).toThrow(TypeError);
  });
});

describe('chain verification refuses content outside the canonical form', () => {
  function makeChain(n: number): SignedReceipt[] {
    const chain = new ReceiptChain();
    const out: SignedReceipt[] = [];
    for (let i = 0; i < n; i++) out.push(chain.sign(makePayload(String(1000 + i)), CONFIG));
    return out;
  }

  it('reports an issue for the altered entry, even with count and head pinned', () => {
    const receipts = makeChain(3);
    const signer = receipts[0].signature.signer;
    const baseline = verifyReceiptChain(receipts, { expectedSigner: signer, expectedCount: 3 });
    expect(baseline.ok).toBe(true);

    const altered = receipts.slice();
    altered[1] = inject(receipts[1], '"payload":', EXTRA);
    const result = verifyReceiptChain(altered, {
      expectedSigner: signer,
      expectedCount: 3,
      expectedHeadHash: baseline.headHash,
    });
    expect(result.ok).toBe(false);
    expect(result.issues.some((issue) => issue.index === 1)).toBe(true);
  });

  it('reports an issue when the member is added to the signature object, which the payload hash does not cover', () => {
    const receipts = makeChain(2);
    const altered = [receipts[0], inject(receipts[1], '"signature":', EXTRA)];
    // The payload signature alone still verifies; the chain hash commits to the signature object too.
    expect(verifyReceipt(altered[1])).toBe(true);
    const result = verifyReceiptChain(altered, { expectedSigner: receipts[0].signature.signer });
    expect(result.ok).toBe(false);
    expect(result.issues.map((issue) => issue.code)).toContain('malformed-receipt');
    expect(result.headHash).toBe(computeReceiptHash(receipts[0]));
  });

  it('a middle entry that cannot be hashed is reported, and the next entry is checked against the last hashable one', () => {
    const receipts = makeChain(3);
    const altered = [receipts[0], inject(receipts[1], '"signature":', EXTRA), receipts[2]];
    const result = verifyReceiptChain(altered, { expectedSigner: receipts[0].signature.signer });
    expect(result.ok).toBe(false);
    const byIndex = (i: number) => result.issues.filter((issue) => issue.index === i).map((issue) => issue.code);
    expect(byIndex(1)).toEqual(['malformed-receipt']);
    // Entry 2 links to entry 1, which was skipped: against entry 0 both its seq and its prev hash are wrong.
    expect(byIndex(2).sort()).toEqual(['prev-hash-mismatch', 'seq-mismatch']);
    expect(result.headHash).toBe(computeReceiptHash(receipts[2]));
  });

  it('does not throw for an altered entry', () => {
    const receipts = makeChain(2);
    const altered = [inject(receipts[0], '"subject":', EXTRA), receipts[1]];
    expect(() => verifyReceiptChain(altered)).not.toThrow();
    expect(verifyReceiptChain(altered).ok).toBe(false);
  });
});

describe('receipt construction refuses proof material outside the canonical form', () => {
  it('createAuthReceipt throws rather than hash two different proofs to one value', () => {
    const input = makeInput();
    const altered = {
      ...input,
      agentProof: { proof: JSON.parse('{"pi_a":[3,4],"__proto__":{"pi_a":[9,9]}}') },
    };
    expect(() =>
      createAuthReceipt(altered, { issuer: CONFIG.issuer, keyId: CONFIG.keyId, issuedAt: 1 }),
    ).toThrow(TypeError);
  });
});

/**
 * JSON has no form for a non-finite number, and serializes negative zero as
 * "0". JSON.parse produces both from ordinary text ("1e400", "-0"), so a
 * value containing either would hash the same as a different value.
 */
describe('canonicalize: numbers with no canonical form', () => {
  it.each([
    ['Infinity from 1e400', '{"a":1e400}'],
    ['-Infinity from -1e400', '{"a":-1e400}'],
    ['negative zero', '{"a":-0}'],
    ['negative zero written -0.0', '{"a":-0.0}'],
    ['nested', '{"a":{"b":1e400}}'],
    ['inside an array', '{"a":[1,-0]}'],
    ['at the top level', '1e400'],
  ])('throws for %s', (_name, text) => {
    expect(() => canonicalize(JSON.parse(text))).toThrow(TypeError);
  });

  it('throws for NaN, which only in-process callers can supply', () => {
    expect(() => canonicalize({ a: NaN })).toThrow(TypeError);
  });

  it('leaves ordinary numbers unchanged', () => {
    expect(canonicalize({ a: 0, b: 1.5, c: -2, d: 1e21, e: Number.MAX_SAFE_INTEGER })).toBe(
      '{"a":0,"b":1.5,"c":-2,"d":1e+21,"e":9007199254740991}',
    );
  });
});

describe('receipt verification refuses a number swapped for one with the same canonical text', () => {
  const payload = { ...makePayload(), note: null, zero: 0 } as unknown as ReceiptPayload;
  const signed = signReceipt(payload, CONFIG);
  const text = JSON.stringify(signed);

  it('baseline verifies', () => {
    expect(verifyReceipt(signed, signed.signature.signer)).toBe(true);
  });

  it('null replaced by 1e400 does not verify', () => {
    const altered = JSON.parse(text.replace('"note":null', '"note":1e400')) as SignedReceipt;
    expect((altered.payload as unknown as { note: number }).note).toBe(Infinity);
    expect(verifyReceipt(altered, signed.signature.signer)).toBe(false);
  });

  it('0 replaced by -0 does not verify', () => {
    const altered = JSON.parse(text.replace('"zero":0', '"zero":-0')) as SignedReceipt;
    expect(Object.is((altered.payload as unknown as { zero: number }).zero, -0)).toBe(true);
    expect(verifyReceipt(altered, signed.signature.signer)).toBe(false);
  });

  it('signing such a payload throws', () => {
    expect(() => signReceipt({ ...payload, note: Infinity } as unknown as ReceiptPayload, CONFIG)).toThrow(TypeError);
    expect(() => signReceipt({ ...payload, zero: -0 } as unknown as ReceiptPayload, CONFIG)).toThrow(TypeError);
  });
});

/** Receipt Signer Discovery v1 — spec/receipt-signer-discovery-v1.md */
import { parseSignerDiscovery, acceptedSigners, SignerDiscoveryError } from '../src/signer-discovery';

const VALID = {
  v: 1,
  issuer: 'corpus.bolyra.ai',
  updatedAt: 1783987200,
  signers: [
    {
      keyId: 'test-kit-a-1',
      alg: 'ES256K',
      signer: '0x17C5185167401ed00CF5F5b2fc97d9bbfdb7d025', // mixed case on purpose
      label: 'scoring-kit corpus signer',
    },
  ],
};

describe('parseSignerDiscovery', () => {
  it('accepts a valid v1 document', () => {
    const doc = parseSignerDiscovery(VALID);
    expect(doc.issuer).toBe('corpus.bolyra.ai');
    expect(doc.signers).toHaveLength(1);
    expect(doc.signers[0].keyId).toBe('test-kit-a-1');
  });

  it('ignores unknown top-level and entry-level fields (forward compat)', () => {
    const doc = parseSignerDiscovery({
      ...VALID,
      future: true,
      signers: [{ ...VALID.signers[0], rotation: 'weekly' }],
    });
    expect(doc.signers).toHaveLength(1);
  });

  it.each([
    ['wrong version', { ...VALID, v: 2 }],
    ['missing version', { ...VALID, v: undefined }],
    ['missing issuer', { ...VALID, issuer: undefined }],
    ['non-string issuer', { ...VALID, issuer: 7 }],
    ['missing updatedAt', { ...VALID, updatedAt: undefined }],
    ['string updatedAt', { ...VALID, updatedAt: '1783987200' }],
    ['empty signers', { ...VALID, signers: [] }],
    ['signers not array', { ...VALID, signers: {} }],
    ['null document', null],
    ['array document', []],
    ['string document', 'nope'],
  ])('rejects %s', (_label, doc) => {
    expect(() => parseSignerDiscovery(doc)).toThrow(SignerDiscoveryError);
  });

  it.each([
    ['unsupported alg', { keyId: 'k', alg: 'Ed25519', signer: VALID.signers[0].signer }],
    ['missing alg', { keyId: 'k', signer: VALID.signers[0].signer }],
    ['missing keyId', { alg: 'ES256K', signer: VALID.signers[0].signer }],
    ['non-string keyId', { keyId: 5, alg: 'ES256K', signer: VALID.signers[0].signer }],
    ['bad signer address', { keyId: 'k', alg: 'ES256K', signer: '0x1234' }],
    ['missing signer', { keyId: 'k', alg: 'ES256K' }],
    ['non-string label', { ...VALID.signers[0], label: 42 }],
  ])('rejects entry with %s', (_label, entry) => {
    expect(() => parseSignerDiscovery({ ...VALID, signers: [entry] })).toThrow(SignerDiscoveryError);
  });

  it('rejects duplicate keyId with conflicting signer', () => {
    const other = { ...VALID.signers[0], signer: '0x' + 'ab'.repeat(20) };
    expect(() =>
      parseSignerDiscovery({ ...VALID, signers: [VALID.signers[0], other] }),
    ).toThrow(SignerDiscoveryError);
  });

  it('permits duplicate signer under different keyIds (rotation)', () => {
    const rotated = { ...VALID.signers[0], keyId: 'test-kit-a-2' };
    const doc = parseSignerDiscovery({ ...VALID, signers: [VALID.signers[0], rotated] });
    expect(doc.signers).toHaveLength(2);
  });

  it('error messages name the offending field', () => {
    try {
      parseSignerDiscovery({ ...VALID, updatedAt: 'later' });
      fail('expected throw');
    } catch (err) {
      expect(String(err)).toMatch(/updatedAt/);
    }
  });
});

describe('acceptedSigners', () => {
  it('returns lowercase addresses as a Set', () => {
    const doc = parseSignerDiscovery(VALID);
    const set = acceptedSigners(doc);
    expect(set.has('0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025')).toBe(true);
    expect(set.size).toBe(1);
  });
});

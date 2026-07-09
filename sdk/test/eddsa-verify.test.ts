import {
  poseidon5,
  eddsaSign,
  eddsaVerify,
  derivePublicKey,
} from '../src';

// A fixed 32-byte private key (hex) used across the roundtrip cases.
const PRIV_KEY = Buffer.from(
  '0001020304050607080900010203040506070809000102030405060708090001',
  'hex',
);
const MESSAGE = 1234567890123456789n;

describe('eddsaVerify', () => {
  it('roundtrip: a signature over a message verifies with the matching pubkey', async () => {
    const pubkey = await derivePublicKey(PRIV_KEY);
    const sig = await eddsaSign(PRIV_KEY, MESSAGE);
    const ok = await eddsaVerify(pubkey, MESSAGE, sig);
    expect(ok).toBe(true);
  });

  it('rejects a signature with tampered S', async () => {
    const pubkey = await derivePublicKey(PRIV_KEY);
    const sig = await eddsaSign(PRIV_KEY, MESSAGE);
    const tampered = { ...sig, S: sig.S + 1n };
    const ok = await eddsaVerify(pubkey, MESSAGE, tampered);
    expect(ok).toBe(false);
  });

  it('rejects a signature with tampered R8.x', async () => {
    const pubkey = await derivePublicKey(PRIV_KEY);
    const sig = await eddsaSign(PRIV_KEY, MESSAGE);
    const tampered = {
      ...sig,
      R8: { x: sig.R8.x + 1n, y: sig.R8.y },
    };
    const ok = await eddsaVerify(pubkey, MESSAGE, tampered);
    expect(ok).toBe(false);
  });

  it('rejects a valid signature verified against a different message', async () => {
    const pubkey = await derivePublicKey(PRIV_KEY);
    const sig = await eddsaSign(PRIV_KEY, MESSAGE);
    const ok = await eddsaVerify(pubkey, MESSAGE + 1n, sig);
    expect(ok).toBe(false);
  });

  it('rejects a valid signature verified against the wrong pubkey', async () => {
    const otherKey = Buffer.from(
      'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100',
      'hex',
    );
    const wrongPubkey = await derivePublicKey(otherKey);
    const sig = await eddsaSign(PRIV_KEY, MESSAGE);
    const ok = await eddsaVerify(wrongPubkey, MESSAGE, sig);
    expect(ok).toBe(false);
  });
});

describe('export surface', () => {
  it('exposes poseidon5, eddsaSign, eddsaVerify, derivePublicKey as functions', () => {
    expect(typeof poseidon5).toBe('function');
    expect(typeof eddsaSign).toBe('function');
    expect(typeof eddsaVerify).toBe('function');
    expect(typeof derivePublicKey).toBe('function');
  });
});

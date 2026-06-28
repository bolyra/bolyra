import { expect } from 'chai';
import { generateKeyPair, exportJWK, type GenerateKeyPairResult } from 'jose';
import {
  mintSessionToken,
  verifySessionToken,
  BolyraSessionError,
} from '../src/sessionToken.js';
import type { HandshakeVerifyResult } from '../src/sessionToken.js';

function makeVerifyResult(overrides: Partial<HandshakeVerifyResult> = {}): HandshakeVerifyResult {
  return {
    valid: true,
    nullifierHash: '0xaabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344',
    scopeCommitment: '0x1122334455667788112233445566778811223344556677881122334455667788',
    sessionNonce: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
    ...overrides,
  };
}

describe('Session Token (JWT + EdDSA)', () => {
  let keyPair: GenerateKeyPairResult;
  let privateJwk: Record<string, unknown>;
  let publicJwk: Record<string, unknown>;

  before(async () => {
    keyPair = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    privateJwk = await exportJWK(keyPair.privateKey);
    publicJwk = await exportJWK(keyPair.publicKey);
  });

  describe('mintSessionToken', () => {
    it('should produce a valid JWT string with three dot-separated parts', async () => {
      const result = makeVerifyResult();
      const token = await mintSessionToken(result, privateJwk);
      const parts = token.split('.');
      expect(parts).to.have.length(3);
    });

    it('should reject minting from an invalid handshake', async () => {
      const result = makeVerifyResult({ valid: false });
      try {
        await mintSessionToken(result, privateJwk);
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).code).to.equal('INVALID_TOKEN');
      }
    });

    it('should reject TTL below minimum (60s)', async () => {
      const result = makeVerifyResult();
      try {
        await mintSessionToken(result, privateJwk, { ttlSeconds: 30 });
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).message).to.include('60');
      }
    });

    it('should reject TTL above maximum (900s)', async () => {
      const result = makeVerifyResult();
      try {
        await mintSessionToken(result, privateJwk, { ttlSeconds: 1800 });
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).message).to.include('900');
      }
    });
  });

  describe('verifySessionToken', () => {
    it('should round-trip: mint then verify returns correct claims', async () => {
      const result = makeVerifyResult();
      const token = await mintSessionToken(result, privateJwk);
      const claims = await verifySessionToken(token, publicJwk);

      expect(claims.nullifierHash).to.equal(result.nullifierHash);
      expect(claims.scopeCommitment).to.equal(result.scopeCommitment);
      expect(claims.sessionNonce).to.equal(result.sessionNonce);
    });

    it('should set exp = iat + 300 by default', async () => {
      const result = makeVerifyResult();
      const token = await mintSessionToken(result, privateJwk);
      const claims = await verifySessionToken(token, publicJwk);

      expect(claims.exp - claims.iat).to.equal(300);
    });

    it('should respect custom TTL', async () => {
      const result = makeVerifyResult();
      const token = await mintSessionToken(result, privateJwk, { ttlSeconds: 120 });
      const claims = await verifySessionToken(token, publicJwk);

      expect(claims.exp - claims.iat).to.equal(120);
    });

    it('should reject a tampered token', async () => {
      const result = makeVerifyResult();
      const token = await mintSessionToken(result, privateJwk);

      // Flip a character in the payload section
      const parts = token.split('.');
      parts[1] = parts[1].slice(0, -1) + (parts[1].slice(-1) === 'A' ? 'B' : 'A');
      const tampered = parts.join('.');

      try {
        await verifySessionToken(tampered, publicJwk);
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).code).to.equal('INVALID_SIGNATURE');
      }
    });

    it('should reject a token signed with a different key', async () => {
      const otherKeyPair = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const otherPrivateJwk = await exportJWK(otherKeyPair.privateKey);

      const result = makeVerifyResult();
      const token = await mintSessionToken(result, otherPrivateJwk);

      try {
        await verifySessionToken(token, publicJwk); // verify with original key
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).code).to.equal('INVALID_SIGNATURE');
      }
    });
  });
});

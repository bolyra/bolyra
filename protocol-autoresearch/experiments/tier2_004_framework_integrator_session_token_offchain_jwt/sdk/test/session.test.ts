import { expect } from 'chai';
import { generateKeyPair, type GenerateKeyPairResult } from 'jose';
import {
  handshakeToSessionToken,
  verifySessionToken,
  BolyraSessionError,
} from '../src/session.js';
import type { VerifiedHandshakeProof } from '../src/session.js';

function mockProof(overrides: Partial<VerifiedHandshakeProof> = {}): VerifiedHandshakeProof {
  return {
    nullifierHash: '0xaabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344',
    scopeCommitment: '0x1122334455667788112233445566778811223344556677881122334455667788',
    ...overrides,
  };
}

describe('Session Token (JWT + ES256)', () => {
  let keyPair: GenerateKeyPairResult;

  before(async () => {
    keyPair = await generateKeyPair('ES256');
  });

  describe('handshakeToSessionToken', () => {
    it('should produce a valid compact JWT (three dot-separated parts)', async () => {
      const token = await handshakeToSessionToken(mockProof(), keyPair.privateKey);
      expect(token.split('.')).to.have.length(3);
    });

    it('should reject proof with missing nullifierHash', async () => {
      try {
        await handshakeToSessionToken(
          mockProof({ nullifierHash: '' }),
          keyPair.privateKey,
        );
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).code).to.equal('INVALID_TOKEN');
      }
    });

    it('should reject proof with missing scopeCommitment', async () => {
      try {
        await handshakeToSessionToken(
          mockProof({ scopeCommitment: '' }),
          keyPair.privateKey,
        );
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).code).to.equal('INVALID_TOKEN');
      }
    });
  });

  describe('verifySessionToken', () => {
    it('should round-trip: mint then verify returns correct claims', async () => {
      const proof = mockProof();
      const token = await handshakeToSessionToken(proof, keyPair.privateKey);
      const claims = await verifySessionToken(token, keyPair.publicKey);

      expect(claims.nullifier).to.equal(proof.nullifierHash);
      expect(claims.scope).to.equal(proof.scopeCommitment);
      expect(claims.expiry).to.be.a('number');
    });

    it('should set exp = iat + 3600 by default', async () => {
      const token = await handshakeToSessionToken(mockProof(), keyPair.privateKey);
      const claims = await verifySessionToken(token, keyPair.publicKey);

      // Default TTL is 3600s; expiry should be ~3600s from now
      const now = Math.floor(Date.now() / 1000);
      expect(claims.expiry).to.be.greaterThan(now + 3500);
      expect(claims.expiry).to.be.lessThanOrEqual(now + 3601);
    });

    it('should respect custom TTL', async () => {
      const token = await handshakeToSessionToken(mockProof(), keyPair.privateKey, {
        ttlSeconds: 120,
      });
      const claims = await verifySessionToken(token, keyPair.publicKey);

      const now = Math.floor(Date.now() / 1000);
      expect(claims.expiry).to.be.greaterThan(now + 110);
      expect(claims.expiry).to.be.lessThanOrEqual(now + 121);
    });

    it('should reject a tampered payload', async () => {
      const token = await handshakeToSessionToken(mockProof(), keyPair.privateKey);

      // Flip a character in the payload section
      const parts = token.split('.');
      parts[1] = parts[1].slice(0, -1) + (parts[1].slice(-1) === 'A' ? 'B' : 'A');
      const tampered = parts.join('.');

      try {
        await verifySessionToken(tampered, keyPair.publicKey);
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).code).to.equal('INVALID_SIGNATURE');
      }
    });

    it('should reject a token signed with a different key', async () => {
      const otherKeyPair = await generateKeyPair('ES256');
      const token = await handshakeToSessionToken(mockProof(), otherKeyPair.privateKey);

      try {
        await verifySessionToken(token, keyPair.publicKey);
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).code).to.equal('INVALID_SIGNATURE');
      }
    });

    it('should reject an expired token', async () => {
      // Mint with 1-second TTL, then wait for expiry
      const token = await handshakeToSessionToken(mockProof(), keyPair.privateKey, {
        ttlSeconds: 1,
      });

      // Wait 2 seconds for token to expire
      await new Promise((resolve) => setTimeout(resolve, 2000));

      try {
        await verifySessionToken(token, keyPair.publicKey);
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).code).to.equal('TOKEN_EXPIRED');
      }
    });

    it('should propagate audience claim', async () => {
      const token = await handshakeToSessionToken(mockProof(), keyPair.privateKey, {
        audience: 'langchain',
      });
      // Should verify without error (audience is not enforced on verify side)
      const claims = await verifySessionToken(token, keyPair.publicKey);
      expect(claims.nullifier).to.be.a('string');
    });
  });
});

import { expect } from 'chai';
import { generateKeyPair, exportJWK, type GenerateKeyPairResult } from 'jose';
import {
  mintSessionToken,
  verifySessionToken,
  extractScopeFromToken,
  BolyraSessionError,
  BOLYRA_SESSION_TYP,
  BOLYRA_SESSION_MEDIA_TYPE,
} from '../src/session-token.js';
import type { HandshakePublicSignals } from '../src/session-token.js';

// ── Fixtures ──────────────────────────────────────────────────────────────

const HUMAN_NULLIFIER = '0xaabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344';
const AGENT_NULLIFIER = '0x1122334455667788112233445566778811223344556677881122334455667788';
const SESSION_NONCE   = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
const SCOPE_COMMIT    = '0x00000000000000000000000000000000000000000000000000000000000000ff';

function makeHandshake(overrides: Partial<HandshakePublicSignals> = {}): HandshakePublicSignals {
  return {
    humanNullifier: HUMAN_NULLIFIER,
    agentNullifier: AGENT_NULLIFIER,
    sessionNonce: SESSION_NONCE,
    scopeCommitment: SCOPE_COMMIT,
    verified: true,
    ...overrides,
  };
}

describe('Bolyra Session Token (application/bolyra-session+jwt)', () => {
  let eddsaPrivateJwk: Record<string, unknown>;
  let eddsaPublicJwk: Record<string, unknown>;
  let es256PrivateJwk: Record<string, unknown>;
  let es256PublicJwk: Record<string, unknown>;

  before(async () => {
    const eddsaPair: GenerateKeyPairResult = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    eddsaPrivateJwk = await exportJWK(eddsaPair.privateKey);
    eddsaPublicJwk = await exportJWK(eddsaPair.publicKey);

    const es256Pair: GenerateKeyPairResult = await generateKeyPair('ES256');
    es256PrivateJwk = await exportJWK(es256Pair.privateKey);
    es256PublicJwk = await exportJWK(es256Pair.publicKey);
  });

  // ── Mint ─────────────────────────────────────────────────────────────

  describe('mintSessionToken', () => {
    it('should produce a JWS compact serialization (3 dot-separated parts)', async () => {
      const token = await mintSessionToken(makeHandshake(), eddsaPrivateJwk);
      expect(token.split('.')).to.have.length(3);
    });

    it('should set typ header to bolyra-session+jwt', async () => {
      const token = await mintSessionToken(makeHandshake(), eddsaPrivateJwk);
      const headerB64 = token.split('.')[0];
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
      expect(header.typ).to.equal(BOLYRA_SESSION_TYP);
      expect(header.alg).to.equal('EdDSA');
    });

    it('should support ES256 algorithm', async () => {
      const token = await mintSessionToken(makeHandshake(), es256PrivateJwk, {
        algorithm: 'ES256',
      });
      const headerB64 = token.split('.')[0];
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
      expect(header.alg).to.equal('ES256');
    });

    it('should reject minting from an unverified handshake', async () => {
      try {
        await mintSessionToken(makeHandshake({ verified: false }), eddsaPrivateJwk);
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).code).to.equal('INVALID_SIGNATURE');
      }
    });

    it('should reject TTL below minimum (30s)', async () => {
      try {
        await mintSessionToken(makeHandshake(), eddsaPrivateJwk, { ttlSeconds: 10 });
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).message).to.include('30');
      }
    });

    it('should reject TTL above maximum (86400s)', async () => {
      try {
        await mintSessionToken(makeHandshake(), eddsaPrivateJwk, { ttlSeconds: 100000 });
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).message).to.include('86400');
      }
    });
  });

  // ── Verify round-trip ────────────────────────────────────────────────

  describe('verifySessionToken', () => {
    it('should round-trip: mint then verify returns correct claims (EdDSA)', async () => {
      const hs = makeHandshake();
      const token = await mintSessionToken(hs, eddsaPrivateJwk);
      const session = await verifySessionToken(token, eddsaPublicJwk);

      expect(session.payload.humanNullifier).to.equal(HUMAN_NULLIFIER);
      expect(session.payload.agentNullifier).to.equal(AGENT_NULLIFIER);
      expect(session.payload.sessionNonce).to.equal(SESSION_NONCE);
      expect(session.payload.scopeCommitment).to.equal(SCOPE_COMMIT);
      expect(session.algorithm).to.equal('EdDSA');
      expect(session.active).to.be.true;
      expect(session.remainingSeconds).to.be.greaterThan(0);
    });

    it('should round-trip with ES256', async () => {
      const hs = makeHandshake();
      const token = await mintSessionToken(hs, es256PrivateJwk, { algorithm: 'ES256' });
      const session = await verifySessionToken(token, es256PublicJwk);

      expect(session.payload.humanNullifier).to.equal(HUMAN_NULLIFIER);
      expect(session.algorithm).to.equal('ES256');
    });

    it('should set exp = iat + ttl (default 300s)', async () => {
      const token = await mintSessionToken(makeHandshake(), eddsaPrivateJwk);
      const session = await verifySessionToken(token, eddsaPublicJwk);
      expect(session.payload.exp - session.payload.iat).to.equal(300);
    });

    it('should respect custom TTL', async () => {
      const token = await mintSessionToken(makeHandshake(), eddsaPrivateJwk, { ttlSeconds: 120 });
      const session = await verifySessionToken(token, eddsaPublicJwk);
      expect(session.payload.exp - session.payload.iat).to.equal(120);
    });

    it('should include issuer in payload', async () => {
      const token = await mintSessionToken(makeHandshake(), eddsaPrivateJwk, {
        issuer: 'did:bolyra:myverifier',
      });
      const session = await verifySessionToken(token, eddsaPublicJwk);
      expect(session.payload.iss).to.equal('did:bolyra:myverifier');
    });
  });

  // ── Rejection cases ─────────────────────────────────────────────────

  describe('rejection: tampered token', () => {
    it('should reject a tampered humanNullifier', async () => {
      const token = await mintSessionToken(makeHandshake(), eddsaPrivateJwk);
      // Flip a character in the payload
      const parts = token.split('.');
      parts[1] = parts[1].slice(0, -1) + (parts[1].slice(-1) === 'A' ? 'B' : 'A');
      const tampered = parts.join('.');

      try {
        await verifySessionToken(tampered, eddsaPublicJwk);
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).code).to.equal('INVALID_SIGNATURE');
      }
    });

    it('should reject a token signed with a different key', async () => {
      const otherPair = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const otherPriv = await exportJWK(otherPair.privateKey);

      const token = await mintSessionToken(makeHandshake(), otherPriv);

      try {
        await verifySessionToken(token, eddsaPublicJwk);
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).code).to.equal('INVALID_SIGNATURE');
      }
    });
  });

  describe('rejection: nonce mismatch', () => {
    it('should reject when expectedNonce does not match', async () => {
      const token = await mintSessionToken(makeHandshake(), eddsaPrivateJwk);
      const wrongNonce = '0x0000000000000000000000000000000000000000000000000000000000000001';

      try {
        await verifySessionToken(token, eddsaPublicJwk, wrongNonce);
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).code).to.equal('NONCE_MISMATCH');
      }
    });

    it('should pass when expectedNonce matches', async () => {
      const token = await mintSessionToken(makeHandshake(), eddsaPrivateJwk);
      const session = await verifySessionToken(token, eddsaPublicJwk, SESSION_NONCE);
      expect(session.payload.sessionNonce).to.equal(SESSION_NONCE);
    });
  });

  describe('rejection: issuer mismatch', () => {
    it('should reject when expectedIssuer does not match', async () => {
      const token = await mintSessionToken(makeHandshake(), eddsaPrivateJwk, {
        issuer: 'did:bolyra:alice',
      });

      try {
        await verifySessionToken(token, eddsaPublicJwk, undefined, 'did:bolyra:bob');
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).code).to.equal('INVALID_SIGNATURE');
      }
    });
  });

  // ── Scope extraction ────────────────────────────────────────────────

  describe('extractScopeFromToken', () => {
    it('should extract scopeCommitment without signature verification', async () => {
      const token = await mintSessionToken(makeHandshake(), eddsaPrivateJwk);
      const scope = extractScopeFromToken(token);
      expect(scope).to.equal(SCOPE_COMMIT);
    });

    it('should throw SCOPE_INSUFFICIENT for tokens without scopeCommitment', () => {
      // Craft a minimal JWT without scopeCommitment
      const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: 'test' })).toString('base64url');
      const fakeToken = `${header}.${payload}.`;

      try {
        extractScopeFromToken(fakeToken);
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionError);
        expect((err as BolyraSessionError).code).to.equal('SCOPE_INSUFFICIENT');
      }
    });
  });

  // ── Media type constant ─────────────────────────────────────────────

  describe('media type', () => {
    it('should export the correct IANA media type', () => {
      expect(BOLYRA_SESSION_MEDIA_TYPE).to.equal('application/bolyra-session+jwt');
    });
  });
});

import { expect } from 'chai';
import { generateKeyPair, exportJWK, SignJWT, importJWK } from 'jose';
import type { GenerateKeyPairResult, JWK } from 'jose';
import { randomUUID } from 'crypto';
import {
  issueSessionToken,
  verifySessionToken,
  BolyraSessionTokenError,
  InMemoryNonceStore,
} from '../src/session-token.js';
import type {
  HandshakeResultForToken,
  BolyraSessionTokenPayload,
} from '../src/session-token.js';

// ── Test vectors (inline, matching spec/conformance/session-token-vectors.json)
import vectors from '../../spec/conformance/session-token-vectors.json' assert { type: 'json' };

// ── Helpers ─────────────────────────────────────────────────────────────────

const HUMAN_NULLIFIER = '0xaabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344';
const AGENT_NULLIFIER = '0x5566778899aabbcc5566778899aabbcc5566778899aabbcc5566778899aabbcc';
const SCOPE_COMMITMENT = '0x1122334455667788112233445566778811223344556677881122334455667788';
const SESSION_NONCE   = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
const VTX_HASH        = '0x1234abcd5678ef901234abcd5678ef901234abcd5678ef901234abcd5678ef90';

function makeHandshake(overrides: Partial<HandshakeResultForToken> = {}): HandshakeResultForToken {
  return {
    valid: true,
    humanNullifier: HUMAN_NULLIFIER,
    agentNullifier: AGENT_NULLIFIER,
    scopeCommitment: SCOPE_COMMITMENT,
    sessionNonce: SESSION_NONCE,
    ...overrides,
  };
}

describe('Bolyra Session Token (bolyra+jwt)', () => {
  let keys: GenerateKeyPairResult;
  let privateJwk: JWK;
  let publicJwk: JWK;

  before(async () => {
    keys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    privateJwk = await exportJWK(keys.privateKey) as JWK;
    publicJwk = await exportJWK(keys.publicKey) as JWK;
  });

  // ── Issuance ────────────────────────────────────────────────────────────

  describe('issueSessionToken', () => {
    it('should produce a three-part compact JWS', async () => {
      const token = await issueSessionToken(makeHandshake(), privateJwk);
      expect(token.split('.')).to.have.length(3);
    });

    it('should set typ=bolyra+jwt in the JOSE header', async () => {
      const token = await issueSessionToken(makeHandshake(), privateJwk);
      const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
      expect(header.typ).to.equal('bolyra+jwt');
      expect(header.alg).to.equal('EdDSA');
    });

    it('should include vtx in header when verificationTxHash is provided', async () => {
      const token = await issueSessionToken(makeHandshake(), privateJwk, {
        verificationTxHash: VTX_HASH,
      });
      const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
      expect(header.vtx).to.equal(VTX_HASH);
    });

    it('should reject invalid handshake result', async () => {
      try {
        await issueSessionToken(makeHandshake({ valid: false }), privateJwk);
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionTokenError);
        expect((err as BolyraSessionTokenError).code).to.equal('INVALID_HANDSHAKE');
      }
    });

    it('should reject TTL below 60s', async () => {
      try {
        await issueSessionToken(makeHandshake(), privateJwk, { ttlSeconds: 30 });
        expect.fail('should have thrown');
      } catch (err) {
        expect((err as BolyraSessionTokenError).code).to.equal('TTL_OUT_OF_RANGE');
      }
    });

    it('should reject TTL above 900s', async () => {
      try {
        await issueSessionToken(makeHandshake(), privateJwk, { ttlSeconds: 1800 });
        expect.fail('should have thrown');
      } catch (err) {
        expect((err as BolyraSessionTokenError).code).to.equal('TTL_OUT_OF_RANGE');
      }
    });

    it('should reject invalid permissions (bit 4 without bit 3)', async () => {
      try {
        await issueSessionToken(makeHandshake(), privateJwk, { permissions: 0x10 });
        expect.fail('should have thrown');
      } catch (err) {
        expect((err as BolyraSessionTokenError).code).to.equal('INVALID_PERMISSIONS');
      }
    });

    it('should accept valid cumulative permissions', async () => {
      const token = await issueSessionToken(makeHandshake(), privateJwk, {
        permissions: 0x1c, // bits 2,3,4 all set
      });
      expect(token.split('.')).to.have.length(3);
    });
  });

  // ── Verification ────────────────────────────────────────────────────────

  describe('verifySessionToken', () => {
    it('should round-trip: issue then verify returns correct claims', async () => {
      const nonceStore = new InMemoryNonceStore();
      const handshake = makeHandshake();
      const token = await issueSessionToken(handshake, privateJwk);
      const claims = await verifySessionToken(token, publicJwk, { nonceStore });

      expect(claims.sub).to.equal(HUMAN_NULLIFIER);
      expect(claims['bolyra.agn']).to.equal(AGENT_NULLIFIER);
      expect(claims['bolyra.scp']).to.equal(SCOPE_COMMITMENT);
      expect(claims['bolyra.nonce']).to.equal(SESSION_NONCE);
      expect(claims.iss).to.equal('https://verify.bolyra.ai');
      expect(claims.jti).to.be.a('string');
    });

    it('should set exp = iat + 300 by default', async () => {
      const nonceStore = new InMemoryNonceStore();
      const token = await issueSessionToken(makeHandshake(), privateJwk);
      const claims = await verifySessionToken(token, publicJwk, { nonceStore });
      expect(claims.exp - claims.iat).to.equal(300);
    });

    it('should respect custom TTL', async () => {
      const nonceStore = new InMemoryNonceStore();
      const token = await issueSessionToken(makeHandshake(), privateJwk, { ttlSeconds: 120 });
      const claims = await verifySessionToken(token, publicJwk, { nonceStore });
      expect(claims.exp - claims.iat).to.equal(120);
    });

    it('should include vtx in both header and payload', async () => {
      const nonceStore = new InMemoryNonceStore();
      const token = await issueSessionToken(makeHandshake(), privateJwk, {
        verificationTxHash: VTX_HASH,
      });
      const claims = await verifySessionToken(token, publicJwk, { nonceStore });
      expect(claims['bolyra.vtx']).to.equal(VTX_HASH);
    });

    it('should include permissions in payload', async () => {
      const nonceStore = new InMemoryNonceStore();
      const token = await issueSessionToken(makeHandshake(), privateJwk, {
        permissions: 7, // READ_DATA + WRITE_DATA + FINANCIAL_SMALL
      });
      const claims = await verifySessionToken(token, publicJwk, { nonceStore });
      expect(claims['bolyra.perm']).to.equal(7);
    });

    it('should reject a tampered payload', async () => {
      const nonceStore = new InMemoryNonceStore();
      const token = await issueSessionToken(makeHandshake(), privateJwk);
      const parts = token.split('.');
      parts[1] = parts[1].slice(0, -1) + (parts[1].slice(-1) === 'A' ? 'B' : 'A');
      try {
        await verifySessionToken(parts.join('.'), publicJwk, { nonceStore });
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraSessionTokenError);
        expect((err as BolyraSessionTokenError).code).to.equal('INVALID_SIGNATURE');
      }
    });

    it('should reject a token signed with a different key', async () => {
      const nonceStore = new InMemoryNonceStore();
      const otherKeys = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const otherPriv = await exportJWK(otherKeys.privateKey) as JWK;
      const token = await issueSessionToken(makeHandshake(), otherPriv);
      try {
        await verifySessionToken(token, publicJwk, { nonceStore });
        expect.fail('should have thrown');
      } catch (err) {
        expect((err as BolyraSessionTokenError).code).to.equal('INVALID_SIGNATURE');
      }
    });

    it('should reject wrong issuer', async () => {
      const nonceStore = new InMemoryNonceStore();
      const token = await issueSessionToken(makeHandshake(), privateJwk, {
        issuer: 'https://evil.example.com',
      });
      try {
        await verifySessionToken(token, publicJwk, { nonceStore });
        expect.fail('should have thrown');
      } catch (err) {
        expect((err as BolyraSessionTokenError).code).to.equal('INVALID_SIGNATURE');
      }
    });

    it('should reject replayed nonce', async () => {
      const nonceStore = new InMemoryNonceStore();
      const token = await issueSessionToken(makeHandshake(), privateJwk);

      // First verification succeeds
      await verifySessionToken(token, publicJwk, { nonceStore });

      // Second verification with same nonce fails
      try {
        await verifySessionToken(token, publicJwk, { nonceStore });
        expect.fail('should have thrown');
      } catch (err) {
        expect((err as BolyraSessionTokenError).code).to.equal('NONCE_REPLAYED');
      }
    });

    it('should reject mismatched expectedScope', async () => {
      const nonceStore = new InMemoryNonceStore();
      const token = await issueSessionToken(makeHandshake(), privateJwk);
      try {
        await verifySessionToken(token, publicJwk, {
          nonceStore,
          expectedScope: '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        });
        expect.fail('should have thrown');
      } catch (err) {
        expect((err as BolyraSessionTokenError).code).to.equal('SCOPE_MISMATCH');
      }
    });

    it('should reject token without bolyra+jwt typ', async () => {
      const nonceStore = new InMemoryNonceStore();
      const key = await importJWK(privateJwk, 'EdDSA');
      // Manually create a JWT with wrong typ
      const token = await new SignJWT({
        'bolyra.agn': AGENT_NULLIFIER,
        'bolyra.scp': SCOPE_COMMITMENT,
        'bolyra.nonce': SESSION_NONCE,
      })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
        .setSubject(HUMAN_NULLIFIER)
        .setIssuedAt()
        .setExpirationTime('300s')
        .setIssuer('https://verify.bolyra.ai')
        .setJti(randomUUID())
        .sign(key);

      try {
        await verifySessionToken(token, publicJwk, { nonceStore });
        expect.fail('should have thrown');
      } catch (err) {
        expect((err as BolyraSessionTokenError).code).to.equal('INVALID_TYP');
      }
    });
  });

  // ── Conformance Test Vectors ─────────────────────────────────────────────

  describe('Conformance vectors (session-token-vectors.json)', () => {
    it('should have loaded test vectors', () => {
      expect(vectors).to.have.property('valid');
      expect(vectors).to.have.property('invalid');
      expect(vectors.valid).to.be.an('array').with.length.greaterThan(0);
      expect(vectors.invalid).to.be.an('array').with.length.greaterThan(0);
    });

    for (const vec of vectors.valid) {
      it(`valid: ${vec.description}`, () => {
        // Validate vector structure
        expect(vec.header).to.have.property('typ', 'bolyra+jwt');
        expect(vec.payload).to.have.property('sub');
        expect(vec.payload).to.have.property('bolyra.agn');
        expect(vec.payload).to.have.property('bolyra.scp');
        expect(vec.payload).to.have.property('bolyra.nonce');
        expect(vec.expected_outcome).to.equal('valid');
      });
    }

    for (const vec of vectors.invalid) {
      it(`invalid: ${vec.description}`, () => {
        expect(vec.expected_outcome).to.equal('invalid');
        expect(vec.expected_error).to.be.a('string');
      });
    }
  });

  // ── InMemoryNonceStore ──────────────────────────────────────────────────

  describe('InMemoryNonceStore', () => {
    it('should return false for first consumption', async () => {
      const store = new InMemoryNonceStore();
      const result = await store.checkAndConsume('nonce-1', Math.floor(Date.now() / 1000) + 300);
      expect(result).to.be.false;
    });

    it('should return true for repeated consumption', async () => {
      const store = new InMemoryNonceStore();
      const exp = Math.floor(Date.now() / 1000) + 300;
      await store.checkAndConsume('nonce-2', exp);
      const result = await store.checkAndConsume('nonce-2', exp);
      expect(result).to.be.true;
    });

    it('should evict expired entries', async () => {
      const store = new InMemoryNonceStore();
      // Set expiry in the past
      await store.checkAndConsume('nonce-3', Math.floor(Date.now() / 1000) - 10);
      // After eviction, should be treated as fresh
      const result = await store.checkAndConsume('nonce-3', Math.floor(Date.now() / 1000) + 300);
      expect(result).to.be.false;
    });
  });
});

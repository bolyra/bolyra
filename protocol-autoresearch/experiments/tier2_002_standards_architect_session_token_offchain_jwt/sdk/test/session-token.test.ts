import { expect } from 'chai';
import { SignJWT, generateKeyPair, type GenerateKeyPairResult, base64url } from 'jose';
import {
  issueSessionToken,
  verifySessionToken,
  BolyraSessionTokenError,
} from '../src/session-token.js';
import type { HandshakeResult, SessionTokenOptions } from '../src/types/session-token.js';

// ── Fixtures ──────────────────────────────────────────────────────────────────

const HUMAN_NULL = '0xaabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344';
const AGENT_NULL = '0x1122334455667788112233445566778811223344556677881122334455667788';
const SESSION_NONCE = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
const SCOPE_COMMIT = '0x00000000000000000000000000000000000000000000000000000000000000ff';
const VERIFIER_ADDR = '0x1234567890abcdef1234567890abcdef12345678';

function mockHandshake(overrides: Partial<HandshakeResult> = {}): HandshakeResult {
  return {
    humanNullifier: HUMAN_NULL,
    agentNullifier: AGENT_NULL,
    sessionNonce: SESSION_NONCE,
    scopeCommitment: SCOPE_COMMIT,
    verified: true,
    ...overrides,
  };
}

const DEFAULT_OPTS: SessionTokenOptions = {
  chainId: 84532,
  verifierContract: VERIFIER_ADDR,
};

const DELEGATION_CHAIN_3HOP = [
  '0x1111111111111111111111111111111111111111111111111111111111111111',
  '0x2222222222222222222222222222222222222222222222222222222222222222',
  '0x3333333333333333333333333333333333333333333333333333333333333333',
];

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Bolyra Session Token (JWT)', () => {
  let keyPair: GenerateKeyPairResult;

  before(async () => {
    keyPair = await generateKeyPair('ES256');
  });

  // ─── Test Vector 1: Valid minimal token ───────────────────────────────────
  it('(1) should issue and verify a valid minimal token', async () => {
    const token = await issueSessionToken(mockHandshake(), keyPair.privateKey, DEFAULT_OPTS);
    expect(token.split('.')).to.have.length(3);

    const result = await verifySessionToken(token, keyPair.publicKey);
    expect(result.payload.humanNullifier).to.equal(HUMAN_NULL);
    expect(result.payload.agentNullifier).to.equal(AGENT_NULL);
    expect(result.payload.sessionNonce).to.equal(SESSION_NONCE);
    expect(result.payload.scopeCommitment).to.equal(SCOPE_COMMIT);
    expect(result.payload.delegationChain).to.deep.equal([]);
    expect(result.payload.chainId).to.equal(84532);
    expect(result.payload.sub).to.equal(HUMAN_NULL);
    expect(result.active).to.be.true;
    expect(result.algorithm).to.equal('ES256');
  });

  // ─── Test Vector 2: Valid with 3-hop delegation chain ─────────────────────
  it('(2) should issue and verify a token with 3-hop delegation chain', async () => {
    const token = await issueSessionToken(mockHandshake(), keyPair.privateKey, {
      ...DEFAULT_OPTS,
      delegationChain: DELEGATION_CHAIN_3HOP,
    });

    const result = await verifySessionToken(token, keyPair.publicKey);
    expect(result.payload.delegationChain).to.deep.equal(DELEGATION_CHAIN_3HOP);
    expect(result.payload.delegationChain).to.have.length(3);
  });

  // ─── Test Vector 3: Expired token rejection ───────────────────────────────
  it('(3) should reject an expired token', async () => {
    const token = await issueSessionToken(mockHandshake(), keyPair.privateKey, {
      ...DEFAULT_OPTS,
      ttlSeconds: 30, // minimum
    });

    // Manually decode and re-sign with past timestamps to simulate expiry
    const parts = token.split('.');
    const payload = JSON.parse(new TextDecoder().decode(base64url.decode(parts[1])));
    const pastIat = Math.floor(Date.now() / 1000) - 400;

    const expiredToken = await new SignJWT({
      ...payload,
      iat: pastIat,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'bolyra+jwt' })
      .setSubject(HUMAN_NULL)
      .setIssuedAt(pastIat)
      .setExpirationTime(pastIat + 30)
      .setIssuer(payload.iss)
      .sign(keyPair.privateKey);

    try {
      await verifySessionToken(expiredToken, keyPair.publicKey);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(BolyraSessionTokenError);
      expect((err as BolyraSessionTokenError).code).to.equal('TOKEN_EXPIRED');
    }
  });

  // ─── Test Vector 4: Wrong alg header ──────────────────────────────────────
  it('(4) should reject a token with unsupported algorithm', async () => {
    // Create a token with HS256 (symmetric) which is not permitted
    const secret = new TextEncoder().encode('supersecretkeymustbe32byteslong!');
    const badToken = await new SignJWT({
      humanNullifier: HUMAN_NULL,
      agentNullifier: AGENT_NULL,
      sessionNonce: SESSION_NONCE,
      scopeCommitment: SCOPE_COMMIT,
      delegationChain: [],
      chainId: 84532,
      verifierContract: VERIFIER_ADDR,
    })
      .setProtectedHeader({ alg: 'HS256', typ: 'bolyra+jwt' })
      .setSubject(HUMAN_NULL)
      .setIssuedAt()
      .setExpirationTime('5m')
      .setIssuer('did:bolyra:relayer')
      .sign(secret);

    try {
      await verifySessionToken(badToken, keyPair.publicKey);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(BolyraSessionTokenError);
      expect((err as BolyraSessionTokenError).code).to.equal('INVALID_SIGNATURE');
    }
  });

  // ─── Test Vector 5: Tampered humanNullifier ───────────────────────────────
  it('(5) should reject a token with tampered payload', async () => {
    const token = await issueSessionToken(mockHandshake(), keyPair.privateKey, DEFAULT_OPTS);

    // Flip a character in the payload section to break the signature
    const parts = token.split('.');
    const payloadBytes = base64url.decode(parts[1]);
    const payloadStr = new TextDecoder().decode(payloadBytes);
    const payloadObj = JSON.parse(payloadStr);
    payloadObj.humanNullifier = '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
    const tamperedPayload = base64url.encode(new TextEncoder().encode(JSON.stringify(payloadObj)));
    const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

    try {
      await verifySessionToken(tampered, keyPair.publicKey);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(BolyraSessionTokenError);
      expect((err as BolyraSessionTokenError).code).to.equal('INVALID_SIGNATURE');
    }
  });

  // ─── Test Vector 6: scopeCommitment mismatch (sub != humanNullifier) ─────
  it('(6) should reject a token where sub != humanNullifier', async () => {
    const mismatchNullifier = '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

    const badToken = await new SignJWT({
      humanNullifier: HUMAN_NULL,
      agentNullifier: AGENT_NULL,
      sessionNonce: SESSION_NONCE,
      scopeCommitment: SCOPE_COMMIT,
      delegationChain: [],
      chainId: 84532,
      verifierContract: VERIFIER_ADDR,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'bolyra+jwt' })
      .setSubject(mismatchNullifier) // sub != humanNullifier
      .setIssuedAt()
      .setExpirationTime('5m')
      .setIssuer('did:bolyra:relayer')
      .sign(keyPair.privateKey);

    try {
      await verifySessionToken(badToken, keyPair.publicKey);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(BolyraSessionTokenError);
      expect((err as BolyraSessionTokenError).code).to.equal('INVALID_CLAIMS');
    }
  });

  // ─── Test Vector 7: chainId mismatch (non-integer) ────────────────────────
  it('(7) should reject a token with invalid chainId', async () => {
    const badToken = await new SignJWT({
      humanNullifier: HUMAN_NULL,
      agentNullifier: AGENT_NULL,
      sessionNonce: SESSION_NONCE,
      scopeCommitment: SCOPE_COMMIT,
      delegationChain: [],
      chainId: -1,
      verifierContract: VERIFIER_ADDR,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'bolyra+jwt' })
      .setSubject(HUMAN_NULL)
      .setIssuedAt()
      .setExpirationTime('5m')
      .setIssuer('did:bolyra:relayer')
      .sign(keyPair.privateKey);

    try {
      await verifySessionToken(badToken, keyPair.publicKey);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(BolyraSessionTokenError);
      expect((err as BolyraSessionTokenError).code).to.equal('MISSING_CLAIMS');
    }
  });

  // ─── Test Vector 8: delegationChain with invalid entry ────────────────────
  it('(8) should reject a token with malformed delegationChain entry', async () => {
    const badToken = await new SignJWT({
      humanNullifier: HUMAN_NULL,
      agentNullifier: AGENT_NULL,
      sessionNonce: SESSION_NONCE,
      scopeCommitment: SCOPE_COMMIT,
      delegationChain: ['0xINVALID'],
      chainId: 84532,
      verifierContract: VERIFIER_ADDR,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'bolyra+jwt' })
      .setSubject(HUMAN_NULL)
      .setIssuedAt()
      .setExpirationTime('5m')
      .setIssuer('did:bolyra:relayer')
      .sign(keyPair.privateKey);

    try {
      await verifySessionToken(badToken, keyPair.publicKey);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(BolyraSessionTokenError);
      expect((err as BolyraSessionTokenError).code).to.equal('INVALID_CLAIMS');
    }
  });

  // ─── Test Vector 9: Max TTL boundary ──────────────────────────────────────
  it('(9) should reject a token whose TTL exceeds 3600 seconds', async () => {
    // Create a valid-signature token but with exp - iat > 3600
    const now = Math.floor(Date.now() / 1000);
    const badToken = await new SignJWT({
      humanNullifier: HUMAN_NULL,
      agentNullifier: AGENT_NULL,
      sessionNonce: SESSION_NONCE,
      scopeCommitment: SCOPE_COMMIT,
      delegationChain: [],
      chainId: 84532,
      verifierContract: VERIFIER_ADDR,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'bolyra+jwt' })
      .setSubject(HUMAN_NULL)
      .setIssuedAt(now)
      .setExpirationTime(now + 7200) // 2 hours > max 3600
      .setIssuer('did:bolyra:relayer')
      .sign(keyPair.privateKey);

    try {
      await verifySessionToken(badToken, keyPair.publicKey);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(BolyraSessionTokenError);
      expect((err as BolyraSessionTokenError).code).to.equal('TTL_EXCEEDED');
    }
  });

  // ─── Test Vector 10: Missing required claim ───────────────────────────────
  it('(10) should reject a token missing a required claim', async () => {
    const badToken = await new SignJWT({
      humanNullifier: HUMAN_NULL,
      // agentNullifier is missing
      sessionNonce: SESSION_NONCE,
      scopeCommitment: SCOPE_COMMIT,
      delegationChain: [],
      chainId: 84532,
      verifierContract: VERIFIER_ADDR,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'bolyra+jwt' })
      .setSubject(HUMAN_NULL)
      .setIssuedAt()
      .setExpirationTime('5m')
      .setIssuer('did:bolyra:relayer')
      .sign(keyPair.privateKey);

    try {
      await verifySessionToken(badToken, keyPair.publicKey);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(BolyraSessionTokenError);
      expect((err as BolyraSessionTokenError).code).to.equal('MISSING_CLAIMS');
    }
  });

  // ─── Test Vector 11: Future iat rejection ──────────────────────────────────
  it('(11) should reject a token with iat too far in the future', async () => {
    const futureIat = Math.floor(Date.now() / 1000) + 300; // 5 min in future
    const badToken = await new SignJWT({
      humanNullifier: HUMAN_NULL,
      agentNullifier: AGENT_NULL,
      sessionNonce: SESSION_NONCE,
      scopeCommitment: SCOPE_COMMIT,
      delegationChain: [],
      chainId: 84532,
      verifierContract: VERIFIER_ADDR,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'bolyra+jwt' })
      .setSubject(HUMAN_NULL)
      .setIssuedAt(futureIat)
      .setExpirationTime(futureIat + 300)
      .setIssuer('did:bolyra:relayer')
      .sign(keyPair.privateKey);

    try {
      await verifySessionToken(badToken, keyPair.publicKey);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(BolyraSessionTokenError);
      expect((err as BolyraSessionTokenError).code).to.equal('FUTURE_IAT');
    }
  });

  // ─── Test Vector 12: Unverified handshake rejection ───────────────────────
  it('(12) should reject issuing a token for unverified handshake', async () => {
    try {
      await issueSessionToken(
        mockHandshake({ verified: false }),
        keyPair.privateKey,
        DEFAULT_OPTS,
      );
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(BolyraSessionTokenError);
      expect((err as BolyraSessionTokenError).code).to.equal('UNVERIFIED_HANDSHAKE');
    }
  });

  // ─── Test Vector 13: TTL at exact maximum boundary ────────────────────────
  it('(13) should accept a token with TTL exactly at 3600s', async () => {
    const token = await issueSessionToken(mockHandshake(), keyPair.privateKey, {
      ...DEFAULT_OPTS,
      ttlSeconds: 3600,
    });

    const result = await verifySessionToken(token, keyPair.publicKey);
    expect(result.active).to.be.true;
    expect(result.remainingSeconds).to.be.greaterThan(3500);
  });

  // ─── Test Vector 14: Default TTL is 300s ──────────────────────────────────
  it('(14) should default to 300s TTL', async () => {
    const token = await issueSessionToken(mockHandshake(), keyPair.privateKey, DEFAULT_OPTS);
    const result = await verifySessionToken(token, keyPair.publicKey);

    const now = Math.floor(Date.now() / 1000);
    const ttl = result.payload.exp - result.payload.iat;
    expect(ttl).to.equal(300);
  });

  // ─── Test Vector 15: Issuer validation ────────────────────────────────────
  it('(15) should reject token with wrong issuer when expectedIssuer is set', async () => {
    const token = await issueSessionToken(mockHandshake(), keyPair.privateKey, {
      ...DEFAULT_OPTS,
      issuer: 'did:bolyra:relayer:alpha',
    });

    try {
      await verifySessionToken(token, keyPair.publicKey, 'did:bolyra:relayer:beta');
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(BolyraSessionTokenError);
      expect((err as BolyraSessionTokenError).code).to.equal('INVALID_SIGNATURE');
    }
  });

  // ─── Test Vector 16: TTL below minimum rejected ───────────────────────────
  it('(16) should reject TTL below minimum (30s)', async () => {
    try {
      await issueSessionToken(mockHandshake(), keyPair.privateKey, {
        ...DEFAULT_OPTS,
        ttlSeconds: 10,
      });
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(BolyraSessionTokenError);
      expect((err as BolyraSessionTokenError).code).to.equal('TTL_EXCEEDED');
    }
  });

  // ─── Test Vector 17: Signed with different key rejected ───────────────────
  it('(17) should reject a token signed with a different key', async () => {
    const otherKeyPair = await generateKeyPair('ES256');
    const token = await issueSessionToken(mockHandshake(), otherKeyPair.privateKey, DEFAULT_OPTS);

    try {
      await verifySessionToken(token, keyPair.publicKey);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(BolyraSessionTokenError);
      expect((err as BolyraSessionTokenError).code).to.equal('INVALID_SIGNATURE');
    }
  });
});

import { expect } from 'chai';
import { SignJWT, generateKeyPair, type GenerateKeyPairResult, type JWTHeaderParameters } from 'jose';
import { randomUUID } from 'crypto';
import {
  encodeSessionToken,
  verifySessionToken,
  SessionTokenError,
} from '../src/sessionToken.js';
import type { HandshakeResult } from '../src/sessionToken.js';

// ── Fixtures ─────────────────────────────────────────────────────────────────

const NULL_HASH = '0xaabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344';
const SCOPE_COMMIT = '0x00000000000000000000000000000000000000000000000000000000000000ff';
const SESSION_NONCE = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
const MERKLE_ROOT = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
const REGISTRY_ADDR = '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC';
const CHAIN_ID = 84532;

function mockHandshake(overrides: Partial<HandshakeResult> = {}): HandshakeResult {
  return {
    nullifierHash: NULL_HASH,
    scopeCommitment: SCOPE_COMMIT,
    sessionNonce: SESSION_NONCE,
    registryAddress: REGISTRY_ADDR,
    humanMerkleRoot: MERKLE_ROOT,
    verified: true,
    ...overrides,
  };
}

// Helper to build a raw JWT for negative tests
async function rawJWT(
  privateKey: CryptoKey,
  payloadOverrides: Record<string, unknown> = {},
  headerOverrides: Record<string, unknown> = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: NULL_HASH,
    iss: REGISTRY_ADDR,
    scope: Buffer.from(SCOPE_COMMIT.slice(2), 'hex').toString('base64url'),
    nonce: SESSION_NONCE,
    bolyra_root: MERKLE_ROOT,
    jti: randomUUID(),
    ...payloadOverrides,
  };

  const header: JWTHeaderParameters = {
    alg: 'ES256',
    typ: 'JWT',
    'x-bolyra-registry': REGISTRY_ADDR,
    'x-bolyra-chain-id': CHAIN_ID,
    ...headerOverrides,
  } as JWTHeaderParameters;

  return new SignJWT(payload as any)
    .setProtectedHeader(header)
    .setIssuedAt(now)
    .setExpirationTime(now + 900)
    .sign(privateKey);
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('Bolyra Session Token (JWT)', () => {
  let keyPair: GenerateKeyPairResult;

  before(async () => {
    keyPair = await generateKeyPair('ES256');
  });

  // ─── 1. Roundtrip encode/verify ──────────────────────────────────────────
  it('should encode and verify a valid session token', async () => {
    const token = await encodeSessionToken(
      mockHandshake(),
      keyPair.privateKey,
      900,
      CHAIN_ID,
    );
    expect(token.split('.')).to.have.length(3);

    const claims = await verifySessionToken(
      token,
      keyPair.publicKey,
      REGISTRY_ADDR,
      CHAIN_ID,
    );

    expect(claims.sub).to.equal(NULL_HASH);
    expect(claims.nonce).to.equal(SESSION_NONCE);
    expect(claims.bolyra_root).to.equal(MERKLE_ROOT);
    expect(claims.iss).to.equal(REGISTRY_ADDR);
    expect(claims.registry).to.equal(REGISTRY_ADDR);
    expect(claims.chainId).to.equal(CHAIN_ID);
    expect(claims.jti).to.be.a('string').with.length.greaterThan(0);
    expect(claims.scope).to.be.a('string').with.length.greaterThan(0);
  });

  // ─── 2. Expired token rejection ──────────────────────────────────────────
  it('should reject an expired token', async () => {
    const now = Math.floor(Date.now() / 1000);
    const pastIat = now - 1000;

    const token = await rawJWT(keyPair.privateKey, {
      iat: pastIat,
      exp: pastIat + 60,
    }, {});

    // Override exp by re-creating with past exp
    const expiredToken = await new SignJWT({
      sub: NULL_HASH,
      iss: REGISTRY_ADDR,
      scope: Buffer.from(SCOPE_COMMIT.slice(2), 'hex').toString('base64url'),
      nonce: SESSION_NONCE,
      bolyra_root: MERKLE_ROOT,
      jti: randomUUID(),
    } as any)
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'JWT',
        'x-bolyra-registry': REGISTRY_ADDR,
        'x-bolyra-chain-id': CHAIN_ID,
      } as JWTHeaderParameters)
      .setIssuedAt(pastIat)
      .setExpirationTime(pastIat + 60)
      .sign(keyPair.privateKey);

    try {
      await verifySessionToken(expiredToken, keyPair.publicKey, REGISTRY_ADDR, CHAIN_ID);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(SessionTokenError);
      expect((err as SessionTokenError).code).to.equal('TOKEN_EXPIRED');
    }
  });

  // ─── 3. Wrong registry rejection ─────────────────────────────────────────
  it('should reject a token with wrong registry address', async () => {
    const token = await encodeSessionToken(
      mockHandshake(),
      keyPair.privateKey,
      900,
      CHAIN_ID,
    );

    try {
      await verifySessionToken(
        token,
        keyPair.publicKey,
        '0x0000000000000000000000000000000000000001',
        CHAIN_ID,
      );
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(SessionTokenError);
      expect((err as SessionTokenError).code).to.equal('REGISTRY_MISMATCH');
    }
  });

  // ─── 4. Tampered claim rejection ─────────────────────────────────────────
  it('should reject a token with tampered payload (bad signature)', async () => {
    const token = await encodeSessionToken(
      mockHandshake(),
      keyPair.privateKey,
      900,
      CHAIN_ID,
    );

    // Flip a byte in the payload
    const parts = token.split('.');
    const payloadBytes = Buffer.from(parts[1], 'base64url');
    const payloadObj = JSON.parse(payloadBytes.toString());
    payloadObj.sub = '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
    const tampered = [
      parts[0],
      Buffer.from(JSON.stringify(payloadObj)).toString('base64url'),
      parts[2],
    ].join('.');

    try {
      await verifySessionToken(tampered, keyPair.publicKey, REGISTRY_ADDR, CHAIN_ID);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(SessionTokenError);
      expect((err as SessionTokenError).code).to.equal('INVALID_SIGNATURE');
    }
  });

  // ─── 5. Nonce mismatch / present check ───────────────────────────────────
  it('should include nonce in claims and reject missing nonce', async () => {
    const token = await encodeSessionToken(
      mockHandshake(),
      keyPair.privateKey,
    );
    const claims = await verifySessionToken(token, keyPair.publicKey, REGISTRY_ADDR, CHAIN_ID);
    expect(claims.nonce).to.equal(SESSION_NONCE);

    // Token with missing nonce
    const badToken = await rawJWT(keyPair.privateKey, { nonce: undefined });
    // Remove nonce from payload — need to rebuild
    const noNonceToken = await new SignJWT({
      sub: NULL_HASH,
      iss: REGISTRY_ADDR,
      scope: Buffer.from(SCOPE_COMMIT.slice(2), 'hex').toString('base64url'),
      bolyra_root: MERKLE_ROOT,
      jti: randomUUID(),
    } as any)
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'JWT',
        'x-bolyra-registry': REGISTRY_ADDR,
        'x-bolyra-chain-id': CHAIN_ID,
      } as JWTHeaderParameters)
      .setIssuedAt()
      .setExpirationTime('15m')
      .sign(keyPair.privateKey);

    try {
      await verifySessionToken(noNonceToken, keyPair.publicKey, REGISTRY_ADDR, CHAIN_ID);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(SessionTokenError);
      expect((err as SessionTokenError).code).to.equal('MISSING_CLAIMS');
    }
  });

  // ─── 6. Scope commitment integrity ──────────────────────────────────────
  it('should encode scopeCommitment as base64url and roundtrip correctly', async () => {
    const token = await encodeSessionToken(
      mockHandshake(),
      keyPair.privateKey,
    );
    const claims = await verifySessionToken(token, keyPair.publicKey, REGISTRY_ADDR, CHAIN_ID);

    // Decode scope back to hex and compare
    const decoded = Buffer.from(claims.scope, 'base64url');
    const hex = '0x' + decoded.toString('hex').padStart(64, '0');
    expect(hex).to.equal(SCOPE_COMMIT);
  });

  // ─── 7. Unverified handshake rejection ───────────────────────────────────
  it('should reject encoding an unverified handshake', async () => {
    try {
      await encodeSessionToken(
        mockHandshake({ verified: false }),
        keyPair.privateKey,
      );
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(SessionTokenError);
      expect((err as SessionTokenError).code).to.equal('UNVERIFIED_HANDSHAKE');
    }
  });

  // ─── 8. TTL boundary — too high ──────────────────────────────────────────
  it('should reject TTL above 3600 seconds', async () => {
    try {
      await encodeSessionToken(mockHandshake(), keyPair.privateKey, 7200);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(SessionTokenError);
      expect((err as SessionTokenError).code).to.equal('TTL_EXCEEDED');
    }
  });

  // ─── 9. TTL boundary — too low ───────────────────────────────────────────
  it('should reject TTL below 60 seconds', async () => {
    try {
      await encodeSessionToken(mockHandshake(), keyPair.privateKey, 10);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(SessionTokenError);
      expect((err as SessionTokenError).code).to.equal('TTL_EXCEEDED');
    }
  });

  // ─── 10. Wrong chain ID ──────────────────────────────────────────────────
  it('should reject a token with wrong chain ID', async () => {
    const token = await encodeSessionToken(
      mockHandshake(),
      keyPair.privateKey,
      900,
      CHAIN_ID,
    );

    try {
      await verifySessionToken(token, keyPair.publicKey, REGISTRY_ADDR, 1); // mainnet
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(SessionTokenError);
      expect((err as SessionTokenError).code).to.equal('CHAIN_ID_MISMATCH');
    }
  });

  // ─── 11. Wrong signing key ───────────────────────────────────────────────
  it('should reject a token signed with a different key', async () => {
    const otherKeyPair = await generateKeyPair('ES256');
    const token = await encodeSessionToken(
      mockHandshake(),
      otherKeyPair.privateKey,
      900,
      CHAIN_ID,
    );

    try {
      await verifySessionToken(token, keyPair.publicKey, REGISTRY_ADDR, CHAIN_ID);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(SessionTokenError);
      expect((err as SessionTokenError).code).to.equal('INVALID_SIGNATURE');
    }
  });

  // ─── 12. Future iat rejection ────────────────────────────────────────────
  it('should reject a token with iat too far in the future', async () => {
    const futureIat = Math.floor(Date.now() / 1000) + 300;
    const badToken = await new SignJWT({
      sub: NULL_HASH,
      iss: REGISTRY_ADDR,
      scope: Buffer.from(SCOPE_COMMIT.slice(2), 'hex').toString('base64url'),
      nonce: SESSION_NONCE,
      bolyra_root: MERKLE_ROOT,
      jti: randomUUID(),
    } as any)
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'JWT',
        'x-bolyra-registry': REGISTRY_ADDR,
        'x-bolyra-chain-id': CHAIN_ID,
      } as JWTHeaderParameters)
      .setIssuedAt(futureIat)
      .setExpirationTime(futureIat + 900)
      .sign(keyPair.privateKey);

    try {
      await verifySessionToken(badToken, keyPair.publicKey, REGISTRY_ADDR, CHAIN_ID);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(SessionTokenError);
      expect((err as SessionTokenError).code).to.equal('FUTURE_IAT');
    }
  });

  // ─── 13. Default TTL is 900s ─────────────────────────────────────────────
  it('should default to 900s TTL (15 minutes)', async () => {
    const token = await encodeSessionToken(mockHandshake(), keyPair.privateKey);
    const claims = await verifySessionToken(token, keyPair.publicKey, REGISTRY_ADDR, CHAIN_ID);
    const ttl = claims.exp - claims.iat;
    expect(ttl).to.equal(900);
  });

  // ─── 14. jti is present and unique ───────────────────────────────────────
  it('should generate unique jti for each token', async () => {
    const token1 = await encodeSessionToken(mockHandshake(), keyPair.privateKey);
    const token2 = await encodeSessionToken(mockHandshake(), keyPair.privateKey);
    const claims1 = await verifySessionToken(token1, keyPair.publicKey, REGISTRY_ADDR, CHAIN_ID);
    const claims2 = await verifySessionToken(token2, keyPair.publicKey, REGISTRY_ADDR, CHAIN_ID);
    expect(claims1.jti).to.not.equal(claims2.jti);
  });
});

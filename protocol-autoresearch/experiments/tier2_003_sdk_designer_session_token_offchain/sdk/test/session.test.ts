import { expect } from 'chai';
import { randomBytes } from 'crypto';
import {
  issueSessionToken,
  verifySessionToken,
  BolyraSessionError,
} from '../src/session.js';
import type { HandshakeResult } from '../src/session.js';

function makeHandshake(overrides: Partial<HandshakeResult> = {}): HandshakeResult {
  return {
    humanProof: {
      nullifierHash: BigInt('0xaabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344'),
      humanMerkleRoot: BigInt('0x1111111111111111111111111111111111111111111111111111111111111111'),
    },
    agentProof: {
      nullifierHash: BigInt('0x2222222222222222222222222222222222222222222222222222222222222222'),
      permissions: 0b00000111,
    },
    sessionNonce: BigInt('0xdeadbeef'),
    verified: true,
    scopeCommitment: BigInt('0x3333333333333333'),
    agentCredentialHash: BigInt('0x4444444444444444'),
    ...overrides,
  } as HandshakeResult;
}

function makeSecret(): Uint8Array {
  return randomBytes(32);
}

describe('SD-JWT Session Token', () => {
  const secret = makeSecret();

  describe('issueSessionToken', () => {
    it('should produce an SD-JWT with tilde-separated disclosures', () => {
      const result = makeHandshake();
      const token = issueSessionToken(result, secret);
      const parts = token.split('~');
      // JWT part + at least 1 disclosure + trailing empty string
      expect(parts.length).to.be.greaterThan(2);
      // JWT part has 3 dot-separated segments
      expect(parts[0].split('.')).to.have.length(3);
    });

    it('should reject minting from an unverified handshake', () => {
      const result = makeHandshake({ verified: false });
      expect(() => issueSessionToken(result, secret)).to.throw(
        BolyraSessionError,
        /unverified/i,
      );
    });

    it('should reject TTL below minimum (60s)', () => {
      const result = makeHandshake();
      expect(() =>
        issueSessionToken(result, secret, { ttlSeconds: 30 }),
      ).to.throw(BolyraSessionError, /60/);
    });

    it('should reject TTL above maximum (3600s)', () => {
      const result = makeHandshake();
      expect(() =>
        issueSessionToken(result, secret, { ttlSeconds: 7200 }),
      ).to.throw(BolyraSessionError, /3600/);
    });
  });

  describe('verifySessionToken', () => {
    it('should round-trip: issue then verify returns correct claims', () => {
      const result = makeHandshake();
      const token = issueSessionToken(result, secret);
      const claims = verifySessionToken(token, secret);

      expect(claims.nullifierHash).to.equal(
        '0x' + result.humanProof.nullifierHash.toString(16),
      );
      expect(claims.iss).to.equal('bolyra.ai');
      expect(claims.exp - claims.iat).to.equal(300);
    });

    it('should respect custom TTL', () => {
      const result = makeHandshake();
      const token = issueSessionToken(result, secret, { ttlSeconds: 120 });
      const claims = verifySessionToken(token, secret);
      expect(claims.exp - claims.iat).to.equal(120);
    });

    it('should reject an expired token', () => {
      const result = makeHandshake();
      // Mint with TTL=60, then manipulate: we can't easily expire,
      // so we test by verifying with a token that has exp in the past.
      // Instead, use clockToleranceSec trick: mint with min TTL,
      // then verify with a large negative tolerance won't work.
      // Best approach: just mint normally and check that a tampered exp fails.
      const token = issueSessionToken(result, secret, { ttlSeconds: 60 });
      // Tamper with the payload to set exp in the past
      const parts = token.split('~');
      const jwtParts = parts[0].split('.');
      // Decode payload, set exp to past
      let s = jwtParts[1].replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4 !== 0) s += '=';
      const payload = JSON.parse(Buffer.from(s, 'base64').toString());
      payload.exp = Math.floor(Date.now() / 1000) - 100;
      const newPayloadB64 = Buffer.from(JSON.stringify(payload))
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
      // Re-sign with correct secret to test expiry (not signature)
      const { createHmac: hm } = require('crypto');
      const sigInput = `${jwtParts[0]}.${newPayloadB64}`;
      const sig = hm('sha256', secret).update(sigInput).digest()
        .toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const expiredJwt = `${sigInput}.${sig}`;
      const expiredToken = `${expiredJwt}~${parts.slice(1).join('~')}`;

      expect(() => verifySessionToken(expiredToken, secret)).to.throw(
        BolyraSessionError,
        /expired/i,
      );
    });

    it('should reject a tampered signature', () => {
      const result = makeHandshake();
      const token = issueSessionToken(result, secret);
      const wrongSecret = makeSecret();
      expect(() => verifySessionToken(token, wrongSecret)).to.throw(
        BolyraSessionError,
        /signature/i,
      );
    });

    it('should support selective disclosure: only nullifierHash', () => {
      const result = makeHandshake();
      const token = issueSessionToken(result, secret, {
        disclose: ['nullifierHash'],
      });
      const claims = verifySessionToken(token, secret);

      expect(claims.nullifierHash).to.be.a('string');
      expect(claims.scopeCommitment).to.be.undefined;
      expect(claims.humanMerkleRoot).to.be.undefined;
      expect(claims.agentCredentialHash).to.be.undefined;
    });

    it('should enforce requiredClaims', () => {
      const result = makeHandshake();
      // Only disclose nullifierHash
      const token = issueSessionToken(result, secret, {
        disclose: ['nullifierHash'],
      });
      // Require scopeCommitment which was not disclosed
      expect(() =>
        verifySessionToken(token, secret, {
          requiredClaims: ['scopeCommitment'],
        }),
      ).to.throw(BolyraSessionError, /scopeCommitment/);
    });

    it('should accept clock tolerance for near-expiry tokens', () => {
      const result = makeHandshake();
      const token = issueSessionToken(result, secret, { ttlSeconds: 60 });
      // Should pass with default tolerance
      const claims = verifySessionToken(token, secret, {
        clockToleranceSec: 5,
      });
      expect(claims.iss).to.equal('bolyra.ai');
    });

    it('should reject a disclosure with invalid digest', () => {
      const result = makeHandshake();
      const token = issueSessionToken(result, secret);
      // Append a fake disclosure
      const fakeDisc = Buffer.from(JSON.stringify(['fakesalt', 'fakeKey', 'fakeVal']))
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
      const tampered = token.slice(0, -1) + fakeDisc + '~';
      expect(() => verifySessionToken(tampered, secret)).to.throw(
        BolyraSessionError,
        /digest/i,
      );
    });
  });
});

import { expect } from 'chai';
import { randomBytes, createHmac, createHash } from 'crypto';
import { SessionTokenIssuer } from '../../src/session/SessionTokenIssuer.js';
import { SessionTokenVerifier } from '../../src/session/SessionTokenVerifier.js';
import {
  SessionTokenExpiredError,
  SessionTokenInvalidError,
  SessionTokenClaimMissingError,
} from '../../src/session/errors.js';
import type { HandshakeResult } from '../../src/session/types.js';

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function makeHandshake(): HandshakeResult {
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
  };
}

describe('SessionTokenVerifier', () => {
  const secret = randomBytes(32);

  describe('verify() — valid token', () => {
    it('should decode a valid token and return correct claims', () => {
      const hs = makeHandshake();
      const token = SessionTokenIssuer.mint(hs, { signingKey: secret });
      const payload = SessionTokenVerifier.verify(token, { signingKey: secret });

      expect(payload.nullifierHash).to.equal(
        '0x' + hs.humanProof.nullifierHash.toString(16),
      );
      expect(payload.humanMerkleRoot).to.equal(
        '0x' + hs.humanProof.humanMerkleRoot.toString(16),
      );
      expect(payload.iss).to.equal('bolyra.ai');
      expect(payload.exp - payload.iat).to.equal(300);
    });
  });

  describe('verify() — expired token', () => {
    it('should throw SessionTokenExpiredError for an expired token', () => {
      const hs = makeHandshake();
      const token = SessionTokenIssuer.mint(hs, { signingKey: secret, ttl: 60 });

      // Forge an expired version by re-signing with exp in the past
      const parts = token.split('~');
      const jwtParts = parts[0].split('.');
      let s = jwtParts[1].replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4 !== 0) s += '=';
      const payload = JSON.parse(Buffer.from(s, 'base64').toString());
      payload.exp = Math.floor(Date.now() / 1000) - 200; // well in the past
      const newPayloadB64 = b64url(Buffer.from(JSON.stringify(payload)));
      const sigInput = `${jwtParts[0]}.${newPayloadB64}`;
      const sig = b64url(createHmac('sha256', secret).update(sigInput).digest());
      const expiredToken = `${sigInput}.${sig}~${parts.slice(1).join('~')}`;

      expect(() =>
        SessionTokenVerifier.verify(expiredToken, { signingKey: secret, clockSkew: 0 }),
      ).to.throw(SessionTokenExpiredError);
    });
  });

  describe('verify() — tampered signature', () => {
    it('should throw SessionTokenInvalidError for wrong key', () => {
      const token = SessionTokenIssuer.mint(makeHandshake(), { signingKey: secret });
      const wrongSecret = randomBytes(32);

      expect(() =>
        SessionTokenVerifier.verify(token, { signingKey: wrongSecret }),
      ).to.throw(SessionTokenInvalidError, /signature/i);
    });
  });

  describe('verify() — missing required claims', () => {
    it('should throw SessionTokenClaimMissingError when required claim not disclosed', () => {
      const token = SessionTokenIssuer.mint(makeHandshake(), {
        signingKey: secret,
        selectiveDisclosureFields: ['nullifierHash'],
      });

      expect(() =>
        SessionTokenVerifier.verify(token, {
          signingKey: secret,
          requiredClaims: ['scopeCommitment'],
        }),
      ).to.throw(SessionTokenClaimMissingError, /scopeCommitment/);
    });
  });

  describe('verify() — clock skew tolerance', () => {
    it('should accept a nearly-expired token within clock skew', () => {
      const hs = makeHandshake();
      const token = SessionTokenIssuer.mint(hs, { signingKey: secret, ttl: 60 });

      // Forge token that expired 10s ago
      const parts = token.split('~');
      const jwtParts = parts[0].split('.');
      let s = jwtParts[1].replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4 !== 0) s += '=';
      const payload = JSON.parse(Buffer.from(s, 'base64').toString());
      payload.exp = Math.floor(Date.now() / 1000) - 10;
      const newPayloadB64 = b64url(Buffer.from(JSON.stringify(payload)));
      const sigInput = `${jwtParts[0]}.${newPayloadB64}`;
      const sig = b64url(createHmac('sha256', secret).update(sigInput).digest());
      const nearExpiredToken = `${sigInput}.${sig}~${parts.slice(1).join('~')}`;

      // With 30s default clock skew, this should pass
      const result = SessionTokenVerifier.verify(nearExpiredToken, {
        signingKey: secret,
      });
      expect(result.iss).to.equal('bolyra.ai');
    });

    it('should reject a token beyond clock skew tolerance', () => {
      const hs = makeHandshake();
      const token = SessionTokenIssuer.mint(hs, { signingKey: secret, ttl: 60 });

      // Forge token that expired 60s ago
      const parts = token.split('~');
      const jwtParts = parts[0].split('.');
      let s = jwtParts[1].replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4 !== 0) s += '=';
      const payload = JSON.parse(Buffer.from(s, 'base64').toString());
      payload.exp = Math.floor(Date.now() / 1000) - 60;
      const newPayloadB64 = b64url(Buffer.from(JSON.stringify(payload)));
      const sigInput = `${jwtParts[0]}.${newPayloadB64}`;
      const sig = b64url(createHmac('sha256', secret).update(sigInput).digest());
      const expiredToken = `${sigInput}.${sig}~${parts.slice(1).join('~')}`;

      // With default 30s clock skew, 60s past should fail
      expect(() =>
        SessionTokenVerifier.verify(expiredToken, { signingKey: secret }),
      ).to.throw(SessionTokenExpiredError);
    });
  });

  describe('verify() — disclosure integrity', () => {
    it('should reject a forged disclosure', () => {
      const token = SessionTokenIssuer.mint(makeHandshake(), { signingKey: secret });
      const fakeDisc = b64url(
        Buffer.from(JSON.stringify(['fakesalt', 'fakeKey', 'fakeVal'])),
      );
      const tampered = token.slice(0, -1) + fakeDisc + '~';

      expect(() =>
        SessionTokenVerifier.verify(tampered, { signingKey: secret }),
      ).to.throw(SessionTokenInvalidError, /digest/i);
    });
  });
});

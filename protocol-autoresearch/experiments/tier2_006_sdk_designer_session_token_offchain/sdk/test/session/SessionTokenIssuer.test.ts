import { expect } from 'chai';
import { randomBytes } from 'crypto';
import { SessionTokenIssuer } from '../../src/session/SessionTokenIssuer.js';
import { SessionTokenInvalidError } from '../../src/session/errors.js';
import type { HandshakeResult, SessionTokenOptions } from '../../src/session/types.js';

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
  };
}

function makeOpts(overrides: Partial<SessionTokenOptions> = {}): SessionTokenOptions {
  return {
    signingKey: randomBytes(32),
    ...overrides,
  };
}

describe('SessionTokenIssuer', () => {
  describe('mint()', () => {
    it('should return a compact SD-JWT with tilde-separated disclosures', () => {
      const token = SessionTokenIssuer.mint(makeHandshake(), makeOpts());
      const parts = token.split('~');
      // JWT part + at least 1 disclosure + trailing empty string
      expect(parts.length).to.be.greaterThan(2);
      // JWT has 3 dot-separated segments
      expect(parts[0].split('.')).to.have.length(3);
    });

    it('should include sd+jwt type in header', () => {
      const token = SessionTokenIssuer.mint(makeHandshake(), makeOpts());
      const headerB64 = token.split('.')[0];
      let s = headerB64.replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4 !== 0) s += '=';
      const header = JSON.parse(Buffer.from(s, 'base64').toString());
      expect(header.typ).to.equal('sd+jwt');
      expect(header.alg).to.equal('HS256');
    });

    it('should default TTL to 300s', () => {
      const secret = randomBytes(32);
      const token = SessionTokenIssuer.mint(makeHandshake(), makeOpts({ signingKey: secret }));
      const jwtPart = token.split('~')[0];
      const payloadB64 = jwtPart.split('.')[1];
      let s = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4 !== 0) s += '=';
      const payload = JSON.parse(Buffer.from(s, 'base64').toString());
      expect(payload.exp - payload.iat).to.equal(300);
    });

    it('should respect custom TTL', () => {
      const secret = randomBytes(32);
      const token = SessionTokenIssuer.mint(
        makeHandshake(),
        makeOpts({ signingKey: secret, ttl: 120 }),
      );
      const jwtPart = token.split('~')[0];
      const payloadB64 = jwtPart.split('.')[1];
      let s = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4 !== 0) s += '=';
      const payload = JSON.parse(Buffer.from(s, 'base64').toString());
      expect(payload.exp - payload.iat).to.equal(120);
    });

    it('should reject TTL below 60s', () => {
      expect(() =>
        SessionTokenIssuer.mint(makeHandshake(), makeOpts({ ttl: 59 })),
      ).to.throw(SessionTokenInvalidError, /60/);
    });

    it('should reject TTL above 3600s', () => {
      expect(() =>
        SessionTokenIssuer.mint(makeHandshake(), makeOpts({ ttl: 7200 })),
      ).to.throw(SessionTokenInvalidError, /3600/);
    });

    it('should reject unverified handshake', () => {
      expect(() =>
        SessionTokenIssuer.mint(
          makeHandshake({ verified: false }),
          makeOpts(),
        ),
      ).to.throw(SessionTokenInvalidError, /unverified/i);
    });

    it('should bind nullifierHash and scopeCommitment correctly', () => {
      const hs = makeHandshake();
      const secret = randomBytes(32);
      const token = SessionTokenIssuer.mint(hs, makeOpts({ signingKey: secret }));
      // Decode disclosures
      const parts = token.split('~').filter((p) => p.length > 0);
      const disclosures = parts.slice(1);
      const claims: Record<string, string> = {};
      for (const disc of disclosures) {
        let s = disc.replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4 !== 0) s += '=';
        const arr = JSON.parse(Buffer.from(s, 'base64').toString());
        claims[arr[1]] = arr[2];
      }
      expect(claims.nullifierHash).to.equal(
        '0x' + hs.humanProof.nullifierHash.toString(16),
      );
      expect(claims.scopeCommitment).to.equal(
        '0x' + hs.scopeCommitment!.toString(16),
      );
    });

    it('should support selective disclosure of only specified fields', () => {
      const secret = randomBytes(32);
      const token = SessionTokenIssuer.mint(
        makeHandshake(),
        makeOpts({
          signingKey: secret,
          selectiveDisclosureFields: ['nullifierHash'],
        }),
      );
      const parts = token.split('~').filter((p) => p.length > 0);
      // JWT + exactly 1 disclosure
      expect(parts.length).to.equal(2);
    });

    it('should include audience when specified', () => {
      const secret = randomBytes(32);
      const token = SessionTokenIssuer.mint(
        makeHandshake(),
        makeOpts({ signingKey: secret, audience: 'api.example.com' }),
      );
      const jwtPart = token.split('~')[0];
      const payloadB64 = jwtPart.split('.')[1];
      let s = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4 !== 0) s += '=';
      const payload = JSON.parse(Buffer.from(s, 'base64').toString());
      expect(payload.aud).to.equal('api.example.com');
    });
  });
});

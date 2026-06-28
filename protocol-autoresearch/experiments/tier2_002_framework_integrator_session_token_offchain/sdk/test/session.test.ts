import { expect } from 'chai';
import {
  mintSessionToken,
  verifySessionToken,
  revokeSessionToken,
  computeSessionRoot,
  BolyraSessionError,
  _resetRevocationSet,
} from '../src/session.js';
import type { VerifiedHandshake } from '../src/session.js';

function makeHandshake(overrides: Partial<VerifiedHandshake> = {}): VerifiedHandshake {
  return {
    humanProof: Buffer.from('human-proof-bytes-for-testing'),
    agentProof: Buffer.from('agent-proof-bytes-for-testing'),
    humanNullifier: 'aabbccdd',
    agentCredHash: '11223344',
    scopeBitmap: 0b00000111, // READ_DATA + WRITE_DATA + FINANCIAL_SMALL
    valid: true,
    ...overrides,
  };
}

describe('Session Tokens', () => {
  beforeEach(() => {
    _resetRevocationSet();
  });

  describe('mintSessionToken', () => {
    it('should produce a valid JWT string with three dot-separated parts', () => {
      const hs = makeHandshake();
      const token = mintSessionToken(hs.humanProof, hs.agentProof, hs, {});
      const parts = token.split('.');
      expect(parts).to.have.length(3);
    });

    it('should reject minting from an invalid handshake', () => {
      const hs = makeHandshake({ valid: false });
      expect(() => mintSessionToken(hs.humanProof, hs.agentProof, hs)).to.throw(
        BolyraSessionError,
        /invalid handshake/i,
      );
    });

    it('should apply scope narrowing via scopeOverride', () => {
      const hs = makeHandshake({ scopeBitmap: 0b00000111 });
      // Narrow to READ_DATA only
      const token = mintSessionToken(hs.humanProof, hs.agentProof, hs, {
        scopeOverride: 0b00000001,
      });
      const payload = verifySessionToken(token);
      expect(payload.scopeBitmap).to.equal(0b00000001);
    });

    it('should reject scope elevation (superset of handshake scope)', () => {
      const hs = makeHandshake({ scopeBitmap: 0b00000001 }); // READ_DATA only
      expect(() =>
        mintSessionToken(hs.humanProof, hs.agentProof, hs, {
          scopeOverride: 0b00000111, // tries to add WRITE + FINANCIAL_SMALL
        }),
      ).to.throw(BolyraSessionError, /not a subset/i);
    });

    it('should reject scopeOverride violating cumulative-bit rules', () => {
      // bit 4 (FINANCIAL_UNLIMITED) implies bits 2+3 — setting bit 4 alone is invalid
      const hs = makeHandshake({ scopeBitmap: 0b00011111 });
      expect(() =>
        mintSessionToken(hs.humanProof, hs.agentProof, hs, {
          scopeOverride: 0b00010001, // bit 4 + bit 0, missing bits 2+3
        }),
      ).to.throw(BolyraSessionError, /cumulative-bit/i);
    });
  });

  describe('verifySessionToken', () => {
    it('should accept a freshly minted token', () => {
      const hs = makeHandshake();
      const token = mintSessionToken(hs.humanProof, hs.agentProof, hs);
      const payload = verifySessionToken(token);
      expect(payload.iss).to.equal('bolyra.ai');
      expect(payload.humanNullifier).to.equal('aabbccdd');
      expect(payload.scopeBitmap).to.equal(0b00000111);
    });

    it('should reject an expired token', () => {
      const hs = makeHandshake();
      const token = mintSessionToken(hs.humanProof, hs.agentProof, hs, {
        expirySeconds: -1, // already expired
      });
      expect(() => verifySessionToken(token)).to.throw(BolyraSessionError, /expired/i);
    });

    it('should reject a tampered token', () => {
      const hs = makeHandshake();
      const token = mintSessionToken(hs.humanProof, hs.agentProof, hs);
      // Flip a character in the payload section
      const parts = token.split('.');
      parts[1] = parts[1].slice(0, -1) + (parts[1].slice(-1) === 'A' ? 'B' : 'A');
      const tampered = parts.join('.');
      expect(() => verifySessionToken(tampered)).to.throw(BolyraSessionError);
    });

    it('should reject when required scope is not satisfied', () => {
      const hs = makeHandshake({ scopeBitmap: 0b00000001 }); // READ_DATA only
      const token = mintSessionToken(hs.humanProof, hs.agentProof, hs);
      expect(() => verifySessionToken(token, 0b00000010)).to.throw(
        BolyraSessionError,
        /INSUFFICIENT_SCOPE/,
      );
    });

    it('should accept when required scope is a subset of token scope', () => {
      const hs = makeHandshake({ scopeBitmap: 0b00000111 });
      const token = mintSessionToken(hs.humanProof, hs.agentProof, hs);
      const payload = verifySessionToken(token, 0b00000001); // require READ_DATA
      expect(payload.scopeBitmap).to.equal(0b00000111);
    });
  });

  describe('revokeSessionToken', () => {
    it('should cause subsequent verify to fail', () => {
      const hs = makeHandshake();
      const token = mintSessionToken(hs.humanProof, hs.agentProof, hs);

      // Valid before revocation
      expect(() => verifySessionToken(token)).to.not.throw();

      // Revoke
      revokeSessionToken(token);

      // Fails after revocation
      expect(() => verifySessionToken(token)).to.throw(BolyraSessionError, /revoked/i);
    });

    it('should not affect other tokens', () => {
      const hs = makeHandshake();
      const token1 = mintSessionToken(hs.humanProof, hs.agentProof, hs);
      const token2 = mintSessionToken(hs.humanProof, hs.agentProof, hs);

      revokeSessionToken(token1);

      expect(() => verifySessionToken(token1)).to.throw(BolyraSessionError, /revoked/i);
      expect(() => verifySessionToken(token2)).to.not.throw();
    });
  });

  describe('computeSessionRoot', () => {
    it('should produce a 0x-prefixed 64-char hex string', () => {
      const hs = makeHandshake();
      const t1 = mintSessionToken(hs.humanProof, hs.agentProof, hs);
      const t2 = mintSessionToken(hs.humanProof, hs.agentProof, hs);
      const root = computeSessionRoot([t1, t2]);
      expect(root).to.match(/^0x[0-9a-f]{64}$/);
    });

    it('should be deterministic regardless of input order', () => {
      const hs = makeHandshake();
      const t1 = mintSessionToken(hs.humanProof, hs.agentProof, hs);
      const t2 = mintSessionToken(hs.humanProof, hs.agentProof, hs);
      const root1 = computeSessionRoot([t1, t2]);
      const root2 = computeSessionRoot([t2, t1]);
      expect(root1).to.equal(root2);
    });
  });
});

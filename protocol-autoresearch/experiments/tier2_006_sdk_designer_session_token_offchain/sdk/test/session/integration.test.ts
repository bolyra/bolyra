import { expect } from 'chai';
import { randomBytes } from 'crypto';
import { SessionTokenIssuer } from '../../src/session/SessionTokenIssuer.js';
import { SessionTokenVerifier } from '../../src/session/SessionTokenVerifier.js';
import type { HandshakeResult } from '../../src/session/types.js';

/**
 * End-to-end integration test:
 * verifyHandshake() -> SessionTokenIssuer.mint() -> SessionTokenVerifier.verify()
 *
 * Uses a realistic handshake fixture (mock prover output) to confirm
 * the full mint-verify round-trip without re-proving.
 */
describe('Session Token Integration', () => {
  // Realistic handshake fixture matching verifyHandshake() output
  const handshakeFixture: HandshakeResult = {
    humanProof: {
      nullifierHash: BigInt(
        '0x1a2b3c4d5e6f708192a3b4c5d6e7f80011223344556677889900aabbccddeeff',
      ),
      humanMerkleRoot: BigInt(
        '0x0fedcba9876543210fedcba9876543210fedcba9876543210fedcba987654321',
      ),
    },
    agentProof: {
      nullifierHash: BigInt(
        '0xdeadbeefcafebabe1122334455667788deadbeefcafebabe1122334455667788',
      ),
      permissions: 0b00000111, // READ_DATA | WRITE_DATA | FINANCIAL_SMALL
    },
    sessionNonce: BigInt('0xabcdef0123456789'),
    verified: true,
    scopeCommitment: BigInt('0x9876543210abcdef9876543210abcdef'),
    agentCredentialHash: BigInt('0xfedcba9876543210fedcba9876543210'),
  };

  const sharedSecret = randomBytes(32);

  it('should round-trip: mint then verify with all claims', () => {
    const token = SessionTokenIssuer.mint(handshakeFixture, {
      signingKey: sharedSecret,
      ttl: 300,
      issuer: 'bolyra.ai',
    });

    const payload = SessionTokenVerifier.verify(token, {
      signingKey: sharedSecret,
      requiredClaims: ['nullifierHash', 'scopeCommitment', 'agentId', 'humanMerkleRoot'],
    });

    expect(payload.nullifierHash).to.equal(
      '0x' + handshakeFixture.humanProof.nullifierHash.toString(16),
    );
    expect(payload.scopeCommitment).to.equal(
      '0x' + handshakeFixture.scopeCommitment!.toString(16),
    );
    expect(payload.agentId).to.equal(
      '0x' + handshakeFixture.agentCredentialHash!.toString(16),
    );
    expect(payload.humanMerkleRoot).to.equal(
      '0x' + handshakeFixture.humanProof.humanMerkleRoot.toString(16),
    );
    expect(payload.iss).to.equal('bolyra.ai');
    expect(payload.exp - payload.iat).to.equal(300);
  });

  it('should support selective disclosure in round-trip', () => {
    const token = SessionTokenIssuer.mint(handshakeFixture, {
      signingKey: sharedSecret,
      selectiveDisclosureFields: ['nullifierHash', 'agentId'],
    });

    const payload = SessionTokenVerifier.verify(token, {
      signingKey: sharedSecret,
      requiredClaims: ['nullifierHash', 'agentId'],
    });

    expect(payload.nullifierHash).to.equal(
      '0x' + handshakeFixture.humanProof.nullifierHash.toString(16),
    );
    expect(payload.agentId).to.equal(
      '0x' + handshakeFixture.agentCredentialHash!.toString(16),
    );
    // Non-disclosed claims should be empty
    expect(payload.scopeCommitment).to.equal('');
    expect(payload.humanMerkleRoot).to.equal('');
  });

  it('should support audience binding in round-trip', () => {
    const token = SessionTokenIssuer.mint(handshakeFixture, {
      signingKey: sharedSecret,
      audience: 'api.acme.com',
    });

    const payload = SessionTokenVerifier.verify(token, {
      signingKey: sharedSecret,
    });

    expect(payload.aud).to.equal('api.acme.com');
  });

  it('should allow multiple sequential mints from the same handshake', () => {
    // Simulates reusing the same handshake result for multiple short-lived tokens
    const token1 = SessionTokenIssuer.mint(handshakeFixture, {
      signingKey: sharedSecret,
      ttl: 60,
    });
    const token2 = SessionTokenIssuer.mint(handshakeFixture, {
      signingKey: sharedSecret,
      ttl: 120,
    });

    // Both should verify independently
    const p1 = SessionTokenVerifier.verify(token1, { signingKey: sharedSecret });
    const p2 = SessionTokenVerifier.verify(token2, { signingKey: sharedSecret });

    expect(p1.exp - p1.iat).to.equal(60);
    expect(p2.exp - p2.iat).to.equal(120);
    // Both bind the same nullifierHash
    expect(p1.nullifierHash).to.equal(p2.nullifierHash);
  });

  it('should reject cross-secret verification', () => {
    const token = SessionTokenIssuer.mint(handshakeFixture, {
      signingKey: sharedSecret,
    });
    const differentSecret = randomBytes(32);

    expect(() =>
      SessionTokenVerifier.verify(token, { signingKey: differentSecret }),
    ).to.throw(/signature/i);
  });
});

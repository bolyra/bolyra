import { describe, it, beforeEach } from 'mocha';
import { expect } from 'chai';
import * as sinon from 'sinon';
import { BolyraClient } from '../src/client';
import { ArtifactResolver } from '../src/artifacts';
import { MerkleProofFetcher } from '../src/merkle';
import * as proveModule from '../src/prove';
import * as nonceModule from '../src/nonce';
import type { SessionNonce } from '../src/nonce';

// Mock provider (ethers-like)
const mockProvider = {
  async call() { return '0x'; },
  async getBlockNumber() { return 42; },
};

const MOCK_ARTIFACTS = {
  humanWasm: '/mock/HumanUniqueness.wasm',
  humanZkey: '/mock/HumanUniqueness_final.zkey',
  agentWasm: '/mock/AgentPolicy.wasm',
  agentZkey: '/mock/AgentPolicy_final.zkey',
  delegationWasm: '/mock/Delegation.wasm',
  delegationZkey: '/mock/Delegation_final.zkey',
  humanVkey: '/mock/HumanUniqueness_vkey.json',
  agentVkey: '/mock/AgentPolicy_vkey.json',
  delegationVkey: '/mock/Delegation_vkey.json',
};

const MOCK_MERKLE_PROOF = {
  root: BigInt('12345678901234567890'),
  siblings: [BigInt('111'), BigInt('222'), BigInt('333')],
  pathIndices: [0, 1, 0],
  leafIndex: 5,
};

const MOCK_HUMAN_IDENTITY = {
  identityCommitment: '98765432109876543210',
  secret: 'test-secret',
  nullifier: 'test-nullifier',
  trapdoor: 'test-trapdoor',
};

const MOCK_AGENT_CREDENTIAL = {
  modelHash: 'mock-model-hash',
  operatorPubKey: 'mock-pub-key',
  permissions: 0b00000011,
  expiry: Math.floor(Date.now() / 1000) + 3600,
  signature: 'mock-signature',
};

const MOCK_HUMAN_PROOF = {
  proof: { pi_a: ['1', '2'], pi_b: [['3', '4'], ['5', '6']], pi_c: ['7', '8'] },
  publicSignals: { nullifierHash: 'abc123', humanMerkleRoot: '12345678901234567890', nonceBinding: 'def456' },
};

const MOCK_AGENT_PROOF = {
  proof: { pi_a: ['9', '10'], pi_b: [['11', '12'], ['13', '14']], pi_c: ['15', '16'] },
  publicSignals: { permissionHash: 'perm-hash', expiryBlock: '9999' },
};

describe('BolyraClient', () => {
  let sandbox: sinon.SinonSandbox;

  beforeEach(() => {
    sandbox = sinon.createSandbox();
  });

  afterEach(() => {
    sandbox.restore();
  });

  describe('handshake() — mock proof fast path', () => {
    it('orchestrates full handshake and returns verified result', async () => {
      // Stub ArtifactResolver
      sandbox.stub(ArtifactResolver.prototype, 'resolve').returns(MOCK_ARTIFACTS);

      // Stub MerkleProofFetcher
      sandbox.stub(MerkleProofFetcher.prototype, 'fetch').resolves(MOCK_MERKLE_PROOF);

      // Stub nonce generation
      const fakeNonce = Buffer.alloc(32, 0xab) as SessionNonce;
      sandbox.stub(nonceModule, 'generateSessionNonce').returns(fakeNonce);

      // Stub low-level prove/verify
      sandbox.stub(proveModule, 'createHumanIdentity').returns(MOCK_HUMAN_IDENTITY as any);
      sandbox.stub(proveModule, 'createAgentCredential').returns(MOCK_AGENT_CREDENTIAL as any);
      sandbox.stub(proveModule, 'proveHandshake').resolves({
        humanProof: MOCK_HUMAN_PROOF,
        agentProof: MOCK_AGENT_PROOF,
      } as any);
      sandbox.stub(proveModule, 'verifyHandshake').resolves(true);

      const client = new BolyraClient({
        provider: mockProvider,
        registryAddress: '0x1234567890abcdef1234567890abcdef12345678',
      });

      const result = await client.handshake('my-secret', {
        modelHash: 'gpt-4-hash',
        operatorPrivKey: 'operator-key',
        permissions: 0b00000011,
        expiry: Math.floor(Date.now() / 1000) + 3600,
      });

      expect(result.verified).to.be.true;
      expect(result.nullifierHash).to.equal('abc123');
      expect(result.sessionNonce).to.equal(fakeNonce);
      expect(result.humanProof).to.deep.equal(MOCK_HUMAN_PROOF);
      expect(result.agentProof).to.deep.equal(MOCK_AGENT_PROOF);

      // Verify call order
      expect((proveModule.createHumanIdentity as sinon.SinonStub).calledOnce).to.be.true;
      expect((proveModule.createAgentCredential as sinon.SinonStub).calledOnce).to.be.true;
      expect((proveModule.proveHandshake as sinon.SinonStub).calledOnce).to.be.true;
      expect((proveModule.verifyHandshake as sinon.SinonStub).calledOnce).to.be.true;
    });

    it('returns verified=false when verifyHandshake fails', async () => {
      sandbox.stub(ArtifactResolver.prototype, 'resolve').returns(MOCK_ARTIFACTS);
      sandbox.stub(MerkleProofFetcher.prototype, 'fetch').resolves(MOCK_MERKLE_PROOF);
      sandbox.stub(nonceModule, 'generateSessionNonce').returns(Buffer.alloc(32, 0xcd) as SessionNonce);
      sandbox.stub(proveModule, 'createHumanIdentity').returns(MOCK_HUMAN_IDENTITY as any);
      sandbox.stub(proveModule, 'createAgentCredential').returns(MOCK_AGENT_CREDENTIAL as any);
      sandbox.stub(proveModule, 'proveHandshake').resolves({
        humanProof: MOCK_HUMAN_PROOF,
        agentProof: MOCK_AGENT_PROOF,
      } as any);
      sandbox.stub(proveModule, 'verifyHandshake').resolves(false);

      const client = new BolyraClient({ provider: mockProvider });
      const result = await client.handshake('secret', {
        modelHash: 'h', operatorPrivKey: 'k', permissions: 1, expiry: 9999,
      });

      expect(result.verified).to.be.false;
    });

    it('propagates ArtifactNotFoundError when artifacts missing', async () => {
      // Don't stub — let it try to resolve real paths (which won't exist in test)
      sandbox.stub(MerkleProofFetcher.prototype, 'fetch').resolves(MOCK_MERKLE_PROOF);
      sandbox.stub(proveModule, 'createHumanIdentity').returns(MOCK_HUMAN_IDENTITY as any);

      const client = new BolyraClient({
        provider: mockProvider,
        artifactsDir: '/nonexistent/path',
      });

      try {
        await client.handshake('secret', {
          modelHash: 'h', operatorPrivKey: 'k', permissions: 1, expiry: 9999,
        });
        expect.fail('should have thrown');
      } catch (err) {
        expect((err as Error).name).to.equal('ArtifactNotFoundError');
      }
    });
  });

  // Slow-path test gated behind FULL_PROOF=1
  (process.env.FULL_PROOF === '1' ? describe : describe.skip)(
    'handshake() — full proof slow path',
    () => {
      it('generates and verifies real proofs against compiled artifacts', async function () {
        this.timeout(120_000); // Real proofs take time

        const client = new BolyraClient({
          provider: mockProvider,
          // Use real artifacts from circuits/build/
          registryAddress: '0x0000000000000000000000000000000000000000',
        });

        // This test requires:
        // 1. Compiled circuits in circuits/build/
        // 2. A mock or local provider that returns valid Merkle proofs
        // Skip if artifacts aren't available
        try {
          const result = await client.handshake('integration-test-secret', {
            modelHash: 'test-model',
            operatorPrivKey: 'test-operator-key',
            permissions: 0b00000001,
            expiry: Math.floor(Date.now() / 1000) + 7200,
          });

          expect(result.verified).to.be.true;
          expect(result.nullifierHash).to.be.a('string').and.not.be.empty;
          expect(result.sessionNonce).to.have.length(32);
        } catch (err) {
          if ((err as Error).name === 'ArtifactNotFoundError') {
            this.skip(); // Artifacts not compiled — skip gracefully
          }
          throw err;
        }
      });
    }
  );
});

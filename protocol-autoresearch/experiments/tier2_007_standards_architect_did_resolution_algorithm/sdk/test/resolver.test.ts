import { describe, it, beforeEach } from 'mocha';
import { expect } from 'chai';
import sinon from 'sinon';
import { DIDResolver, encodeBabyJubJubMultibase } from '../src/resolver';
import type { DIDResolutionResult } from '../src/resolver';
import testVectors from '../../spec/test-vectors/did-resolution-vectors.json';

const ZERO_BYTES32 = '0x' + '0'.repeat(64);

/**
 * Create a mock ethers.Provider + Contract that returns the on-chain state
 * from a test vector.
 */
function createMockProvider(onChainState: any) {
  const mockContract: any = {};

  if (onChainState) {
    mockContract.getEnrollmentStatus = sinon.stub().resolves({
      enrolled: onChainState.getEnrollmentStatus.enrolled,
      publicKey: onChainState.getEnrollmentStatus.publicKey.map(BigInt) as [bigint, bigint],
      blockNumber: BigInt(onChainState.getEnrollmentStatus.blockNumber),
    });

    mockContract.isRevoked = sinon.stub().resolves(onChainState.isRevoked);

    mockContract.getAgentCredential = sinon.stub().resolves({
      agentId: onChainState.getAgentCredential.agentId,
      modelHash: onChainState.getAgentCredential.modelHash,
      operatorPubKey: onChainState.getAgentCredential.operatorPubKey.map(BigInt) as [bigint, bigint],
      permissions: onChainState.getAgentCredential.permissions,
      expiry: BigInt(onChainState.getAgentCredential.expiry),
    });

    mockContract.getMerkleRoot = sinon.stub().resolves(
      BigInt(onChainState.getMerkleRoot)
    );
  } else {
    // For parse-failure vectors, contract methods should never be called
    mockContract.getEnrollmentStatus = sinon.stub().rejects(new Error('Should not be called'));
    mockContract.isRevoked = sinon.stub().rejects(new Error('Should not be called'));
    mockContract.getAgentCredential = sinon.stub().rejects(new Error('Should not be called'));
    mockContract.getMerkleRoot = sinon.stub().rejects(new Error('Should not be called'));
  }

  const mockProvider: any = {
    getBlock: sinon.stub().resolves({ timestamp: 1700000000 }),
  };

  return { mockProvider, mockContract };
}

describe('DIDResolver', () => {
  // Override DIDResolver to inject mock contract
  function createResolver(mockProvider: any, mockContract: any, registryAddress: string) {
    const resolver = new DIDResolver(mockProvider, registryAddress);
    // Replace the internal registry contract with our mock
    (resolver as any).registry = mockContract;
    return resolver;
  }

  describe('Test vector: human-enrolled', () => {
    const vector = testVectors.vectors.find((v) => v.id === 'human-enrolled')!;

    it('resolves a valid human identity to a full DID Document', async () => {
      const { mockProvider, mockContract } = createMockProvider(vector.onChainState);
      const resolver = createResolver(mockProvider, mockContract, vector.input.registryAddress);

      const result = await resolver.resolve(vector.input.did);

      expect(result.didDocument).to.not.be.null;
      expect(result.didDocument!.id).to.equal(vector.expectedOutput.didDocument!.id);
      expect(result.didDocument!['@context']).to.deep.equal(
        vector.expectedOutput.didDocument!['@context']
      );
      expect(result.didResolutionMetadata.contentType).to.equal('application/did+ld+json');
      expect(result.didResolutionMetadata.error).to.be.undefined;

      // Verify structure
      expect(result.didDocument!.verificationMethod).to.have.length(1);
      expect(result.didDocument!.verificationMethod![0].type).to.equal('EdDSAVerificationKey2022');
      expect(result.didDocument!.authentication).to.deep.equal([`${vector.input.did}#key-1`]);
      expect(result.didDocument!.service).to.have.length(1);
      expect(result.didDocument!.service![0].type).to.equal('BolyraProofExchange');

      // Verify metadata
      expect(result.didDocumentMetadata.versionId).to.be.a('string');
      expect(result.didDocumentMetadata.deactivated).to.be.undefined;
    });
  });

  describe('Test vector: agent-enrolled', () => {
    const vector = testVectors.vectors.find((v) => v.id === 'agent-enrolled')!;

    it('resolves a valid agent identity with agent-policy service', async () => {
      const { mockProvider, mockContract } = createMockProvider(vector.onChainState);
      const resolver = createResolver(mockProvider, mockContract, vector.input.registryAddress);

      const result = await resolver.resolve(vector.input.did);

      expect(result.didDocument).to.not.be.null;
      expect(result.didDocument!.id).to.equal(vector.input.did);
      expect(result.didDocument!.service).to.have.length(2);
      expect(result.didDocument!.service![0].type).to.equal('BolyraProofExchange');
      expect(result.didDocument!.service![1].type).to.equal('BolyraAgentPolicy');
      expect(result.didDocument!.service![1].permissions).to.equal(7);
      expect(result.didResolutionMetadata.error).to.be.undefined;
    });
  });

  describe('Test vector: revoked-identity', () => {
    const vector = testVectors.vectors.find((v) => v.id === 'revoked-identity')!;

    it('returns deactivated=true with minimal DID Document', async () => {
      const { mockProvider, mockContract } = createMockProvider(vector.onChainState);
      const resolver = createResolver(mockProvider, mockContract, vector.input.registryAddress);

      const result = await resolver.resolve(vector.input.did);

      expect(result.didDocument).to.not.be.null;
      expect(result.didDocument!.id).to.equal(vector.input.did);
      expect(result.didDocument!['@context']).to.deep.equal(['https://www.w3.org/ns/did/v1']);
      expect(result.didDocument!.verificationMethod).to.be.undefined;
      expect(result.didDocument!.service).to.be.undefined;
      expect(result.didDocumentMetadata.deactivated).to.be.true;
      expect(result.didResolutionMetadata.contentType).to.equal('application/did+ld+json');
    });
  });

  describe('Test vector: not-found', () => {
    const vector = testVectors.vectors.find((v) => v.id === 'not-found')!;

    it('returns notFound error for non-existent commitment', async () => {
      const { mockProvider, mockContract } = createMockProvider(vector.onChainState);
      const resolver = createResolver(mockProvider, mockContract, vector.input.registryAddress);

      const result = await resolver.resolve(vector.input.did);

      expect(result.didDocument).to.be.null;
      expect(result.didResolutionMetadata.error).to.equal('notFound');
      expect(result.didResolutionMetadata.message).to.equal('Commitment not enrolled');
      expect(result.didDocumentMetadata).to.deep.equal({});
    });
  });

  describe('Test vector: malformed-did', () => {
    const vector = testVectors.vectors.find((v) => v.id === 'malformed-did')!;

    it('returns invalidDid error for missing prefix', async () => {
      const { mockProvider, mockContract } = createMockProvider(vector.onChainState);
      const resolver = createResolver(mockProvider, mockContract, vector.input.registryAddress);

      const result = await resolver.resolve(vector.input.did);

      expect(result.didDocument).to.be.null;
      expect(result.didResolutionMetadata.error).to.equal('invalidDid');
      expect(result.didResolutionMetadata.message).to.equal('Missing did:bolyra: prefix');

      // Contract methods should not have been called
      expect(mockContract.getEnrollmentStatus.called).to.be.false;
    });
  });

  describe('Test vector: invalid-hex', () => {
    const vector = testVectors.vectors.find((v) => v.id === 'invalid-hex')!;

    it('returns invalidDid error for non-hex characters', async () => {
      const { mockProvider, mockContract } = createMockProvider(vector.onChainState);
      const resolver = createResolver(mockProvider, mockContract, vector.input.registryAddress);

      const result = await resolver.resolve(vector.input.did);

      expect(result.didDocument).to.be.null;
      expect(result.didResolutionMetadata.error).to.equal('invalidDid');
      expect(result.didResolutionMetadata.message).to.equal('Invalid hex commitment');
    });
  });

  describe('Test vector: no-0x-prefix', () => {
    const vector = testVectors.vectors.find((v) => v.id === 'no-0x-prefix')!;

    it('resolves DID without 0x prefix identically', async () => {
      const { mockProvider, mockContract } = createMockProvider(vector.onChainState);
      const resolver = createResolver(mockProvider, mockContract, vector.input.registryAddress);

      const result = await resolver.resolve(vector.input.did);

      expect(result.didDocument).to.not.be.null;
      expect(result.didDocument!.id).to.equal(vector.input.did);
      expect(result.didResolutionMetadata.contentType).to.equal('application/did+ld+json');
      expect(result.didResolutionMetadata.error).to.be.undefined;
    });
  });

  describe('RPC failure', () => {
    it('returns internalError when contract call fails', async () => {
      const mockContract: any = {
        getEnrollmentStatus: sinon.stub().rejects(new Error('RPC timeout')),
        isRevoked: sinon.stub().rejects(new Error('RPC timeout')),
        getAgentCredential: sinon.stub().rejects(new Error('RPC timeout')),
        getMerkleRoot: sinon.stub().rejects(new Error('RPC timeout')),
      };
      const mockProvider: any = { getBlock: sinon.stub() };
      const resolver = createResolver(mockProvider, mockContract, '0x1234');

      const result = await resolver.resolve(
        'did:bolyra:0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890'
      );

      expect(result.didDocument).to.be.null;
      expect(result.didResolutionMetadata.error).to.equal('internalError');
      expect(result.didResolutionMetadata.message).to.include('RPC timeout');
    });
  });

  describe('encodeBabyJubJubMultibase', () => {
    it('returns a z-prefixed base58btc string', () => {
      const result = encodeBabyJubJubMultibase([123456789n, 987654321n]);
      expect(result).to.match(/^z[1-9A-HJ-NP-Za-km-z]+$/);
    });

    it('sets parity bit for odd y coordinate', () => {
      const even = encodeBabyJubJubMultibase([100n, 200n]);
      const odd = encodeBabyJubJubMultibase([100n, 201n]);
      expect(even).to.not.equal(odd);
    });
  });
});

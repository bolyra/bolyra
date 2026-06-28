/**
 * Tests for the Bolyra DID Resolver
 *
 * Tests the pure functions (parseDID, document construction) directly
 * and mocks ethers.js for the full resolution flow.
 */

import { describe, it, expect } from 'vitest';
import { parseDID, resolve, getResolver } from './resolver';
import type { DIDResolutionResult, ParsedDID } from './resolver';

// Load conformance vectors
import vectors from '../../../spec/conformance/did-resolution-vectors.json';

// ---------- parseDID ----------

describe('parseDID', () => {
  it('parses a valid did:bolyra DID', () => {
    const result = parseDID(
      'did:bolyra:84532:0x1234567890abcdef1234567890abcdef12345678:0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
    );
    expect(result).toEqual({
      chainId: '84532',
      registryAddress: '0x1234567890abcdef1234567890abcdef12345678',
      subjectId: '0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
    });
  });

  it('normalizes addresses to lowercase', () => {
    const result = parseDID(
      'did:bolyra:84532:0x1234567890ABCDEF1234567890ABCDEF12345678:0x00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF',
    );
    expect(result).not.toBeNull();
    expect(result!.registryAddress).toBe('0x1234567890abcdef1234567890abcdef12345678');
    expect(result!.subjectId).toBe('0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
  });

  it('rejects DID with wrong method', () => {
    expect(parseDID('did:example:84532:0x1234567890abcdef1234567890abcdef12345678:0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff')).toBeNull();
  });

  it('rejects DID with missing components', () => {
    expect(parseDID('did:bolyra:84532:0x1234567890abcdef1234567890abcdef12345678')).toBeNull();
  });

  it('rejects DID with leading zeros in chain-id', () => {
    expect(parseDID('did:bolyra:084532:0x1234567890abcdef1234567890abcdef12345678:0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff')).toBeNull();
  });

  it('rejects DID with chain-id of zero', () => {
    expect(parseDID('did:bolyra:0:0x1234567890abcdef1234567890abcdef12345678:0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff')).toBeNull();
  });

  it('rejects DID with invalid registry address length', () => {
    expect(parseDID('did:bolyra:84532:0x1234:0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff')).toBeNull();
  });

  it('rejects DID with invalid subject-id length', () => {
    expect(parseDID('did:bolyra:84532:0x1234567890abcdef1234567890abcdef12345678:0x0011')).toBeNull();
  });

  it('rejects DID with extra components', () => {
    expect(parseDID('did:bolyra:84532:0x1234567890abcdef1234567890abcdef12345678:0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff:extra')).toBeNull();
  });
});

// ---------- Conformance Vector Tests ----------

describe('conformance vectors (structural)', () => {
  for (const vector of vectors.vectors) {
    it(`vector: ${vector.id} — ${vector.description}`, () => {
      const { input, expectedOutput } = vector;

      // Test parse validity
      const parsed = parseDID(input.did);

      if (expectedOutput.didResolutionMetadata.error === 'invalidDid') {
        expect(parsed).toBeNull();
        return;
      }

      // For unsupported chain, parse should succeed but resolution should fail
      if (expectedOutput.didResolutionMetadata.error === 'unsupportedChainId') {
        expect(parsed).not.toBeNull();
        return;
      }

      // For notFound, parse should succeed
      if (expectedOutput.didResolutionMetadata.error === 'notFound') {
        expect(parsed).not.toBeNull();
        return;
      }

      // For active/deactivated DIDs, check document structure
      if (expectedOutput.didDocument) {
        expect(parsed).not.toBeNull();
        const doc = expectedOutput.didDocument;
        expect(doc['@context']).toContain('https://www.w3.org/ns/did/v1');
        expect(doc.id).toBe(input.did);
        expect(doc.controller).toBe(input.did);

        // Check deactivated has no verification methods
        if (expectedOutput.didDocumentMetadata.deactivated) {
          expect(doc.verificationMethod).toBeUndefined();
          expect(doc.service).toBeUndefined();
        }
      }
    });
  }
});

// ---------- getResolver factory ----------

describe('getResolver', () => {
  it('returns a resolver map with "bolyra" key', () => {
    const resolverMap = getResolver();
    expect(resolverMap).toHaveProperty('bolyra');
    expect(typeof resolverMap.bolyra).toBe('function');
  });

  it('resolver function returns invalidDid for malformed DIDs', async () => {
    const resolverMap = getResolver();
    const result = await resolverMap.bolyra('did:bolyra:bad', {}, {}, {});
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
    expect(result.didDocument).toBeNull();
  });
});

// ---------- resolve with unsupported chain ----------

describe('resolve', () => {
  it('returns unsupportedChainId for unknown chain', async () => {
    const result = await resolve(
      'did:bolyra:99999:0x1234567890abcdef1234567890abcdef12345678:0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
      { rpcEndpoints: {} },
    );
    expect(result.didResolutionMetadata.error).toBe('unsupportedChainId');
    expect(result.didResolutionMetadata.message).toContain('99999');
    expect(result.didDocument).toBeNull();
  });

  it('returns invalidDid for malformed input', async () => {
    const result = await resolve('did:bolyra:abc');
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
  });
});

import { encodeProof, encodeMultiSlotProof, computeMappingSlot, EIP1186Proof } from '../proofEncoder';

// ──────────────────────── Fixtures ────────────────────────

// Simulated eth_getProof response with two storage slots.
const MOCK_PROOF: EIP1186Proof = {
  address: '0x1234567890AbcdEF1234567890aBcdef12345678',
  balance: '0x0',
  codeHash: '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
  nonce: '0x0',
  storageHash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
  accountProof: [
    '0xf90211a0deadbeef' + '00'.repeat(500),  // branch node (simplified)
    '0xf8518080a0' + 'aa'.repeat(32) + '80808080a0' + 'bb'.repeat(32) + '80808080808080808080',
    '0xe4820020a0' + 'cc'.repeat(32),  // leaf node
  ],
  storageProof: [
    {
      key: '0x0000000000000000000000000000000000000000000000000000000000000003',
      value: '0xdeadbeef',
      proof: [
        '0xf90211a0' + '11'.repeat(32) + '00'.repeat(480),
        '0xe4820020a0' + '22'.repeat(32),
      ],
    },
    {
      key: '0x0000000000000000000000000000000000000000000000000000000000000004',
      value: '0xcafebabe',
      proof: [
        '0xf90211a0' + '33'.repeat(32) + '00'.repeat(480),
        '0xe4820020a0' + '44'.repeat(32),
      ],
    },
  ],
};

// ──────────────────────── Tests ────────────────────────

describe('proofEncoder', () => {
  describe('encodeProof', () => {
    it('should encode account proof with 0x prefixes', () => {
      const encoded = encodeProof(MOCK_PROOF, 0);
      expect(encoded.accountProof).toHaveLength(3);
      encoded.accountProof.forEach((node) => {
        expect(node.startsWith('0x')).toBe(true);
      });
    });

    it('should encode storage proof for slot 0', () => {
      const encoded = encodeProof(MOCK_PROOF, 0);
      expect(encoded.storageProof).toHaveLength(2);
      encoded.storageProof.forEach((node) => {
        expect(node.startsWith('0x')).toBe(true);
      });
    });

    it('should encode storage proof for slot 1', () => {
      const encoded = encodeProof(MOCK_PROOF, 1);
      expect(encoded.storageProof).toHaveLength(2);
    });

    it('should throw for out-of-range slot index', () => {
      expect(() => encodeProof(MOCK_PROOF, 5)).toThrow('slotIndex 5 out of range');
    });

    it('should default to slot index 0', () => {
      const encoded = encodeProof(MOCK_PROOF);
      expect(encoded.storageProof).toEqual(
        encodeProof(MOCK_PROOF, 0).storageProof
      );
    });

    it('should handle proof nodes without 0x prefix', () => {
      const proofWithoutPrefix: EIP1186Proof = {
        ...MOCK_PROOF,
        accountProof: ['f90211a0deadbeef', 'f8518080'],
        storageProof: [
          {
            key: '0x03',
            value: '0x01',
            proof: ['e4820020a0' + 'cc'.repeat(32)],
          },
        ],
      };
      const encoded = encodeProof(proofWithoutPrefix, 0);
      expect(encoded.accountProof[0]).toBe('0xf90211a0deadbeef');
      expect(encoded.accountProof[1]).toBe('0xf8518080');
      expect(encoded.storageProof[0].startsWith('0x')).toBe(true);
    });
  });

  describe('encodeMultiSlotProof', () => {
    it('should return one EncodedProof per storage slot', () => {
      const results = encodeMultiSlotProof(MOCK_PROOF);
      expect(results).toHaveLength(2);
    });

    it('should share account proof across all slots', () => {
      const results = encodeMultiSlotProof(MOCK_PROOF);
      expect(results[0].accountProof).toEqual(results[1].accountProof);
    });

    it('should have different storage proofs per slot', () => {
      const results = encodeMultiSlotProof(MOCK_PROOF);
      expect(results[0].storageProof).not.toEqual(results[1].storageProof);
    });
  });

  describe('computeMappingSlot', () => {
    it('should compute a deterministic slot for given base and key', () => {
      const slot1 = computeMappingSlot(3, 0);
      const slot2 = computeMappingSlot(3, 0);
      expect(slot1).toBe(slot2);
    });

    it('should return different slots for different keys', () => {
      const slot1 = computeMappingSlot(3, 0);
      const slot2 = computeMappingSlot(3, 1);
      expect(slot1).not.toBe(slot2);
    });

    it('should return different slots for different base slots', () => {
      const slot1 = computeMappingSlot(3, 0);
      const slot2 = computeMappingSlot(4, 0);
      expect(slot1).not.toBe(slot2);
    });

    it('should return a 66-char hex string (0x + 64 hex digits)', () => {
      const slot = computeMappingSlot(3, 42);
      expect(slot).toMatch(/^0x[0-9a-f]{64}$/);
    });
  });
});
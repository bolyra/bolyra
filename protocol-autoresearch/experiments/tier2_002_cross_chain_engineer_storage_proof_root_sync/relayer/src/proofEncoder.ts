import { RLP } from "@ethersproject/rlp";
import { hexlify, zeroPadValue, toBeHex } from "ethers";

/**
 * EIP-1186 proof response shape from eth_getProof.
 */
export interface EIP1186Proof {
  accountProof: string[];
  storageProof: Array<{
    key: string;
    value: string;
    proof: string[];
  }>;
  address: string;
  balance: string;
  codeHash: string;
  nonce: string;
  storageHash: string;
}

/**
 * Encoded proof ready for on-chain submission.
 */
export interface EncodedProof {
  accountProof: string[];
  storageProof: string[];
}

/**
 * Encode an EIP-1186 proof response into the format expected by StorageProofLib.
 * Each proof node is an RLP-encoded trie node (already hex-encoded from the RPC).
 *
 * @param proof  Raw eth_getProof response for a single storage key.
 * @param slotIndex  Index into storageProof array (default 0).
 * @returns Encoded account proof and storage proof as hex string arrays.
 */
export function encodeProof(
  proof: EIP1186Proof,
  slotIndex: number = 0
): EncodedProof {
  // Account proof nodes are already RLP-encoded hex strings from the RPC.
  const accountProof = proof.accountProof.map((node) => ensureHexPrefix(node));

  // Storage proof nodes for the requested slot.
  if (slotIndex >= proof.storageProof.length) {
    throw new Error(
      `slotIndex ${slotIndex} out of range (${proof.storageProof.length} slots)`
    );
  }
  const storageProof = proof.storageProof[slotIndex].proof.map((node) =>
    ensureHexPrefix(node)
  );

  return { accountProof, storageProof };
}

/**
 * Encode multiple storage slot proofs from a single eth_getProof call.
 * Shares the account proof across all slots.
 *
 * @param proof  Raw eth_getProof response with multiple storage keys.
 * @returns Array of EncodedProof, one per storage key.
 */
export function encodeMultiSlotProof(
  proof: EIP1186Proof
): EncodedProof[] {
  const accountProof = proof.accountProof.map((node) => ensureHexPrefix(node));

  return proof.storageProof.map((sp) => ({
    accountProof,
    storageProof: sp.proof.map((node) => ensureHexPrefix(node)),
  }));
}

/**
 * Ensure a hex string has the 0x prefix.
 */
function ensureHexPrefix(hex: string): string {
  return hex.startsWith("0x") ? hex : `0x${hex}`;
}

/**
 * Compute the storage slot for a Solidity mapping(uint256 => bytes32)
 * at a given base slot and key.
 *
 * slot = keccak256(abi.encode(key, baseSlot))
 */
export function computeMappingSlot(
  baseSlot: number | bigint,
  key: number | bigint
): string {
  const { keccak256, AbiCoder } = require("ethers");
  const coder = new AbiCoder();
  const encoded = coder.encode(
    ["uint256", "uint256"],
    [key, baseSlot]
  );
  return keccak256(encoded);
}
/**
 * @file prover.ts
 * @module @bolyra/sdk/delegation/prover
 * @description Proof generation helper for the Delegation circuit v2.
 *
 * This module builds the full witness (including Merkle proof for delegatee
 * inclusion) and generates a Groth16 proof using snarkjs.
 *
 * Usage:
 *   import { DelegationProver } from "@bolyra/sdk/delegation/prover";
 *
 *   const prover = new DelegationProver({
 *     wasmPath: "./circuits/delegation/delegation_js/delegation.wasm",
 *     zkeyPath: "./circuits/delegation/delegation_final.zkey",
 *     provider: ethersProvider,
 *     identityRegistryAddress: "0x...",
 *   });
 *
 *   const { proof, publicSignals } = await prover.prove({
 *     delegatorSecret: 12345n,
 *     delegatorNonce: 67890n,
 *     delegateeCredCommitment: 0xabc...n,
 *     scope: 42n,
 *     agentTreeSnapshot: snapshotFromIndexer,
 *     leafIndex: 7,
 *   });
 */

import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
import { ethers } from "ethers";

// ── Types ───────────────────────────────────────────────────────────

export interface MerkleProof {
    pathElements: bigint[];
    pathIndices: number[];
    root: bigint;
}

export interface AgentTreeSnapshot {
    leaves: bigint[];
    depth: number;
}

export interface DelegationProveInput {
    delegatorSecret: bigint;
    delegatorNonce: bigint;
    delegateeCredCommitment: bigint;
    scope: bigint;
    agentTreeSnapshot: AgentTreeSnapshot;
    leafIndex: number;
}

export interface DelegationProverConfig {
    wasmPath: string;
    zkeyPath: string;
    provider?: ethers.Provider;
    identityRegistryAddress?: string;
}

export interface DelegationProofResult {
    proof: snarkjs.Groth16Proof;
    publicSignals: string[];
    agentTreeRoot: bigint;
    scopeCommitment: bigint;
    nullifierHash: bigint;
}

// ── Merkle Tree Utilities ───────────────────────────────────────────

let _poseidon: any = null;
let _F: any = null;

async function getPoseidon(): Promise<{ poseidon: any; F: any }> {
    if (!_poseidon) {
        _poseidon = await buildPoseidon();
        _F = _poseidon.F;
    }
    return { poseidon: _poseidon, F: _F };
}

function poseidonHash(poseidon: any, F: any, inputs: bigint[]): bigint {
    return F.toObject(poseidon(inputs.map((x: bigint) => F.e(x))));
}

/**
 * Build a binary Merkle tree from leaves and return layers.
 */
function buildMerkleTree(
    poseidon: any,
    F: any,
    leaves: bigint[],
    depth: number
): bigint[][] {
    const numLeaves = 2 ** depth;
    const paddedLeaves = [...leaves];
    while (paddedLeaves.length < numLeaves) {
        paddedLeaves.push(0n);
    }

    const layers: bigint[][] = [paddedLeaves];
    let currentLayer = paddedLeaves;

    for (let i = 0; i < depth; i++) {
        const nextLayer: bigint[] = [];
        for (let j = 0; j < currentLayer.length; j += 2) {
            nextLayer.push(poseidonHash(poseidon, F, [currentLayer[j], currentLayer[j + 1]]));
        }
        layers.push(nextLayer);
        currentLayer = nextLayer;
    }

    return layers;
}

/**
 * Extract a Merkle authentication path from precomputed layers.
 */
function getMerkleProof(
    layers: bigint[][],
    leafIndex: number,
    depth: number
): MerkleProof {
    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];
    let idx = leafIndex;

    for (let i = 0; i < depth; i++) {
        const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
        pathElements.push(layers[i][siblingIdx]);
        pathIndices.push(idx % 2);
        idx = Math.floor(idx / 2);
    }

    return {
        pathElements,
        pathIndices,
        root: layers[depth][0],
    };
}

// ── Prover Class ────────────────────────────────────────────────────

export class DelegationProver {
    private config: DelegationProverConfig;

    constructor(config: DelegationProverConfig) {
        this.config = config;
    }

    /**
     * Generate a Groth16 proof for a delegation.
     *
     * @param input Delegation inputs including the agent tree snapshot
     *              and the leaf index of the delegatee's credential commitment.
     * @returns The proof, public signals, and derived values.
     */
    async prove(input: DelegationProveInput): Promise<DelegationProofResult> {
        const { poseidon, F } = await getPoseidon();

        // 1. Build Merkle tree and extract proof
        const layers = buildMerkleTree(
            poseidon,
            F,
            input.agentTreeSnapshot.leaves,
            input.agentTreeSnapshot.depth
        );
        const merkleProof = getMerkleProof(
            layers,
            input.leafIndex,
            input.agentTreeSnapshot.depth
        );

        // Verify the leaf matches
        if (
            input.agentTreeSnapshot.leaves[input.leafIndex] !==
            input.delegateeCredCommitment
        ) {
            throw new Error(
                `Leaf at index ${input.leafIndex} does not match delegateeCredCommitment`
            );
        }

        // 2. Compute derived values
        const delegatorCredCommitment = poseidonHash(poseidon, F, [
            input.delegatorSecret,
            input.delegatorNonce,
        ]);
        const scopeCommitment = poseidonHash(poseidon, F, [
            delegatorCredCommitment,
            input.delegateeCredCommitment,
            input.scope,
        ]);
        const nullifierHash = poseidonHash(poseidon, F, [
            input.delegatorSecret,
            input.scope,
        ]);

        // 3. Pad Merkle proof to depth 20 if snapshot depth < 20
        const paddedPathElements = [...merkleProof.pathElements];
        const paddedPathIndices = [...merkleProof.pathIndices];
        while (paddedPathElements.length < 20) {
            paddedPathElements.push(0n);
            paddedPathIndices.push(0);
        }

        // 4. Build circuit witness
        const witness = {
            agentTreeRoot: merkleProof.root.toString(),
            scopeCommitment: scopeCommitment.toString(),
            nullifierHash: nullifierHash.toString(),
            delegatorSecret: input.delegatorSecret.toString(),
            delegatorNonce: input.delegatorNonce.toString(),
            delegateeCredCommitment: input.delegateeCredCommitment.toString(),
            scope: input.scope.toString(),
            merklePathElements: paddedPathElements.map((x) => x.toString()),
            merklePathIndices: paddedPathIndices.map((x) => x.toString()),
        };

        // 5. Generate Groth16 proof
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            witness,
            this.config.wasmPath,
            this.config.zkeyPath
        );

        return {
            proof,
            publicSignals,
            agentTreeRoot: merkleProof.root,
            scopeCommitment,
            nullifierHash,
        };
    }

    /**
     * Fetch the latest agent tree root from the on-chain IdentityRegistry.
     * Useful for verifying that a proof's root will be accepted.
     */
    async fetchLatestAgentTreeRoot(): Promise<bigint> {
        if (!this.config.provider || !this.config.identityRegistryAddress) {
            throw new Error(
                "Provider and identityRegistryAddress required to fetch on-chain root"
            );
        }

        const abi = ["function agentRoot() view returns (uint256)"];
        const contract = new ethers.Contract(
            this.config.identityRegistryAddress,
            abi,
            this.config.provider
        );

        return contract.agentRoot();
    }

    /**
     * Check whether a root is still valid in the on-chain history buffer.
     */
    async isRootValid(root: bigint): Promise<boolean> {
        if (!this.config.provider || !this.config.identityRegistryAddress) {
            throw new Error(
                "Provider and identityRegistryAddress required for root validation"
            );
        }

        const abi = ["function isValidAgentRoot(uint256) view returns (bool)"];
        const contract = new ethers.Contract(
            this.config.identityRegistryAddress,
            abi,
            this.config.provider
        );

        return contract.isValidAgentRoot(root);
    }
}

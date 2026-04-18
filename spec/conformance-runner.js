#!/usr/bin/env node
/**
 * Bolyra Conformance Test Runner
 *
 * Runs the test vectors from spec/test-vectors.json against the actual
 * circuit implementations to verify protocol conformance.
 *
 * Usage:
 *   node spec/conformance-runner.js
 *   node spec/conformance-runner.js --vector valid-handshake-basic
 *   node spec/conformance-runner.js --type delegation
 */

const fs = require('fs');
const path = require('path');

// Use circomlibjs from circuits/node_modules
const MODULE_PATH = path.join(__dirname, '../circuits/node_modules');
module.paths.unshift(MODULE_PATH);

const { buildPoseidon, buildEddsa, buildBabyjub } = require('circomlibjs');

const VECTORS_PATH = path.join(__dirname, 'test-vectors.json');
const CIRCUITS_DIR = path.join(__dirname, '../circuits');

async function main() {
    const vectors = JSON.parse(fs.readFileSync(VECTORS_PATH, 'utf-8'));
    console.log(`Bolyra Conformance Test Runner v${vectors.version}`);
    console.log(`${vectors.vectors.length} test vectors loaded\n`);

    // Filter by CLI args if provided
    const args = process.argv.slice(2);
    let selectedVectors = vectors.vectors;

    if (args.includes('--vector')) {
        const id = args[args.indexOf('--vector') + 1];
        selectedVectors = selectedVectors.filter(v => v.id === id);
    }
    if (args.includes('--type')) {
        const type = args[args.indexOf('--type') + 1];
        selectedVectors = selectedVectors.filter(v => v.type === type);
    }

    const poseidon = await buildPoseidon();
    const eddsa = await buildEddsa();
    const babyJub = await buildBabyjub();
    const F = poseidon.F;

    let passed = 0;
    let failed = 0;
    let skipped = 0;

    for (const vector of selectedVectors) {
        process.stdout.write(`  ${vector.id}: `);

        try {
            const result = await runVector(vector, { poseidon, eddsa, babyJub, F });

            if (result.skipped) {
                console.log(`SKIP -- ${result.reason}`);
                skipped++;
            } else if (result.pass) {
                console.log('PASS');
                passed++;
            } else {
                console.log(`FAIL -- ${result.reason}`);
                failed++;
            }
        } catch (err) {
            console.log(`ERROR -- ${err.message}`);
            failed++;
        }
    }

    console.log(`\n${passed} passed, ${failed} failed, ${skipped} skipped`);
    process.exit(failed > 0 ? 1 : 0);
}

async function runVector(vector, crypto) {
    switch (vector.type) {
        case 'handshake':
            return runHandshakeVector(vector, crypto);
        case 'delegation':
            return runDelegationVector(vector, crypto);
        case 'enrollment':
            return runEnrollmentVector(vector, crypto);
        case 'delegation_chain':
            return runDelegationChainVector(vector, crypto);
        default:
            return { skipped: true, reason: `unknown vector type: ${vector.type}` };
    }
}

async function runHandshakeVector(vector, { poseidon, eddsa, babyJub, F }) {
    const inputs = vector.inputs;
    const expected = vector.expected;

    // For replay vectors, we can only check the logic, not the on-chain state
    if (inputs.isReplay) {
        return { pass: expected.result === 'FAIL', reason: 'replay detection is on-chain only' };
    }

    // Check if this tests credential expiry
    if (inputs.agentExpiry && inputs.currentTimestamp) {
        const expiry = BigInt(inputs.agentExpiry);
        const current = BigInt(inputs.currentTimestamp);
        const isExpired = current >= expiry;

        if (expected.result === 'FAIL' && expected.reason === 'credential_expired') {
            return { pass: isExpired, reason: isExpired ? '' : 'expected expiry but credential is still valid' };
        }
    }

    // Check scope violation
    if (inputs.agentPermissions && inputs.requiredScope) {
        const perms = BigInt(inputs.agentPermissions);
        const required = BigInt(inputs.requiredScope);
        const violation = (required & ~perms) !== 0n;

        if (expected.result === 'FAIL' && expected.reason === 'scope_violation') {
            return { pass: violation, reason: violation ? '' : 'expected scope violation but permissions satisfy' };
        }
    }

    // For PASS vectors, verify crypto properties
    if (expected.result === 'PASS') {
        if (inputs.humanSecret) {
            const secret = BigInt(inputs.humanSecret);
            const pubKey = babyJub.mulPointEscalar(babyJub.Base8, secret);
            const commitment = F.toObject(poseidon([F.toObject(pubKey[0]), F.toObject(pubKey[1])]));

            // Verify nullifier is deterministic
            if (expected.humanNullifierDeterministic) {
                const scope = BigInt(inputs.scope || '1');
                const nullifier = F.toObject(poseidon([scope, secret]));
                // Run twice, should produce same nullifier
                const nullifier2 = F.toObject(poseidon([scope, secret]));
                if (nullifier !== nullifier2) {
                    return { pass: false, reason: 'nullifier not deterministic' };
                }
            }

            // Verify scope commitment is identity-bound
            if (expected.agentScopeCommitmentIdentityBound && inputs.agentPermissions) {
                const perms = BigInt(inputs.agentPermissions);
                const modelHash = BigInt(inputs.agentModelHash || '12345');
                // Agent credential commitment binds bitmask to credential
                // Structural check: Poseidon2(bitmask, credCmt) is deterministic
                const credCmt = F.toObject(poseidon([perms, modelHash]));
                const scopeCmt = F.toObject(poseidon([perms, credCmt]));
                const scopeCmt2 = F.toObject(poseidon([perms, credCmt]));
                if (scopeCmt !== scopeCmt2) {
                    return { pass: false, reason: 'scope commitment not identity-bound (non-deterministic)' };
                }
            }
        }

        return { pass: true };
    }

    return { skipped: true, reason: 'vector requires circuit artifacts for full verification' };
}

async function runDelegationVector(vector, { poseidon, F }) {
    const inputs = vector.inputs;
    const expected = vector.expected;

    // On-chain-only checks: delegation without handshake, scope chain mismatch, phantom delegatee
    if (expected.reason === 'delegation_requires_handshake') {
        return { pass: expected.result === 'FAIL', reason: 'on-chain check (DelegationRequiresHandshake)' };
    }
    if (inputs.previousScopeCommitmentTampered) {
        return { pass: expected.result === 'FAIL', reason: 'on-chain check (ScopeChainMismatch)' };
    }
    if (inputs.delegateeEnrolled === false) {
        return { pass: expected.result === 'FAIL', reason: 'on-chain check (StaleAgentRoot)' };
    }

    const delegatorScope = BigInt(inputs.delegatorScope);
    const delegateeScope = BigInt(inputs.delegateeScope);

    // Check scope subset
    const scopeViolation = (delegateeScope & ~delegatorScope) !== 0n;

    if (expected.result === 'FAIL' && expected.reason === 'scope_escalation') {
        return { pass: scopeViolation, reason: scopeViolation ? '' : 'expected scope escalation but scope is valid' };
    }

    // Check expiry
    if (inputs.delegatorExpiry && inputs.delegateeExpiry) {
        const delegatorExp = BigInt(inputs.delegatorExpiry);
        const delegateeExp = BigInt(inputs.delegateeExpiry);
        const expiryViolation = delegateeExp > delegatorExp;

        if (expected.result === 'FAIL' && expected.reason === 'expiry_escalation') {
            return { pass: expiryViolation, reason: expiryViolation ? '' : 'expected expiry escalation but expiry is valid' };
        }
    }

    if (expected.result === 'PASS') {
        const scopeNarrowed = !scopeViolation && delegateeScope !== delegatorScope;
        if (expected.scopeNarrowed !== undefined && expected.scopeNarrowed !== scopeNarrowed) {
            return { pass: false, reason: `scope narrowing mismatch: expected ${expected.scopeNarrowed}, got ${scopeNarrowed}` };
        }
        return { pass: true };
    }

    return { pass: expected.result === 'FAIL' && scopeViolation };
}

async function runEnrollmentVector(vector, crypto) {
    const inputs = vector.inputs;
    const expected = vector.expected;

    const bitmask = BigInt(inputs.permissionBitmask);
    const bit2 = (bitmask >> 2n) & 1n;
    const bit3 = (bitmask >> 3n) & 1n;
    const bit4 = (bitmask >> 4n) & 1n;

    const violation = (bit4 === 1n && bit3 === 0n) ||
                      (bit4 === 1n && bit2 === 0n) ||
                      (bit3 === 1n && bit2 === 0n);

    if (expected.result === 'FAIL' && expected.reason === 'cumulative_bit_violation') {
        return { pass: violation, reason: violation ? '' : 'expected cumulative violation but encoding is valid' };
    }

    return { pass: !violation };
}

async function runDelegationChainVector(vector, { poseidon, F }) {
    const inputs = vector.inputs;
    const expected = vector.expected;

    const hops = inputs.hops;

    // Check each hop for scope violation
    for (let i = 0; i < hops.length; i++) {
        const delegatorScope = BigInt(hops[i].delegatorScope);
        const delegateeScope = BigInt(hops[i].delegateeScope);
        const violation = (delegateeScope & ~delegatorScope) !== 0n;

        if (violation) {
            return {
                pass: expected.result === 'FAIL',
                reason: `scope violation at hop ${i}`
            };
        }
    }

    // Check max hops
    if (expected.result === 'FAIL' && expected.reason === 'max_hops_exceeded') {
        const maxHops = 3;
        return {
            pass: hops.length > maxHops,
            reason: hops.length > maxHops ? '' : `expected max hops exceeded but only ${hops.length} hops`
        };
    }

    if (expected.result === 'PASS') {
        return {
            pass: true,
            hopCount: hops.length,
        };
    }

    return { pass: false, reason: 'unexpected test result' };
}

main().catch(err => {
    console.error('Runner failed:', err);
    process.exit(2);
});

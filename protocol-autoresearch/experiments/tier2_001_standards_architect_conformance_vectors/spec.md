# Conformance Test Suite with JSON Test Vectors

## Abstract

Produce 50+ JSON test vectors covering all three circuits and the delegation chain. Each vector specifies: circuit name, input signals (valid or invalid), expected output signals or expected rejection reason. Categories: valid handshake (human+agent), expired credential (currentTimestamp > expiryTimestamp), revoked human nullifier, stale Merkle root (not in 30-root buffer), scope subset violation in delegation, cumulative bit encoding violation (bit 4 without bits 2+3), delegation chain at depth 1/3/4 (4 must fail), and cross-hop scope commitment mismatch. Ship as a standalone JSON file with a JSON Schema for the vector format, enabling any implementation to run the suite without snarkjs.

## Normative Requirements

Implementations MUST ...

#!/usr/bin/env bash
# copy-artifacts.sh — Copy circuit build artifacts into circuits-package/artifacts/
# Normalizes naming: *_final.zkey -> *_groth16.zkey
# Generates SHA-256 checksums
# Skips PLONK .zkey files (too large), .ptau, .r1cs, .sym files

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$(cd "$PACKAGE_DIR/../circuits/build" && pwd)"
ARTIFACTS_DIR="$PACKAGE_DIR/artifacts"

CIRCUITS=("HumanUniqueness" "AgentPolicy" "Delegation")
MISSING=0

echo "=== Bolyra Circuit Artifacts Copy ==="
echo "Source: $BUILD_DIR"
echo "Target: $ARTIFACTS_DIR"
echo ""

# Clean previous artifacts
rm -rf "$ARTIFACTS_DIR"

for circuit in "${CIRCUITS[@]}"; do
  CIRCUIT_DIR="$ARTIFACTS_DIR/$circuit"
  mkdir -p "$CIRCUIT_DIR"

  # Copy .wasm from {Circuit}_js/ subdirectory
  WASM_SRC="$BUILD_DIR/${circuit}_js/${circuit}.wasm"
  if [[ -f "$WASM_SRC" ]]; then
    cp "$WASM_SRC" "$CIRCUIT_DIR/${circuit}.wasm"
    echo "[OK] $circuit.wasm"
  else
    echo "[WARN] Missing: $WASM_SRC"
    MISSING=$((MISSING + 1))
  fi

  # Copy Groth16 .zkey (named *_final.zkey in build/)
  ZKEY_SRC="$BUILD_DIR/${circuit}_final.zkey"
  if [[ -f "$ZKEY_SRC" ]]; then
    cp "$ZKEY_SRC" "$CIRCUIT_DIR/${circuit}_groth16.zkey"
    echo "[OK] ${circuit}_groth16.zkey (from ${circuit}_final.zkey)"
  else
    echo "[WARN] Missing: $ZKEY_SRC"
    MISSING=$((MISSING + 1))
  fi

  # Copy Groth16 vkey
  # HumanUniqueness uses {Circuit}_vkey.json, others use {Circuit}_groth16_vkey.json
  VKEY_GROTH16_SRC="$BUILD_DIR/${circuit}_groth16_vkey.json"
  VKEY_PLAIN_SRC="$BUILD_DIR/${circuit}_vkey.json"

  if [[ -f "$VKEY_GROTH16_SRC" ]]; then
    cp "$VKEY_GROTH16_SRC" "$CIRCUIT_DIR/${circuit}_groth16_vkey.json"
    echo "[OK] ${circuit}_groth16_vkey.json"
  elif [[ -f "$VKEY_PLAIN_SRC" ]]; then
    # HumanUniqueness: {Circuit}_vkey.json is the Groth16 vkey
    cp "$VKEY_PLAIN_SRC" "$CIRCUIT_DIR/${circuit}_groth16_vkey.json"
    echo "[OK] ${circuit}_groth16_vkey.json (from ${circuit}_vkey.json)"
  else
    echo "[WARN] Missing Groth16 vkey for $circuit"
    MISSING=$((MISSING + 1))
  fi

  # Copy PLONK vkey (verification only, no .zkey -- too large)
  # For AgentPolicy/Delegation: {Circuit}_vkey.json is the PLONK vkey
  # (when a separate _groth16_vkey.json exists)
  if [[ "$circuit" != "HumanUniqueness" ]]; then
    if [[ -f "$VKEY_GROTH16_SRC" && -f "$VKEY_PLAIN_SRC" ]]; then
      # Both exist: _groth16_vkey.json is groth16, _vkey.json is plonk
      cp "$VKEY_PLAIN_SRC" "$CIRCUIT_DIR/${circuit}_plonk_vkey.json"
      echo "[OK] ${circuit}_plonk_vkey.json (from ${circuit}_vkey.json)"
    fi
  fi

  # Skip PLONK .zkey files (too large, 146MB each)
  PLONK_ZKEY="$BUILD_DIR/${circuit}_plonk.zkey"
  if [[ -f "$PLONK_ZKEY" ]]; then
    echo "[SKIP] ${circuit}_plonk.zkey (too large for npm)"
  fi
done

echo ""

# Generate SHA-256 checksums
echo "=== Generating checksums ==="
CHECKSUM_FILE="$ARTIFACTS_DIR/checksums.sha256"
(
  cd "$ARTIFACTS_DIR"
  find . -type f -not -name "checksums.sha256" | sort | while read -r f; do
    shasum -a 256 "$f"
  done
) > "$CHECKSUM_FILE"

echo "Checksums written to $CHECKSUM_FILE"
echo ""

# Summary
TOTAL_SIZE=$(du -sh "$ARTIFACTS_DIR" | cut -f1)
FILE_COUNT=$(find "$ARTIFACTS_DIR" -type f | wc -l | tr -d ' ')
echo "=== Summary ==="
echo "Files: $FILE_COUNT"
echo "Total size: $TOTAL_SIZE"

if [[ "$MISSING" -gt 0 ]]; then
  echo ""
  echo "ERROR: $MISSING artifact(s) missing. Build circuits first: npm run compile:circuits"
  exit 1
fi

echo "Done."

/**
 * Lazy-initialized crypto primitives.
 * circomlibjs requires async factory calls; we cache them on first use.
 */

let _poseidon: any = null;
let _eddsa: any = null;
let _babyJub: any = null;
let _F: any = null;

async function ensureCrypto(): Promise<void> {
  if (_poseidon) return;
  const circomlibjs = await import('circomlibjs');
  _poseidon = await circomlibjs.buildPoseidon();
  _eddsa = await circomlibjs.buildEddsa();
  _babyJub = await circomlibjs.buildBabyjub();
  _F = _poseidon.F;
}

/** Poseidon hash with 2 inputs. Returns a bigint. */
export async function poseidon2(a: bigint, b: bigint): Promise<bigint> {
  await ensureCrypto();
  const hash = _poseidon([a, b]);
  return _F.toObject(hash);
}

/** Poseidon hash with 5 inputs. Returns a bigint. */
export async function poseidon5(
  a: bigint,
  b: bigint,
  c: bigint,
  d: bigint,
  e: bigint,
): Promise<bigint> {
  await ensureCrypto();
  const hash = _poseidon([a, b, c, d, e]);
  return _F.toObject(hash);
}

/**
 * Derive EdDSA public key from a private key buffer (Baby Jubjub).
 * Uses eddsa.prv2pub which matches what EdDSAPoseidonVerifier expects:
 * hash the key, clamp bits per RFC 8032, then multiply base point.
 *
 * IMPORTANT: This is NOT the same as babyJub.mulPointEscalar(Base8, scalar).
 * The HumanUniqueness circuit uses BabyPbk (direct scalar multiply) for
 * the human identity. The AgentPolicy circuit uses EdDSAPoseidonVerifier
 * which expects prv2pub-derived keys. Use the right function for each.
 */
export async function derivePublicKey(
  secret: bigint | Buffer,
): Promise<{ x: bigint; y: bigint }> {
  await ensureCrypto();
  const key =
    typeof secret === 'bigint'
      ? Buffer.from(secret.toString(16).padStart(64, '0'), 'hex')
      : secret;
  // Use eddsa.prv2pub which matches EdDSAPoseidonVerifier's key derivation
  const pubKey = _eddsa.prv2pub(key);
  return {
    x: _F.toObject(pubKey[0]),
    y: _F.toObject(pubKey[1]),
  };
}

/**
 * Derive public key via direct scalar multiplication (Baby Jubjub).
 * Used by HumanUniqueness circuit's BabyPbk component.
 */
export async function derivePublicKeyScalar(
  secret: bigint,
): Promise<{ x: bigint; y: bigint }> {
  await ensureCrypto();
  const pubKey = _babyJub.mulPointEscalar(_babyJub.Base8, secret);
  return {
    x: _F.toObject(pubKey[0]),
    y: _F.toObject(pubKey[1]),
  };
}

/** Sign a message (field element) with EdDSA. */
export async function eddsaSign(
  privateKey: bigint | Buffer,
  message: bigint,
): Promise<{ R8: { x: bigint; y: bigint }; S: bigint }> {
  await ensureCrypto();
  const key =
    typeof privateKey === 'bigint'
      ? Buffer.from(privateKey.toString(16).padStart(64, '0'), 'hex')
      : privateKey;
  const msgFe = _F.e(message);
  const sig = _eddsa.signPoseidon(key, msgFe);
  return {
    R8: { x: _F.toObject(sig.R8[0]), y: _F.toObject(sig.R8[1]) },
    S: sig.S,
  };
}

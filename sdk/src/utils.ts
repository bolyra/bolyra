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

/** Derive EdDSA public key from secret scalar (Baby Jubjub). */
export async function derivePublicKey(
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

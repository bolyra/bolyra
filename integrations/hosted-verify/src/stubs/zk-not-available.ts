/**
 * Build-time stub for `circomlibjs` / `snarkjs` (see the `alias` block in
 * wrangler.jsonc).
 *
 * The hosted verify preview is CLASSICAL ONLY: no code path may reach circuit
 * crypto. workerd forbids compiling WebAssembly from runtime buffers, so these
 * libraries could not run here even if bundled. If a future change accidentally
 * routes into a ZK path, this stub makes it fail loudly instead of silently.
 */
function unavailable(): never {
  throw new Error(
    'ZK circuit crypto (circomlibjs/snarkjs) is not available in the hosted ' +
      'verify preview — classical verification only',
  );
}

export const buildPoseidon = unavailable;
export const buildEddsa = unavailable;
export const buildBabyjub = unavailable;
export const groth16 = { verify: unavailable, fullProve: unavailable };
export const plonk = { verify: unavailable, fullProve: unavailable };
export default { buildPoseidon, buildEddsa, buildBabyjub, groth16, plonk };

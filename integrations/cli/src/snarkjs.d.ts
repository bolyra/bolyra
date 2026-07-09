// Minimal ambient declaration for snarkjs (mirrors sdk/src/snarkjs.d.ts).
// snarkjs ships no types; the external verifier only needs groth16.verify.
declare module 'snarkjs' {
  export namespace groth16 {
    function verify(
      vkey: unknown,
      publicSignals: string[],
      proof: unknown,
    ): Promise<boolean>;
  }
}

import {
  bindingDigest,
  verifyBindingSig,
  checkRequestBinding,
  checkModelBinding,
  type BindingClaim,
} from '../../src/verify/binding';
import { VerifyDenial } from '../../src/verify/verdict';
import { derivePublicKey, eddsaSign } from '@bolyra/sdk';
import { hashModel } from '../../src/parse';

/**
 * A canonical binding claim. Operators sign the digest of THIS to authorize a
 * specific agent/project/program/model + capability set.
 */
const BINDING: BindingClaim = {
  agent_name: 'research-bot',
  project_key: '/work/acme/research',
  program: 'crewai',
  model: 'opus-4.1',
  capabilities: ['read_data', 'write_data', 'financial_small'],
};

/** Operator private keys, as raw 32-byte buffers. */
const PRIV = Buffer.alloc(32, 0x11);
const PRIV2 = Buffer.alloc(32, 0x22);

describe('binding signature (F1 request-authorizing signature)', () => {
  it('accepts a valid signature over the binding against the proven key', async () => {
    const pub = await derivePublicKey(PRIV);
    const sig = await eddsaSign(PRIV, await bindingDigest(BINDING));
    await expect(verifyBindingSig(BINDING, sig, pub)).resolves.toBeUndefined();
  });

  it('rejects a cross-signer: signature by a DIFFERENT key vs the proven key (F1)', async () => {
    const pub = await derivePublicKey(PRIV);
    // Signed with PRIV2, but verified against PRIV's public key.
    const sig = await eddsaSign(PRIV2, await bindingDigest(BINDING));
    await expect(verifyBindingSig(BINDING, sig, pub)).rejects.toMatchObject({
      code: 'invalid_signature',
    });
    await expect(verifyBindingSig(BINDING, sig, pub)).rejects.toBeInstanceOf(
      VerifyDenial,
    );
  });

  it('rejects a tampered binding: sig over the original, verify a mutated binding', async () => {
    const pub = await derivePublicKey(PRIV);
    const sig = await eddsaSign(PRIV, await bindingDigest(BINDING));
    const tampered: BindingClaim = { ...BINDING, program: 'langchain' };
    await expect(verifyBindingSig(tampered, sig, pub)).rejects.toMatchObject({
      code: 'invalid_signature',
    });
  });

  it('produces digests in the BN254 scalar field', async () => {
    const BN254_FIELD_ORDER =
      21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const d = await bindingDigest(BINDING);
    expect(d).toBeGreaterThanOrEqual(0n);
    expect(d).toBeLessThan(BN254_FIELD_ORDER);
  });
});

describe('checkRequestBinding', () => {
  const validRequest = {
    agent_name: BINDING.agent_name,
    project_key: BINDING.project_key,
    program: BINDING.program,
    model: BINDING.model,
    granted_capabilities: ['read_data', 'write_data'],
  };

  it('passes when all fields match and capabilities are a subset', () => {
    expect(() => checkRequestBinding(validRequest, BINDING)).not.toThrow();
  });

  it('throws request_mismatch when project_key differs', () => {
    const req = { ...validRequest, project_key: '/work/acme/other' };
    try {
      checkRequestBinding(req, BINDING);
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyDenial);
      expect((err as VerifyDenial).code).toBe('request_mismatch');
      expect((err as VerifyDenial).detail).toMatchObject({ field: 'project_key' });
    }
  });

  it('throws request_mismatch when granted_capabilities exceed the binding (superset)', () => {
    const req = {
      ...validRequest,
      granted_capabilities: ['read_data', 'access_pii'],
    };
    try {
      checkRequestBinding(req, BINDING);
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyDenial);
      expect((err as VerifyDenial).code).toBe('request_mismatch');
      expect((err as VerifyDenial).detail).toMatchObject({
        field: 'granted_capabilities',
        capability: 'access_pii',
      });
    }
  });

  it('compares project_key LITERALLY — no path normalization', () => {
    // A binding whose project_key contains `..` segments.
    const dottedBinding: BindingClaim = {
      ...BINDING,
      project_key: '/work/acme/sub/../research',
    };
    // Byte-equal literal string: passes.
    const equalReq = {
      ...validRequest,
      project_key: '/work/acme/sub/../research',
    };
    expect(() => checkRequestBinding(equalReq, dottedBinding)).not.toThrow();

    // Different literal that NORMALIZES to the same path: must still mismatch,
    // proving no path.resolve/normalization happens.
    const normalizedReq = {
      ...validRequest,
      project_key: '/work/acme/research',
    };
    try {
      checkRequestBinding(normalizedReq, dottedBinding);
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyDenial);
      expect((err as VerifyDenial).code).toBe('request_mismatch');
      expect((err as VerifyDenial).detail).toMatchObject({ field: 'project_key' });
    }
  });
});

describe('checkModelBinding', () => {
  it('passes when the proven model hash matches the requested model', () => {
    expect(() =>
      checkModelBinding(hashModel('opus-4.1'), 'opus-4.1'),
    ).not.toThrow();
  });

  it('throws model_mismatch when the requested model differs', () => {
    try {
      checkModelBinding(hashModel('opus-4.1'), 'sonnet-4.5');
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyDenial);
      expect((err as VerifyDenial).code).toBe('model_mismatch');
    }
  });
});

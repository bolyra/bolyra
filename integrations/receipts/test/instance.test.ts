import {
  INSTANCE_BINDING_DST,
  INSTANCE_REF_PREFIX,
  computeInstanceRef,
  validateInstancePreimage,
  verifyInstanceBinding,
  type InstancePreimage,
} from '../src/instance';
import { signReceipt, verifyReceipt } from '../src/sign';
import { createAuthReceipt, createCommerceReceipt } from '../src/receipt';
import type {
  CommerceReceiptInput,
  ReceiptPayload,
  ReceiptSignerConfig,
  SignedReceipt,
} from '../src/types';
import * as vectors from './fixtures/instance-vectors.json';

const TEST_PRIVATE_KEY = '0x' + '01'.repeat(32);

const TEST_CONFIG: ReceiptSignerConfig = {
  issuer: 'test-server',
  keyId: 'key-1',
  privateKey: TEST_PRIVATE_KEY,
};

const GOLDEN_PREIMAGE: InstancePreimage = {
  audience: 'merchant.example',
  program: 'x402',
  capabilities: ['payments:send'],
  amountUsd: '12.50',
  decisionAt: '2026-08-24T10:00:00.123Z',
  requestNonce: 'nonce-abc123',
};

function makeCommerceInput(): CommerceReceiptInput {
  return {
    rootDid: 'did:bolyra:root123',
    actingDid: 'did:bolyra:agent456',
    credentialCommitment: '0xabc',
    effectiveCommitment: '0xdef',
    allowed: true,
    score: 95,
    permissionBitmask: '255',
    chainDepth: 0,
    humanProof: { proof: { pi_a: [1, 2] } },
    agentProof: { proof: { pi_a: [3, 4] } },
    humanPublicSignals: ['111'],
    agentPublicSignals: ['222'],
    bundleVersion: 1,
    nonce: '12345',
    commerce: {
      rail: 'x402',
      amount: 12.5,
      currency: 'USD',
      merchant: 'merchant.example',
      intentHash: 'ab'.repeat(32),
    },
  };
}

/** Commerce payload carrying a correctly-computed instance block. */
function makeBoundPayload(preimage: InstancePreimage = GOLDEN_PREIMAGE): ReceiptPayload {
  const payload = createCommerceReceipt(makeCommerceInput(), TEST_CONFIG);
  return { ...payload, instance: { ref: computeInstanceRef(preimage), preimage } };
}

function signPayload(payload: ReceiptPayload): SignedReceipt {
  return signReceipt(payload, TEST_CONFIG);
}

describe('constants', () => {
  it('pin the spec values', () => {
    expect(INSTANCE_BINDING_DST).toBe(vectors.dst);
    expect(INSTANCE_REF_PREFIX).toBe(vectors.refPrefix);
  });
});

describe('validateInstancePreimage', () => {
  it('accepts every golden preimage', () => {
    for (const { name, preimage } of vectors.golden) {
      const result = validateInstancePreimage(preimage);
      expect({ name, ok: result.ok }).toEqual({ name, ok: true });
    }
  });

  it('rejects every out-of-domain vector with a reason', () => {
    for (const { name, preimage } of vectors.outOfDomain) {
      const result = validateInstancePreimage(preimage);
      expect({ name, ok: result.ok }).toEqual({ name, ok: false });
      if (!result.ok) expect(result.detail.length).toBeGreaterThan(0);
    }
  });

  it('general fields keep the full 0x00..0x7F domain (tab and DEL in requestNonce)', () => {
    const result = validateInstancePreimage({
      ...GOLDEN_PREIMAGE,
      requestNonce: 'a\tb\x7f',
    });
    expect(result.ok).toBe(true);
  });

  it('rejects a character just past the ASCII boundary (0x80) in any field', () => {
    const result = validateInstancePreimage({
      ...GOLDEN_PREIMAGE,
      requestNonce: 'a\x80',
    });
    expect(result.ok).toBe(false);
  });

  describe('audience identifier syntax (§3.1.1, ^[\\x21-\\x7E]{1,256}$)', () => {
    it('accepts identifier shapes: 0x address, DID, project key, URL', () => {
      for (const audience of [
        '0x' + 'ab'.repeat(20),
        'did:bolyra:merchant123',
        'proj_live_8f3k2',
        'https://merchant.example/pay',
      ]) {
        expect({ audience, ok: validateInstancePreimage({ ...GOLDEN_PREIMAGE, audience }).ok })
          .toEqual({ audience, ok: true });
      }
    });

    it('accepts exactly 256 characters and rejects 257', () => {
      expect(validateInstancePreimage({ ...GOLDEN_PREIMAGE, audience: 'a'.repeat(256) }).ok).toBe(true);
      expect(validateInstancePreimage({ ...GOLDEN_PREIMAGE, audience: 'a'.repeat(257) }).ok).toBe(false);
    });

    it('rejects space, tab, DEL, and empty (identifier floor, tighter than the general domain)', () => {
      for (const audience of ['Acme Corp', 'a\tb', 'a\x7f', '']) {
        expect({ audience, ok: validateInstancePreimage({ ...GOLDEN_PREIMAGE, audience }).ok })
          .toEqual({ audience, ok: false });
      }
    });
  });
});

describe('computeInstanceRef', () => {
  it('reproduces every golden vector byte-for-byte', () => {
    for (const { name, preimage, ref } of vectors.golden) {
      expect({ name, ref: computeInstanceRef(preimage as InstancePreimage) }).toEqual({ name, ref });
    }
  });

  it('is independent of member insertion order', () => {
    const reordered = {
      requestNonce: GOLDEN_PREIMAGE.requestNonce,
      decisionAt: GOLDEN_PREIMAGE.decisionAt,
      amountUsd: GOLDEN_PREIMAGE.amountUsd,
      capabilities: GOLDEN_PREIMAGE.capabilities,
      program: GOLDEN_PREIMAGE.program,
      audience: GOLDEN_PREIMAGE.audience,
    } as InstancePreimage;
    expect(computeInstanceRef(reordered)).toBe(computeInstanceRef(GOLDEN_PREIMAGE));
  });

  it('capability order is significant (arrays are not sorted)', () => {
    const a = computeInstanceRef({ ...GOLDEN_PREIMAGE, capabilities: ['a', 'b'] });
    const b = computeInstanceRef({ ...GOLDEN_PREIMAGE, capabilities: ['b', 'a'] });
    expect(a).not.toBe(b);
  });

  it('a different decisionAt yields a different ref', () => {
    const other = computeInstanceRef({
      ...GOLDEN_PREIMAGE,
      decisionAt: '2026-08-24T10:00:00.124Z',
    });
    expect(other).not.toBe(computeInstanceRef(GOLDEN_PREIMAGE));
  });

  it('presence vs absence of requestNonce changes the ref', () => {
    const { requestNonce: _omitted, ...withoutNonce } = GOLDEN_PREIMAGE;
    expect(computeInstanceRef(withoutNonce)).not.toBe(computeInstanceRef(GOLDEN_PREIMAGE));
  });

  it('throws on an out-of-domain preimage instead of best-effort hashing', () => {
    expect(() =>
      computeInstanceRef({ ...GOLDEN_PREIMAGE, audience: 'café.example' }),
    ).toThrow(/domain/i);
  });
});

describe('verifyInstanceBinding', () => {
  it('receipt without an instance block: ok, not present', () => {
    const receipt = signPayload(createCommerceReceipt(makeCommerceInput(), TEST_CONFIG));
    expect(verifyInstanceBinding(receipt)).toEqual({ ok: true, present: false, code: 'absent' });
  });

  it('commerce receipt with a correct binding: ok and present', () => {
    const receipt = signPayload(makeBoundPayload());
    expect(verifyReceipt(receipt)).toBe(true);
    expect(verifyInstanceBinding(receipt)).toEqual({ ok: true, present: true, code: 'ok' });
  });

  it('auth-kind receipt carrying an instance block is rejected (v1 scope)', () => {
    const auth = createAuthReceipt(makeCommerceInput(), TEST_CONFIG);
    const payload: ReceiptPayload = {
      ...auth,
      instance: { ref: computeInstanceRef(GOLDEN_PREIMAGE), preimage: GOLDEN_PREIMAGE },
    };
    const result = verifyInstanceBinding(signPayload(payload));
    expect(result.ok).toBe(false);
    expect(result.code).toBe('wrong_kind');
  });

  it.each([
    ['null', null],
    ['array', []],
    ['string', 'x'],
    ['number', 7],
    ['missing ref', { preimage: GOLDEN_PREIMAGE }],
  ])(
    'malformed instance BLOCK (%s) fails deterministically instead of throwing',
    (_name, block) => {
      const payload = {
        ...createCommerceReceipt(makeCommerceInput(), TEST_CONFIG),
        instance: block,
      } as unknown as ReceiptPayload;
      const result = verifyInstanceBinding(signPayload(payload));
      expect(result.ok).toBe(false);
      expect(result.code).toBe('malformed_ref');
    },
  );

  it.each([
    ['missing prefix', 'e7a84dcc6ab62430d6f230ee03396cd250772f99990457a999cc255d1b579c12'],
    ['uppercase hex', 'birv1:' + 'AB'.repeat(32)],
    ['short digest', 'birv1:abcdef'],
    ['unknown version prefix', 'birv9:' + 'ab'.repeat(32)],
  ])('malformed ref (%s) is rejected before any hashing', (_name, badRef) => {
    const payload = makeBoundPayload();
    const tampered: ReceiptPayload = {
      ...payload,
      instance: { ...payload.instance!, ref: badRef },
    };
    const result = verifyInstanceBinding(signPayload(tampered));
    expect(result.ok).toBe(false);
    expect(result.code).toBe('malformed_ref');
  });

  it('out-of-domain preimage is rejected with its own code, not best-effort hashed', () => {
    const payload = makeBoundPayload();
    const tampered: ReceiptPayload = {
      ...payload,
      instance: {
        ref: payload.instance!.ref,
        preimage: { ...GOLDEN_PREIMAGE, audience: 'café.example' },
      },
    };
    const result = verifyInstanceBinding(signPayload(tampered));
    expect(result.ok).toBe(false);
    expect(result.code).toBe('out_of_domain');
  });

  it('tampered preimage field no longer matches the ref', () => {
    const payload = makeBoundPayload();
    const tampered: ReceiptPayload = {
      ...payload,
      instance: {
        ref: payload.instance!.ref,
        preimage: { ...GOLDEN_PREIMAGE, amountUsd: '9999.99' },
      },
    };
    const result = verifyInstanceBinding(signPayload(tampered));
    expect(result.ok).toBe(false);
    expect(result.code).toBe('ref_mismatch');
  });

  it('SPEC MOTIVATION: a signer-issued receipt with a wrong ref passes verifyReceipt but fails here', () => {
    // The issuer signs a payload whose instance.ref does not match its own
    // preimage. Signature verification cannot catch this; the semantic check must.
    const payload = makeBoundPayload();
    const wrongRef: ReceiptPayload = {
      ...payload,
      instance: {
        ref: computeInstanceRef({ ...GOLDEN_PREIMAGE, decisionAt: '2026-08-24T10:00:00.999Z' }),
        preimage: GOLDEN_PREIMAGE,
      },
    };
    const receipt = signPayload(wrongRef);
    expect(verifyReceipt(receipt)).toBe(true); // signature is genuinely valid
    const result = verifyInstanceBinding(receipt);
    expect(result.ok).toBe(false);
    expect(result.code).toBe('ref_mismatch');
  });

  it('post-signing tamper is caught by BOTH verifyReceipt and the semantic check', () => {
    const receipt = signPayload(makeBoundPayload());
    const tampered: SignedReceipt = {
      ...receipt,
      payload: {
        ...receipt.payload,
        instance: {
          ref: receipt.payload.instance!.ref,
          preimage: { ...GOLDEN_PREIMAGE, amountUsd: '0.01' },
        },
      },
    };
    expect(verifyReceipt(tampered)).toBe(false);
    expect(verifyInstanceBinding(tampered).ok).toBe(false);
  });

  it('external actionRef participates in the binding verbatim', () => {
    const withAction: InstancePreimage = {
      ...GOLDEN_PREIMAGE,
      actionRef: 'v2:' + 'ab'.repeat(32),
    };
    const receipt = signPayload(makeBoundPayload(withAction));
    expect(verifyInstanceBinding(receipt)).toEqual({ ok: true, present: true, code: 'ok' });

    const swapped: ReceiptPayload = {
      ...receipt.payload,
      instance: {
        ref: receipt.payload.instance!.ref,
        preimage: { ...withAction, actionRef: 'v2:' + 'cd'.repeat(32) },
      },
    };
    expect(verifyInstanceBinding(signPayload(swapped)).code).toBe('ref_mismatch');
  });
});

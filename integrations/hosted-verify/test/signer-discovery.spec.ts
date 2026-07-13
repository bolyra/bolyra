/**
 * GET /.well-known/bolyra-signers.json — Receipt Signer Discovery v1
 * (spec/receipt-signer-discovery-v1.md) for the preview's pinned signer.
 */
import { describe, it, expect } from 'vitest';
import { SELF, env } from 'cloudflare:test';
import worker, { type Env } from '../src/index';

const BASE = 'https://hosted-verify.test';
const WELL_KNOWN = `${BASE}/.well-known/bolyra-signers.json`;

// Shape assertions are inline: the installed @bolyra/receipts (published
// ~0.8.0) predates parseSignerDiscovery, and this suite tests the WORKER's
// output shape — canonical parser round-trips are covered in the receipts
// and gateway suites, which resolve local source/dist.
interface Doc {
  v: number;
  issuer: string;
  updatedAt: number;
  signers: Array<{ keyId: string; alg: string; signer: string }>;
}

describe('/.well-known/bolyra-signers.json', () => {
  it('serves a valid v1 document for the pinned signer, unauthenticated', async () => {
    const res = await SELF.fetch(WELL_KNOWN);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('application/json');
    const doc = (await res.json()) as Doc;
    expect(doc.v).toBe(1);
    expect(typeof doc.issuer).toBe('string');
    expect(typeof doc.updatedAt).toBe('number');
    expect(doc.signers).toHaveLength(1);
    expect(doc.signers[0].alg).toBe('ES256K');
    expect(doc.signers[0].signer).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(typeof doc.signers[0].keyId).toBe('string');
  });

  it('signer address is stable across requests (cached derivation)', async () => {
    const doc = (await (await SELF.fetch(WELL_KNOWN)).json()) as Doc;
    const doc2 = (await (await SELF.fetch(WELL_KNOWN)).json()) as Doc;
    expect(doc2.signers[0].signer).toBe(doc.signers[0].signer);
  });

  it('404s when no signer key is configured', async () => {
    const req = new Request(WELL_KNOWN);
    const res = await worker.fetch(req, { ...env, RECEIPT_SIGNER_KEY: '' } as Env);
    expect(res.status).toBe(404);
  });

  it('only answers GET', async () => {
    const res = await SELF.fetch(WELL_KNOWN, { method: 'POST' });
    expect(res.status).toBe(405);
  });
});

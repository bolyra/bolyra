/**
 * `test/fixtures/registrations.json` is committed cryptographic material. This
 * spec recomputes every entry with the package's own primitives so the file
 * cannot silently drift from `canonicalize`, `bindingDigest` or `credentialId`.
 */
import { describe, expect, it } from 'vitest';
import { VerifyDenial } from '../src/verify/verdict';
import { bindingDigest, verifyBindingSig } from '../src/verify/binding';
import { parseBinding, parseSig } from '../src/verify/bundle';
import { credentialId } from '../src/credential-id';
import registrations from './fixtures/registrations.json';
import { env } from 'cloudflare:test';
import mandate from './fixtures/mandate.json';

type Fixture = {
  body: { version: number; binding: unknown; signature: unknown; operator_pubkey: { x: string; y: string } };
  credential_id: string;
  binding_digest_hex: string;
};
const F = registrations as Record<string, Fixture>;

const point = (p: { x: string; y: string }) => ({ x: BigInt(p.x), y: BigInt(p.y) });

describe('registration fixtures', () => {
  it.each(Object.keys(F))('%s: digest and id recompute; the signature verifies unless the entry is the bad-signature case', (name) => {
    const f = F[name]!;
    const binding = parseBinding(f.body.binding);
    const digest = bindingDigest(binding);
    expect(digest.toString(16).padStart(64, '0')).toBe(f.binding_digest_hex);
    expect(credentialId(point(f.body.operator_pubkey), digest)).toBe(f.credential_id);
    const sig = parseSig(f.body.signature);
    const check = () =>
      verifyBindingSig(binding, { R8: point(sig.R8), S: BigInt(sig.S) }, point(f.body.operator_pubkey));
    if (name === 'badSig') {
      expect(check).toThrow(VerifyDenial);
    } else {
      expect(check).not.toThrow();
    }
  });

  it('valid and untrusted share a binding digest but not an id: the id is a function of the signer', () => {
    expect(F.untrusted!.binding_digest_hex).toBe(F.valid!.binding_digest_hex);
    expect(F.untrusted!.credential_id).not.toBe(F.valid!.credential_id);
  });

  it('badSig is valid2\'s binding with valid\'s signature', () => {
    expect(F.badSig!.body.binding).toEqual(F.valid2!.body.binding);
    expect(F.badSig!.body.signature).toEqual(F.valid!.body.signature);
    expect(F.badSig!.credential_id).toBe(F.valid2!.credential_id);
  });

  it('the deployment capability map is the mpp mandate vocabulary, verbatim', () => {
    expect(JSON.parse(env.CAPABILITY_MAP!)).toEqual(mandate.capability_map);
    expect(Object.keys(mandate.capability_map).sort()).toEqual([
      'mpp:financial:medium',
      'mpp:financial:small',
      'mpp:financial:unlimited',
    ]);
  });
});

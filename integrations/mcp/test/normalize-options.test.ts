/**
 * P2-2: normalizeOptions back-compat shim for attachBolyraProof callers.
 *
 * The third parameter of attachBolyraProof changed from BolyraConfig to
 * AttachProofOptions. normalizeOptions detects raw BolyraConfig objects
 * and wraps them as { sdkConfig: ... }.
 */

import { normalizeOptions } from '../src/client';
import type { AttachProofOptions } from '../src/client';
import type { BolyraConfig } from '../src/types';

jest.mock('@bolyra/sdk', () => ({}));

describe('normalizeOptions', () => {
  it('returns empty options for undefined input', () => {
    expect(normalizeOptions(undefined)).toEqual({});
  });

  it('passes through AttachProofOptions with devMode', () => {
    const input: AttachProofOptions = { devMode: true };
    expect(normalizeOptions(input)).toBe(input);
  });

  it('passes through AttachProofOptions with sdkConfig', () => {
    const input: AttachProofOptions = { sdkConfig: {} as BolyraConfig };
    expect(normalizeOptions(input)).toBe(input);
  });

  it('wraps a raw BolyraConfig as sdkConfig', () => {
    const rawConfig = { circuitDir: '/some/path', rpcUrl: 'http://localhost:8545' } as BolyraConfig;
    const result = normalizeOptions(rawConfig);
    expect(result).toEqual({ sdkConfig: rawConfig });
    expect((result as AttachProofOptions).sdkConfig).toBe(rawConfig);
  });

  it('wraps a BolyraConfig that has neither devMode nor sdkConfig', () => {
    const rawConfig = { registryAddress: '0xabc' } as any;
    const result = normalizeOptions(rawConfig);
    expect(result).toEqual({ sdkConfig: rawConfig });
  });
});

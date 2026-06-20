/**
 * Tests for withBolyraAuth() — language model wrapper middleware.
 */

import type { LanguageModelV1, LanguageModelV1CallOptions } from 'ai';
import { withBolyraAuth } from '../src/middleware';
import { createDevIdentities } from '@bolyra/sdk';

/** Create a minimal mock LanguageModelV1 for testing. */
function createMockModel(overrides: Partial<LanguageModelV1> = {}): LanguageModelV1 {
  return {
    specificationVersion: 'v1',
    provider: 'test-provider',
    modelId: 'test-model',
    defaultObjectGenerationMode: 'json',
    supportsUrl: undefined,
    doGenerate: jest.fn().mockResolvedValue({
      rawCall: { rawPrompt: '', rawSettings: {} },
      finishReason: 'stop' as const,
      usage: { promptTokens: 10, completionTokens: 5 },
      text: 'test response',
    }),
    doStream: jest.fn().mockResolvedValue({
      rawCall: { rawPrompt: '', rawSettings: {} },
      stream: new ReadableStream(),
    }),
    ...overrides,
  };
}

describe('withBolyraAuth', () => {
  it('throws when no credential, gateway, or devMode is provided', () => {
    const model = createMockModel();
    expect(() => withBolyraAuth(model, {})).toThrow(
      '@bolyra/ai: withBolyraAuth requires either `credential`, `gateway`, or `devMode: true`.',
    );
  });

  it('wraps a model and changes the modelId', () => {
    const model = createMockModel();
    const wrapped = withBolyraAuth(model, { devMode: true });
    expect(wrapped.modelId).toBe('bolyra:test-model');
  });

  it('preserves the provider', () => {
    const model = createMockModel();
    const wrapped = withBolyraAuth(model, { devMode: true });
    expect(wrapped.provider).toBe('test-provider');
  });

  it('returns a LanguageModelV1 with doGenerate and doStream', () => {
    const model = createMockModel();
    const wrapped = withBolyraAuth(model, { devMode: true });
    expect(typeof wrapped.doGenerate).toBe('function');
    expect(typeof wrapped.doStream).toBe('function');
  });

  it('works with dev mode using createDevIdentities', async () => {
    const devIds = await createDevIdentities();
    const model = createMockModel();
    const wrapped = withBolyraAuth(model, {
      credential: devIds.agent,
      devMode: true,
    });
    expect(wrapped.modelId).toBe('bolyra:test-model');
  });

  it('accepts gateway config without credential', () => {
    const model = createMockModel();
    const wrapped = withBolyraAuth(model, {
      gateway: { url: 'https://gateway.example.com', apiKey: 'gw_test' },
    });
    expect(wrapped.modelId).toBe('bolyra:test-model');
  });

  it('invokes the underlying model doGenerate through the wrapper', async () => {
    const doGenerate = jest.fn().mockResolvedValue({
      rawCall: { rawPrompt: '', rawSettings: {} },
      finishReason: 'stop' as const,
      usage: { promptTokens: 10, completionTokens: 5 },
      text: 'test response',
    });
    const model = createMockModel({ doGenerate });
    const wrapped = withBolyraAuth(model, { devMode: true });

    const params: LanguageModelV1CallOptions = {
      inputFormat: 'prompt',
      mode: { type: 'regular' },
      prompt: [{ role: 'user', content: [{ type: 'text', text: 'hello' }] }],
    };

    await wrapped.doGenerate(params);
    expect(doGenerate).toHaveBeenCalled();
  });
});

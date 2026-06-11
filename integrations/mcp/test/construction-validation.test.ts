/**
 * P2-1: resolveCredential construction-time validation.
 *
 * Both withBolyraAuthStdio and bolyraAuthMiddleware must throw immediately
 * when called without resolveCredential and devMode is not enabled.
 */

import { withBolyraAuthStdio } from '../src/server-stdio';
import { bolyraAuthMiddleware } from '../src/server-http';

jest.mock('@bolyra/sdk', () => ({}));

/** Minimal mock server with a tools/call handler already registered. */
function makeMockServer() {
  const handlers = new Map<string, Function>();
  handlers.set('tools/call', async () => ({ content: [] }));
  return {
    _requestHandlers: handlers,
    setRequestHandler: jest.fn(),
  };
}

describe('withBolyraAuthStdio construction-time validation', () => {
  it('throws when devMode is false and resolveCredential is missing', () => {
    expect(() =>
      withBolyraAuthStdio(makeMockServer() as any, { devMode: false }),
    ).toThrow(/resolveCredential is required when devMode is not enabled/);
  });

  it('throws when devMode is undefined and resolveCredential is missing', () => {
    expect(() =>
      withBolyraAuthStdio(makeMockServer() as any, {}),
    ).toThrow(/resolveCredential is required when devMode is not enabled/);
  });

  it('does not throw when devMode is true', () => {
    expect(() =>
      withBolyraAuthStdio(makeMockServer() as any, { devMode: true }),
    ).not.toThrow();
  });

  it('does not throw when resolveCredential is provided', () => {
    expect(() =>
      withBolyraAuthStdio(makeMockServer() as any, {
        resolveCredential: async () => null,
      }),
    ).not.toThrow();
  });
});

describe('bolyraAuthMiddleware construction-time validation', () => {
  it('throws when devMode is false and resolveCredential is missing', () => {
    expect(() =>
      bolyraAuthMiddleware({ devMode: false }),
    ).toThrow(/resolveCredential is required when devMode is not enabled/);
  });

  it('throws when devMode is undefined and resolveCredential is missing', () => {
    expect(() =>
      bolyraAuthMiddleware({}),
    ).toThrow(/resolveCredential is required when devMode is not enabled/);
  });

  it('does not throw when devMode is true', () => {
    expect(() =>
      bolyraAuthMiddleware({ devMode: true }),
    ).not.toThrow();
  });

  it('does not throw when resolveCredential is provided', () => {
    expect(() =>
      bolyraAuthMiddleware({ resolveCredential: async () => null }),
    ).not.toThrow();
  });
});

import { BolyraDeniedError, BolyraGateConfigError, isBolyraDeniedError } from '../src/errors';
import { handleDenials } from '../src/handle-denials';
import { deny } from '../src/types';
import { denyResponse } from '../src/deny';

describe('BolyraDeniedError', () => {
  test('carries the verdict and the Problem Details response', () => {
    const verdict = deny('scope_exceeded', 'required scope exceeds the credential scope');
    const err = new BolyraDeniedError(verdict, denyResponse(verdict));
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('BolyraDeniedError');
    expect(err.verdict.code).toBe('scope_exceeded');
    expect(err.response.status).toBe(403);
    expect(err.message).toContain('scope_exceeded');
  });
});

describe('handleDenials', () => {
  test('returns the denial response instead of propagating', async () => {
    const verdict = deny('missing_authorization', 'no header');
    const wrapped = handleDenials(async () => {
      throw new BolyraDeniedError(verdict, denyResponse(verdict));
    });
    const res = await wrapped(new Request('https://x'));
    expect(res).toBeInstanceOf(Response);
    expect((res as Response).status).toBe(401);
  });

  test('the returned denial response is the same object as err.response', async () => {
    const verdict = deny('missing_authorization', 'no header');
    const denialResponse = denyResponse(verdict);
    const wrapped = handleDenials(async () => {
      throw new BolyraDeniedError(verdict, denialResponse);
    });
    const res = await wrapped(new Request('https://x'));
    expect(res).toBe(denialResponse);
  });

  test('re-throws anything that is not a BolyraDeniedError', async () => {
    const wrapped = handleDenials(async () => {
      throw new TypeError('boom');
    });
    await expect(wrapped(new Request('https://x'))).rejects.toBeInstanceOf(TypeError);
  });

  test('passes through the handler result on success', async () => {
    const wrapped = handleDenials(async () => 'ok');
    await expect(wrapped(new Request('https://x'))).resolves.toBe('ok');
  });

  test('a Response returned by the handler passes through by identity', async () => {
    const okResponse = new Response('ok', { status: 200 });
    const wrapped = handleDenials(async () => okResponse);
    const res = await wrapped(new Request('https://x'));
    expect(res).toBe(okResponse);
  });

  test('forwards every argument through a variadic handler', async () => {
    const ctx = { params: { id: '42' } };
    let seen: unknown[] = [];
    const wrapped = handleDenials(async (req: Request, c: typeof ctx) => {
      seen = [req, c];
      return 'ok';
    });
    const req = new Request('https://x');
    await wrapped(req, ctx);
    expect(seen[0]).toBe(req);
    expect(seen[1]).toBe(ctx);
  });
});

describe('isBolyraDeniedError', () => {
  test('true for a real BolyraDeniedError instance', () => {
    const verdict = deny('missing_authorization', 'no header');
    const err = new BolyraDeniedError(verdict, denyResponse(verdict));
    expect(isBolyraDeniedError(err)).toBe(true);
  });

  test('true for a structurally matching plain object (a second hoisted copy)', () => {
    const shaped = {
      name: 'BolyraDeniedError',
      response: new Response(null, { status: 401 }),
      verdict: { code: 'x', message: 'y' },
    };
    expect(isBolyraDeniedError(shaped)).toBe(true);
  });

  test('false for an unrelated Error', () => {
    expect(isBolyraDeniedError(new Error('x'))).toBe(false);
  });

  test('false for null', () => {
    expect(isBolyraDeniedError(null)).toBe(false);
  });
});

test('BolyraGateConfigError is a named Error', () => {
  const e = new BolyraGateConfigError('bad hooks');
  expect(e.name).toBe('BolyraGateConfigError');
  expect(e).toBeInstanceOf(Error);
  expect(e.message).toBe('bad hooks');
});

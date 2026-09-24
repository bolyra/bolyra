import {
  BolyraDeniedError,
  BolyraGateConfigError,
  isBolyraDeniedError,
  isBolyraGateConfigError,
} from '../src/errors';
import { handleDenials, sendDenial } from '../src/handle-denials';
import { deny } from '../src/types';
import { denyProblem, denyResponse } from '../src/deny';

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

describe('sendDenial (Express-style res)', () => {
  function resSpy() {
    const writes: Array<[string, unknown[]]> = [];
    const res = {
      status: (code: number) => { writes.push(['status', [code]]); return res; },
      setHeader: (name: string, value: string) => { writes.push(['setHeader', [name, value]]); return res; },
      end: (body?: string) => { writes.push(['end', [body]]); return res; },
    };
    return { res, writes };
  }

  test('a denial writes status 401 + application/problem+json body exactly once and returns true', async () => {
    const verdict = deny('missing_authorization', 'no header');
    const err = new BolyraDeniedError(verdict, denyResponse(verdict));
    const { res, writes } = resSpy();
    expect(await sendDenial(err, res)).toBe(true);
    expect(writes.map(([m]) => m)).toEqual(['status', 'setHeader', 'end']);
    expect(writes[0]).toEqual(['status', [401]]);
    expect(writes[1]).toEqual(['setHeader', ['content-type', 'application/problem+json']]);
    const body = JSON.parse(writes[2]![1][0] as string);
    expect(body).toMatchObject({ status: 401, code: 'missing_authorization' });
    expect(writes.filter(([m]) => m === 'end')).toHaveLength(1);
  });

  test('a plain-Node-shaped res (statusCode property, no status()) gets statusCode assigned', async () => {
    const verdict = deny('scope_exceeded', 'over tier');
    const err = new BolyraDeniedError(verdict, denyResponse(verdict));
    const writes: Array<[string, unknown[]]> = [];
    const res = {
      statusCode: 200,
      setHeader: (name: string, value: string) => { writes.push(['setHeader', [name, value]]); },
      end: (body?: string) => { writes.push(['end', [body]]); },
    };
    expect(await sendDenial(err, res)).toBe(true);
    expect(res.statusCode).toBe(403);
    expect(writes.map(([m]) => m)).toEqual(['setHeader', 'end']);
    expect(JSON.parse(writes[1]![1][0] as string)).toMatchObject({ status: 403, code: 'scope_exceeded' });
  });

  test('headersSent: true returns false with zero writes (the response is already committed)', async () => {
    const verdict = deny('missing_authorization', 'no header');
    const err = new BolyraDeniedError(verdict, denyResponse(verdict));
    const { res, writes } = resSpy();
    expect(await sendDenial(err, { ...res, headersSent: true })).toBe(false);
    expect(writes).toEqual([]);
  });

  test('a non-denial returns false with no writes', async () => {
    const { res, writes } = resSpy();
    expect(await sendDenial(new Error('boom'), res)).toBe(false);
    expect(await sendDenial(undefined, res)).toBe(false);
    expect(writes).toEqual([]);
  });
});

describe('isBolyraGateConfigError', () => {
  test('true for a real BolyraGateConfigError instance', () => {
    expect(isBolyraGateConfigError(new BolyraGateConfigError('bad hooks'))).toBe(true);
  });

  test('true for a structurally matching plain object (a second hoisted copy)', () => {
    expect(isBolyraGateConfigError({ name: 'BolyraGateConfigError', message: 'bad hooks' })).toBe(true);
  });

  test('false for an unrelated Error, a denial, and null', () => {
    expect(isBolyraGateConfigError(new Error('x'))).toBe(false);
    const verdict = deny('missing_authorization', 'no header');
    expect(isBolyraGateConfigError(new BolyraDeniedError(verdict, denyResponse(verdict)))).toBe(false);
    expect(isBolyraGateConfigError(null)).toBe(false);
  });
});

describe('denyProblem: verdict detail (T8)', () => {
  const ID = 'ab'.repeat(32);

  test('copies string reason and credential_id from verdict.detail', async () => {
    const verdict = deny('untrusted_root', 'not active', { reason: 'credential_not_active', credential_id: ID });
    expect(denyProblem(verdict)).toEqual({
      type: 'https://bolyra.ai/problems/mpp/untrusted-root',
      title: 'Untrusted Issuer',
      status: 401,
      detail: 'not active',
      code: 'untrusted_root',
      reason: 'credential_not_active',
      credential_id: ID,
    });
    // The HTTP body carries the same fields.
    const body = await denyResponse(verdict).json();
    expect(body).toMatchObject({ reason: 'credential_not_active', credential_id: ID });
  });

  test('missing detail: the fields are absent (not undefined-valued)', () => {
    const problem = denyProblem(deny('expired', 'stale'));
    expect('reason' in problem).toBe(false);
    expect('credential_id' in problem).toBe(false);
  });

  test('non-string reason / credential_id are dropped', () => {
    const problem = denyProblem(deny('untrusted_root', 'x', { reason: 42, credential_id: { id: ID } }));
    expect('reason' in problem).toBe(false);
    expect('credential_id' in problem).toBe(false);
  });

  test('no other detail keys leak into the problem body', async () => {
    const verdict = deny('untrusted_root', 'x', {
      reason: 'credential_not_active', credential_id: ID, internal: 'db-host:5432', stack: 'at ...',
    });
    const problem = denyProblem(verdict);
    expect(Object.keys(problem).sort()).toEqual(
      ['code', 'credential_id', 'detail', 'reason', 'status', 'title', 'type'],
    );
    const body = await denyResponse(verdict).json();
    expect(body).not.toHaveProperty('internal');
    expect(body).not.toHaveProperty('stack');
  });

  test('a {code, message} pick without detail still works (existing callers)', () => {
    expect(denyProblem({ code: 'expired', message: 'm' })).toMatchObject({ code: 'expired', status: 403 });
  });
});

describe('denyProblem: reason is an identifier (T8 hardening)', () => {
  test('a free-text reason is dropped from the problem and the HTTP body', async () => {
    const verdict = deny('invalid_proof', 'agent: invalid proof envelope', { reason: 'Invalid circuit.name: x' });
    expect('reason' in denyProblem(verdict)).toBe(false);
    expect(await denyResponse(verdict).json()).not.toHaveProperty('reason');
    // Still reachable in-process on the verdict.
    expect(new BolyraDeniedError(verdict, denyResponse(verdict)).verdict.detail?.reason).toBe('Invalid circuit.name: x');
  });

  test.each(['Credential_not_active', 'credential-not-active', 'a'.repeat(65), '', 'has space', '2fa_failed', '_leading_underscore'])(
    'non-identifier reason %p is dropped', (reason) => {
      expect('reason' in denyProblem(deny('untrusted_root', 'x', { reason }))).toBe(false);
    },
  );

  test('identifiers with digits after the first char pass (tier_2_exceeded)', () => {
    expect(denyProblem(deny('scope_exceeded', 'x', { reason: 'tier_2_exceeded' })).reason).toBe('tier_2_exceeded');
  });

  test('identifier reasons pass through (credential_not_active, 64 chars)', () => {
    expect(denyProblem(deny('untrusted_root', 'x', { reason: 'credential_not_active' })).reason).toBe('credential_not_active');
    expect(denyProblem(deny('untrusted_root', 'x', { reason: 'a'.repeat(64) })).reason).toBe('a'.repeat(64));
  });

  test('credential_id is capped at 256 chars: 64-hex and 256 pass, 257 is dropped', async () => {
    const hex = 'ab'.repeat(32);
    expect(denyProblem(deny('untrusted_root', 'x', { credential_id: hex })).credential_id).toBe(hex);
    expect(denyProblem(deny('untrusted_root', 'x', { credential_id: 'c'.repeat(256) })).credential_id).toBe('c'.repeat(256));
    const long = deny('untrusted_root', 'x', { credential_id: 'c'.repeat(257) });
    expect('credential_id' in denyProblem(long)).toBe(false);
    expect(await denyResponse(long).json()).not.toHaveProperty('credential_id');
  });

  test('credential_id keeps the plain string rule', () => {
    expect(denyProblem(deny('untrusted_root', 'x', { credential_id: 'Not An Identifier!' })).credential_id).toBe('Not An Identifier!');
  });
});

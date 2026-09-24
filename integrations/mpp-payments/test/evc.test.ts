/**
 * External verifier transports — fail-closed host obligations (EVC v1 §5–§7):
 * command spawn (timeout, output cap, hostile output, exit codes) and hosted
 * URL mode (transport faults, invalid verdicts).
 */

import {
  runCommandVerifier,
  callUrlVerifier,
  callUrlVerifierWithEvidence,
  normalizeVerifierUrl,
  validateVerdict,
} from '../src/evc';
import type { VerifierRequest } from '../src/types';

const REQUEST: VerifierRequest = {
  version: 1,
  bundle: 'e30',
  request: {
    agent_name: 'a',
    project_key: 'p',
    program: 'mpp',
    model: 'm',
    granted_capabilities: ['mpp:financial:small'],
  },
  now_unix: 1751990400,
};

/** Spawn `node -e <script>` as the verifier command. */
function nodeVerifier(script: string, extra: { timeoutMs?: number; maxStdoutBytes?: number } = {}) {
  return runCommandVerifier(
    { command: process.execPath, args: ['-e', script], ...extra },
    REQUEST,
  );
}

describe('runCommandVerifier', () => {
  test('honors an allow verdict from a conforming verifier', async () => {
    const verdict = await nodeVerifier(
      `let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{
         JSON.parse(d); process.stdout.write(JSON.stringify({verdict:'allow'}));
       });`,
    );
    expect(verdict).toEqual({ verdict: 'allow' });
  });

  test('honors a deny verdict with a registry code', async () => {
    const verdict = await nodeVerifier(
      `process.stdout.write(JSON.stringify({verdict:'deny',code:'scope_exceeded',message:'no'}));`,
    );
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'scope_exceeded' });
  });

  test('fails closed on garbage stdout', async () => {
    const verdict = await nodeVerifier(`process.stdout.write('ALLOW!!');`);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
  });

  test('fails closed on a schema-violating verdict (open schema)', async () => {
    const verdict = await nodeVerifier(
      `process.stdout.write(JSON.stringify({verdict:'allow',bonus:'field'}));`,
    );
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
  });

  test('fails closed when the verifier times out (SIGKILL)', async () => {
    const verdict = await nodeVerifier(`setTimeout(()=>{}, 60000);`, { timeoutMs: 500 });
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
  }, 15000);

  test('fails closed when stdout exceeds the cap', async () => {
    const verdict = await nodeVerifier(
      `process.stdout.write('x'.repeat(4096));`,
      { maxStdoutBytes: 1024 },
    );
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
  });

  test('an allow paired with a non-zero exit fails closed (spec §7.1)', async () => {
    const verdict = await nodeVerifier(
      `process.stdout.write(JSON.stringify({verdict:'allow'}));process.exit(3);`,
    );
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
  });

  test('fails closed when the command cannot be spawned', async () => {
    const verdict = await runCommandVerifier(
      { command: '/nonexistent/verifier-binary' },
      REQUEST,
    );
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
  });
});

describe('callUrlVerifier', () => {
  const originalFetch = global.fetch;
  afterEach(() => {
    global.fetch = originalFetch;
  });

  function stubFetch(status: number, body: unknown) {
    global.fetch = jest.fn(async () =>
      new Response(typeof body === 'string' ? body : JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
      }),
    ) as unknown as typeof fetch;
  }

  test('honors a 200 allow verdict and sends the bearer token', async () => {
    stubFetch(200, { verdict: 'allow', kind: 'classical' });
    const verdict = await callUrlVerifier(
      { url: 'https://verify.example/v1/verify', token: 'tok' },
      REQUEST,
    );
    expect(verdict).toMatchObject({ verdict: 'allow', kind: 'classical' });
    const call = (global.fetch as jest.Mock).mock.calls[0];
    expect(call[1].headers.authorization).toBe('Bearer tok');
    expect(JSON.parse(call[1].body)).toMatchObject({ version: 1, bundle: 'e30' });
  });

  test('honors a 200 deny verdict (decisions ride status 200)', async () => {
    stubFetch(200, { verdict: 'deny', code: 'expired', message: 'stale', kind: 'classical' });
    const verdict = await callUrlVerifier({ url: 'https://verify.example' }, REQUEST);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'expired' });
  });

  test('fails closed on transport-level statuses (401/404/…)', async () => {
    stubFetch(401, { error: 'bad token' });
    const verdict = await callUrlVerifier({ url: 'https://verify.example' }, REQUEST);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
  });

  test('fails closed on invalid verdict bodies', async () => {
    stubFetch(200, { verdict: 'maybe' });
    const verdict = await callUrlVerifier({ url: 'https://verify.example' }, REQUEST);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
  });

  test('fails closed when fetch rejects (unreachable endpoint)', async () => {
    global.fetch = jest.fn(async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    const verdict = await callUrlVerifier({ url: 'https://verify.example' }, REQUEST);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
  });

  test('a 500 body may only carry deny internal_error', async () => {
    stubFetch(500, { verdict: 'allow' });
    const verdict = await callUrlVerifier({ url: 'https://verify.example' }, REQUEST);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
  });

  test('fails closed when the response body exceeds the cap', async () => {
    stubFetch(200, `{"verdict":"allow","kind":"${'x'.repeat(4096)}"}`);
    const verdict = await callUrlVerifier(
      { url: 'https://verify.example', maxBodyBytes: 1024 },
      REQUEST,
    );
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
  });
});

describe('callUrlVerifierWithEvidence', () => {
  const originalFetch = global.fetch;
  afterEach(() => {
    global.fetch = originalFetch;
  });
  const ID = 'ab'.repeat(32);

  function stubFetch(status: number, body: unknown, headers: Record<string, string> = {}) {
    global.fetch = jest.fn(async () =>
      new Response(typeof body === 'string' ? body : JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json', ...headers },
      }),
    ) as unknown as typeof fetch;
  }

  test('allow: returns the verdict, HTTP status, and the raw credential-id / receipt headers', async () => {
    stubFetch(200, { verdict: 'allow', kind: 'classical' }, {
      'x-bolyra-credential-id': ID,
      'x-bolyra-receipt': 'eyJhbGciOiJFUzI1NksifQ.e30.c2ln',
    });
    const evidence = await callUrlVerifierWithEvidence({ url: 'https://verify.example/v1/verify' }, REQUEST);
    expect(evidence).toEqual({
      verdict: { verdict: 'allow', kind: 'classical' },
      status: 200,
      credentialId: ID,
      receipt: 'eyJhbGciOiJFUzI1NksifQ.e30.c2ln',
    });
  });

  test('headers absent: credentialId / receipt are absent (not undefined-valued)', async () => {
    stubFetch(200, { verdict: 'allow' });
    const evidence = await callUrlVerifierWithEvidence({ url: 'https://verify.example/v1/verify' }, REQUEST);
    expect(evidence).toEqual({ verdict: { verdict: 'allow' }, status: 200 });
    expect('credentialId' in evidence).toBe(false);
    expect('receipt' in evidence).toBe(false);
  });

  test('a 200 deny keeps its detail and reports status 200', async () => {
    stubFetch(200, {
      verdict: 'deny', code: 'untrusted_root', message: 'not active',
      detail: { reason: 'credential_not_active', credential_id: ID },
    });
    const evidence = await callUrlVerifierWithEvidence({ url: 'https://verify.example/v1/verify' }, REQUEST);
    expect(evidence.status).toBe(200);
    expect(evidence.verdict).toEqual({
      verdict: 'deny', code: 'untrusted_root', message: 'not active',
      detail: { reason: 'credential_not_active', credential_id: ID },
    });
  });

  test.each([401, 404, 429, 503])('non-2xx status %i fails closed and reports the status', async (status) => {
    stubFetch(status, { error: 'nope' });
    const evidence = await callUrlVerifierWithEvidence({ url: 'https://verify.example/v1/verify' }, REQUEST);
    expect(evidence.status).toBe(status);
    expect(evidence.verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
  });

  test('a 500 deny internal_error is honored with status 500', async () => {
    stubFetch(500, { verdict: 'deny', code: 'internal_error', message: 'storage unavailable' });
    const evidence = await callUrlVerifierWithEvidence({ url: 'https://verify.example/v1/verify' }, REQUEST);
    expect(evidence).toEqual({
      verdict: { verdict: 'deny', code: 'internal_error', message: 'storage unavailable' },
      status: 500,
    });
  });

  test('no HTTP response (unreachable): status is absent, verdict fails closed', async () => {
    global.fetch = jest.fn(async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    const evidence = await callUrlVerifierWithEvidence({ url: 'https://verify.example/v1/verify' }, REQUEST);
    expect(evidence.verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
    expect('status' in evidence).toBe(false);
  });

  test('callUrlVerifier returns exactly the bare verdict (shape preserved)', async () => {
    stubFetch(200, { verdict: 'allow', kind: 'classical' }, { 'x-bolyra-credential-id': ID });
    const verdict = await callUrlVerifier({ url: 'https://verify.example/v1/verify' }, REQUEST);
    expect(verdict).toEqual({ verdict: 'allow', kind: 'classical' });
  });
});

describe('normalizeVerifierUrl (TD-1)', () => {
  test.each([
    ['https://verify.example', 'https://verify.example/v1/verify'],
    ['https://verify.example/', 'https://verify.example/v1/verify'],
    ['https://verify.example?x=1', 'https://verify.example/v1/verify?x=1'],
    ['https://verify.example/?x=1', 'https://verify.example/v1/verify?x=1'],
    ['https://[::1]:8787', 'https://[::1]:8787/v1/verify'],
    ['http://[2001:db8::1]/', 'http://[2001:db8::1]/v1/verify'],
    ['https://verify.example#frag', 'https://verify.example/v1/verify#frag'],
    ['https://verify.example/?x=1#frag', 'https://verify.example/v1/verify?x=1#frag'],
  ])('a root path is rewritten to /v1/verify: %s', (input, expected) => {
    expect(normalizeVerifierUrl(input)).toBe(expected);
  });

  test.each([
    'https://verify.example/v1/verify',
    'https://verify.test/v1/verify',
    'https://verify.example/custom/',
    'https://verify.example/custom/?x=1',
    'https://verify.example/custom',
    'https://verify.example/v1/verify/',
    'https://VERIFY.example:8443/Custom?b=2&a=1',
    'https://[::1]:8787/custom/',
    'https://verify.example/custom#frag',
    // Dot segments are NOT roots: URL parsing would collapse them to '/', but
    // eligibility is decided on the original string's path portion.
    'https://verify.example/custom/..',
    'https://verify.example/%2e',
    'https://verify.example/./',
    'https://verify.example/..',
    'https://verify.example/..?x=1',
    // Backslash paths are not roots either (WHATWG reads '\\' as '/').
    'https://verify.example\\custom',
  ])('every other path is preserved byte-for-byte: %s', (input) => {
    expect(normalizeVerifierUrl(input)).toBe(input);
  });

  test('is exported from the package entry point', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const entry = require('../src/index');
    expect(entry.normalizeVerifierUrl).toBe(normalizeVerifierUrl);
  });

  test('an invalid URL throws', () => {
    expect(() => normalizeVerifierUrl('not a url')).toThrow();
  });

  test.each([
    'https://verify.example ',
    'https://verify.example/ ',
    ' https://verify.example',
    '\thttps://verify.example/v1/verify',
    'https://verify.example/v1/verify\n',
  ])('leading/trailing whitespace is refused, never trimmed: %p', (url) => {
    expect(() => normalizeVerifierUrl(url)).toThrow(TypeError);
  });

  test('a URL without a scheme://authority form throws (no ambiguous path portion)', () => {
    expect(() => normalizeVerifierUrl('https:verify.example')).toThrow(TypeError);
  });

  describe('inside callUrlVerifierWithEvidence (direct callers)', () => {
    const originalFetch = global.fetch;
    afterEach(() => {
      global.fetch = originalFetch;
    });
    function spyFetch() {
      const spy = jest.fn(async () =>
        new Response(JSON.stringify({ verdict: 'allow' }), { status: 200, headers: { 'content-type': 'application/json' } }),
      );
      global.fetch = spy as unknown as typeof fetch;
      return spy;
    }

    test.each([
      ['https://verify.example', 'https://verify.example/v1/verify'],
      ['https://verify.example/', 'https://verify.example/v1/verify'],
      ['https://verify.example/custom/?x=1', 'https://verify.example/custom/?x=1'],
    ])('%s is fetched as %s', async (url, expected) => {
      const spy = spyFetch();
      await callUrlVerifierWithEvidence({ url }, REQUEST);
      expect((spy.mock.calls[0] as unknown[])[0]).toBe(expected);
    });

    test.each(['https://verify.example ', 'https://verify.example/ '])(
      'whitespace-padded %p fails closed (deny internal_error) without fetching',
      async (url) => {
        const spy = spyFetch();
        const evidence = await callUrlVerifierWithEvidence({ url }, REQUEST);
        expect(evidence.verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
        expect(spy).not.toHaveBeenCalled();
      },
    );

    test('an invalid URL fails closed without fetching', async () => {
      const spy = spyFetch();
      const evidence = await callUrlVerifierWithEvidence({ url: 'not a url' }, REQUEST);
      expect(evidence.verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
      expect(spy).not.toHaveBeenCalled();
    });
  });
});

describe('validateVerdict', () => {
  test('accepts the closed allow/deny schemas', () => {
    expect(validateVerdict({ verdict: 'allow' })).toEqual({ verdict: 'allow' });
    expect(
      validateVerdict({
        verdict: 'allow',
        consume_nonces: [{ issuer_key: 'k', nonce: 'n', retain_until: 1 }],
      }),
    ).not.toBeNull();
    expect(
      validateVerdict({ verdict: 'deny', code: 'expired', message: 'm', detail: { a: 1 } }),
    ).not.toBeNull();
  });

  test('rejects unknown members, unknown codes, and wrong types', () => {
    expect(validateVerdict({ verdict: 'deny', code: 'nope', message: 'm' })).toBeNull();
    expect(validateVerdict({ verdict: 'deny', code: 'expired' })).toBeNull();
    expect(validateVerdict({ verdict: 'allow', extra: true })).toBeNull();
    expect(
      validateVerdict({
        verdict: 'allow',
        consume_nonces: [{ issuer_key: 'k', nonce: 'n', retain_until: 1, extra: 2 }],
      }),
    ).toBeNull();
    expect(validateVerdict('allow')).toBeNull();
    expect(validateVerdict(null)).toBeNull();
  });

  test('rejects unrecognized kind values (spec §3.5 closed vocabulary)', () => {
    expect(validateVerdict({ verdict: 'allow', kind: 'quantum' })).toBeNull();
    expect(validateVerdict({ verdict: 'deny', code: 'expired', message: 'm', kind: 'maybe' })).toBeNull();
    expect(validateVerdict({ verdict: 'allow', kind: 'external' })).not.toBeNull();
  });

  test('rejects empty consume_nonces (minItems 1: omitted, never []) and non-integer retain_until', () => {
    expect(validateVerdict({ verdict: 'allow', consume_nonces: [] })).toBeNull();
    expect(
      validateVerdict({
        verdict: 'allow',
        consume_nonces: [{ issuer_key: 'k', nonce: 'n', retain_until: 1.5 }],
      }),
    ).toBeNull();
  });
});

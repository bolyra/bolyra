/**
 * External verifier transports — fail-closed host obligations (EVC v1 §5–§7):
 * command spawn (timeout, output cap, hostile output, exit codes) and hosted
 * URL mode (transport faults, invalid verdicts).
 */

import { runCommandVerifier, callUrlVerifier, validateVerdict } from '../src/evc';
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

import { promises as fs } from 'fs';
import * as os from 'os';
import * as path from 'path';

import { FileNonceStore, buildConsumeNonce } from '../../src/verify/nonce-store';

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

describe('FileNonceStore (local nonce mode)', () => {
  let dir: string;
  let store: FileNonceStore;

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bolyra-nonce-'));
    store = new FileNonceStore(dir);
  });

  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('marks a never-seen key fresh, then rejects an immediate replay', async () => {
    expect(await store.markIfFresh('nonce-a', 60)).toBe(true);
    expect(await store.markIfFresh('nonce-a', 60)).toBe(false);
  });

  it('treats distinct keys independently', async () => {
    expect(await store.markIfFresh('123', 60)).toBe(true);
    expect(await store.markIfFresh('456', 60)).toBe(true);
    expect(await store.markIfFresh('123', 60)).toBe(false);
  });

  it('allows re-use once the entry has expired', async () => {
    // Short TTL so the entry expires quickly, then a fresh mark succeeds again.
    expect(await store.markIfFresh('nonce-ttl', 0.05)).toBe(true);
    await sleep(120);
    expect(await store.markIfFresh('nonce-ttl', 60)).toBe(true);
    // ...and is now protected again at the new TTL.
    expect(await store.markIfFresh('nonce-ttl', 60)).toBe(false);
  });

  it('is durable across store instances backed by the same dir', async () => {
    expect(await store.markIfFresh('durable', 60)).toBe(true);
    const reopened = new FileNonceStore(dir);
    expect(await reopened.markIfFresh('durable', 60)).toBe(false);
  });

  it('yields exactly one true under concurrent marks of the same fresh key', async () => {
    const attempts = 50;
    const results = await Promise.all(
      Array.from({ length: attempts }, () => store.markIfFresh('race', 60)),
    );
    expect(results.filter((r) => r === true)).toHaveLength(1);
    expect(results.filter((r) => r === false)).toHaveLength(attempts - 1);
  });
});

describe('buildConsumeNonce (host nonce mode)', () => {
  it('builds the consume_nonce instruction shape', () => {
    expect(buildConsumeNonce('123', 'zPub', 1720003600)).toEqual({
      issuer_key: 'zPub',
      nonce: '123',
      retain_until: 1720003600,
    });
  });
});

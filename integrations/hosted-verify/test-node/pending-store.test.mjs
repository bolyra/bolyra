// The canary pending store (scripts/lib/pending-store.mjs): one file per credential id in a
// directory, created atomically (`wx`) and removed with a single unlink, so concurrent
// verify-deploy runs can never overwrite or lose each other's unresolved entries.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pendingStore } from '../scripts/lib/pending-store.mjs';

const A = 'a'.repeat(64);
const B = 'b'.repeat(64);
const lineOf = (id) => `2026-09-24T00:00:00.000Z staging canary ${id} pending`;

function withDir(fn) {
  const root = mkdtempSync(path.join(tmpdir(), 'pending-store-'));
  try {
    return fn(path.join(root, 'canary-pending-staging'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test('interleaved runs: append A, append B, remove A leaves exactly B (with its line)', () =>
  withDir((dir) => {
    const runA = pendingStore(dir);
    const runB = pendingStore(dir);
    runA.append(A, lineOf(A));
    runB.append(B, lineOf(B));
    runA.remove(A);
    assert.deepEqual(readdirSync(dir), [`${B}.pending`]);
    assert.equal(readFileSync(path.join(dir, `${B}.pending`), 'utf8'), `${lineOf(B)}\n`);
  }));

test('the directory is 0700 and each record 0600', () =>
  withDir((dir) => {
    pendingStore(dir).append(A, lineOf(A));
    assert.equal(statSync(dir).mode & 0o777, 0o700);
    assert.equal(statSync(path.join(dir, `${A}.pending`)).mode & 0o777, 0o600);
  }));

test('removing a record that does not exist (or a missing directory) is a no-op', () =>
  withDir((dir) => {
    pendingStore(dir).remove(A);
    pendingStore(dir).append(B, lineOf(B));
    pendingStore(dir).remove(A);
    assert.deepEqual(readdirSync(dir), [`${B}.pending`]);
  }));

test('a duplicate id is refused (atomic exclusive create), and the first record is untouched', () =>
  withDir((dir) => {
    const s = pendingStore(dir);
    s.append(A, lineOf(A));
    assert.throws(() => s.append(A, 'overwritten'), { code: 'EEXIST' });
    assert.equal(readFileSync(path.join(dir, `${A}.pending`), 'utf8'), `${lineOf(A)}\n`);
  }));

test('only 64-hex ids become file names', () =>
  withDir((dir) => {
    const s = pendingStore(dir);
    for (const bad of ['../x', 'A'.repeat(64), 'a'.repeat(63), '']) {
      assert.throws(() => s.append(bad, 'x'), /credential id/);
      assert.throws(() => s.remove(bad), /credential id/);
    }
  }));

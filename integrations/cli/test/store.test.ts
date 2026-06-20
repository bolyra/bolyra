import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  ensureStoreDir,
  saveCredential,
  loadCredential,
  listCredentials,
  revokeCredential,
  deleteCredential,
} from '../src/store';
import type { StoredCredential } from '../src/format';

function makeCred(commitment: string = '12345678901234567890'): StoredCredential {
  return {
    commitment,
    modelHash: '99887766554433221100',
    modelName: 'test-model',
    operatorPublicKey: { x: '111', y: '222' },
    permissionBitmask: '7',
    expiryTimestamp: String(Math.floor(Date.now() / 1000) + 86400),
    signature: { R8: { x: '333', y: '444' }, S: '555' },
    createdAt: new Date().toISOString(),
    revoked: false,
    revokedAt: null,
    revokedReason: null,
  };
}

describe('credential store', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-cli-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('ensureStoreDir creates directory', () => {
    const dir = path.join(tmpDir, 'sub', 'dir');
    const result = ensureStoreDir(dir);
    expect(result).toBe(dir);
    expect(fs.existsSync(dir)).toBe(true);
  });

  it('saveCredential writes a JSON file', () => {
    const cred = makeCred();
    const filePath = saveCredential(cred, tmpDir);
    expect(fs.existsSync(filePath)).toBe(true);
    const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    expect(data.commitment).toBe(cred.commitment);
  });

  it('loadCredential reads back saved credential', () => {
    const cred = makeCred();
    saveCredential(cred, tmpDir);
    const loaded = loadCredential(cred.commitment, tmpDir);
    expect(loaded).not.toBeNull();
    expect(loaded!.commitment).toBe(cred.commitment);
    expect(loaded!.modelName).toBe('test-model');
  });

  it('loadCredential returns null for missing credential', () => {
    expect(loadCredential('nonexistent', tmpDir)).toBeNull();
  });

  it('listCredentials returns all credentials', () => {
    saveCredential(makeCred('111'), tmpDir);
    saveCredential(makeCred('222'), tmpDir);
    const creds = listCredentials(tmpDir);
    expect(creds).toHaveLength(2);
  });

  it('listCredentials returns empty for empty store', () => {
    expect(listCredentials(tmpDir)).toHaveLength(0);
  });

  it('listCredentials returns empty for nonexistent directory', () => {
    expect(listCredentials(path.join(tmpDir, 'nonexistent'))).toHaveLength(0);
  });

  it('revokeCredential marks credential as revoked', () => {
    const cred = makeCred();
    saveCredential(cred, tmpDir);
    const revoked = revokeCredential(cred.commitment, 'test reason', tmpDir);
    expect(revoked.revoked).toBe(true);
    expect(revoked.revokedAt).toBeTruthy();
    expect(revoked.revokedReason).toBe('test reason');

    // Verify persisted
    const loaded = loadCredential(cred.commitment, tmpDir);
    expect(loaded!.revoked).toBe(true);
  });

  it('revokeCredential throws for missing credential', () => {
    expect(() => revokeCredential('nonexistent', undefined, tmpDir)).toThrow('not found');
  });

  it('deleteCredential removes a credential file', () => {
    const cred = makeCred();
    saveCredential(cred, tmpDir);
    expect(deleteCredential(cred.commitment, tmpDir)).toBe(true);
    expect(loadCredential(cred.commitment, tmpDir)).toBeNull();
  });

  it('deleteCredential returns false for missing credential', () => {
    expect(deleteCredential('nonexistent', tmpDir)).toBe(false);
  });
});

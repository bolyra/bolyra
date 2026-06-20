import {
  permissionsAbbrev,
  permissionsFullNames,
  bitmaskBinary,
  credentialStatus,
  timeRemaining,
  formatTimestamp,
  formatCredentialInspect,
  formatCredentialTable,
} from '../src/format';
import type { StoredCredential } from '../src/format';

describe('permissionsAbbrev', () => {
  it('converts bitmask to abbreviations', () => {
    expect(permissionsAbbrev(0b00000111n)).toBe('RW$');
  });

  it('handles all permissions', () => {
    expect(permissionsAbbrev(0b11111111n)).toBe('RW$$$$$$SDP');
  });

  it('handles single permission', () => {
    expect(permissionsAbbrev(0b00000001n)).toBe('R');
  });
});

describe('permissionsFullNames', () => {
  it('lists full permission names', () => {
    expect(permissionsFullNames(0b00000011n)).toBe('READ_DATA, WRITE_DATA');
  });
});

describe('bitmaskBinary', () => {
  it('formats as 8-bit binary', () => {
    expect(bitmaskBinary(7n)).toBe('0b00000111');
    expect(bitmaskBinary(255n)).toBe('0b11111111');
    expect(bitmaskBinary(0n)).toBe('0b00000000');
  });
});

describe('credentialStatus', () => {
  it('returns active for future expiry', () => {
    const future = BigInt(Math.floor(Date.now() / 1000) + 86400);
    expect(credentialStatus(future, false)).toBe('active');
  });

  it('returns expired for past expiry', () => {
    expect(credentialStatus(1000n, false)).toBe('expired');
  });

  it('returns revoked when revoked flag is set', () => {
    const future = BigInt(Math.floor(Date.now() / 1000) + 86400);
    expect(credentialStatus(future, true)).toBe('revoked');
  });

  it('revoked takes precedence over expired', () => {
    expect(credentialStatus(1000n, true)).toBe('revoked');
  });
});

describe('timeRemaining', () => {
  it('returns expired for past timestamps', () => {
    expect(timeRemaining(1000n)).toBe('expired');
  });

  it('returns days for future timestamps', () => {
    const future = BigInt(Math.floor(Date.now() / 1000) + 86400 * 10);
    const result = timeRemaining(future);
    expect(result).toMatch(/\d+d remaining/);
  });
});

describe('formatTimestamp', () => {
  it('formats Unix timestamp as ISO-8601', () => {
    const result = formatTimestamp(1750000000n);
    expect(result).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});

function makeCredential(overrides: Partial<StoredCredential> = {}): StoredCredential {
  return {
    commitment: '12345678901234567890',
    modelHash: '99887766554433221100',
    modelName: 'gpt-4o',
    operatorPublicKey: { x: '111', y: '222' },
    permissionBitmask: '7',
    expiryTimestamp: String(Math.floor(Date.now() / 1000) + 86400),
    signature: { R8: { x: '333', y: '444' }, S: '555' },
    createdAt: new Date().toISOString(),
    revoked: false,
    revokedAt: null,
    revokedReason: null,
    ...overrides,
  };
}

describe('formatCredentialInspect', () => {
  it('formats an active credential', () => {
    const cred = makeCredential();
    const output = formatCredentialInspect(cred);
    expect(output).toContain('Credential:');
    expect(output).toContain('Model hash:');
    expect(output).toContain('Model name:');
    expect(output).toContain('gpt-4o');
    expect(output).toContain('Permissions:');
    expect(output).toContain('active');
  });

  it('formats a revoked credential', () => {
    const cred = makeCredential({
      revoked: true,
      revokedAt: '2026-06-19T12:00:00Z',
      revokedReason: 'compromised',
    });
    const output = formatCredentialInspect(cred);
    expect(output).toContain('revoked');
    expect(output).toContain('compromised');
  });
});

describe('formatCredentialTable', () => {
  it('formats a table of credentials', () => {
    const creds = [makeCredential(), makeCredential({ modelName: 'claude-4' })];
    const output = formatCredentialTable(creds);
    expect(output).toContain('COMMITMENT');
    expect(output).toContain('gpt-4o');
    expect(output).toContain('claude-4');
  });

  it('returns empty message for no credentials', () => {
    expect(formatCredentialTable([])).toBe('No credentials found.');
  });
});

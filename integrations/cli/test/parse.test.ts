import {
  parseDuration,
  parseExpiry,
  parsePermissions,
  serializeBigInt,
  truncateHex,
  parseKeyFile,
} from '../src/parse';
import { Permission } from '@bolyra/sdk';

describe('parseDuration', () => {
  it('parses seconds', () => {
    expect(parseDuration('60s')).toBe(60);
  });

  it('parses minutes', () => {
    expect(parseDuration('5m')).toBe(300);
  });

  it('parses hours', () => {
    expect(parseDuration('24h')).toBe(86400);
  });

  it('parses days', () => {
    expect(parseDuration('30d')).toBe(2592000);
  });

  it('parses weeks', () => {
    expect(parseDuration('2w')).toBe(1209600);
  });

  it('parses years', () => {
    expect(parseDuration('1y')).toBe(31536000);
  });

  it('returns null for invalid input', () => {
    expect(parseDuration('abc')).toBeNull();
    expect(parseDuration('')).toBeNull();
    expect(parseDuration('30')).toBeNull();
    expect(parseDuration('d30')).toBeNull();
  });
});

describe('parseExpiry', () => {
  it('parses duration string as relative to now', () => {
    const before = BigInt(Math.floor(Date.now() / 1000) + 86400);
    const result = parseExpiry('1d');
    const after = BigInt(Math.floor(Date.now() / 1000) + 86400);
    expect(result).toBeGreaterThanOrEqual(before);
    expect(result).toBeLessThanOrEqual(after);
  });

  it('parses Unix timestamp', () => {
    const futureTs = Math.floor(Date.now() / 1000) + 86400;
    expect(parseExpiry(String(futureTs))).toBe(BigInt(futureTs));
  });

  it('rejects past Unix timestamp', () => {
    expect(() => parseExpiry('1000000000')).toThrow('Expiry must be in the future');
  });

  it('rejects zero duration', () => {
    expect(() => parseDuration('0d')).toThrow('Duration must be positive');
  });

  it('throws on invalid input', () => {
    expect(() => parseExpiry('abc')).toThrow('Invalid expiry');
  });
});

describe('parsePermissions', () => {
  it('parses comma-separated permission names', () => {
    const perms = parsePermissions('read,write');
    expect(perms).toContain(Permission.READ_DATA);
    expect(perms).toContain(Permission.WRITE_DATA);
  });

  it('handles case-insensitive names', () => {
    const perms = parsePermissions('READ_DATA,WRITE_DATA');
    expect(perms).toContain(Permission.READ_DATA);
    expect(perms).toContain(Permission.WRITE_DATA);
  });

  it('handles aliases', () => {
    const perms = parsePermissions('sign,delegate,pii');
    expect(perms).toContain(Permission.SIGN_ON_BEHALF);
    expect(perms).toContain(Permission.SUB_DELEGATE);
    expect(perms).toContain(Permission.ACCESS_PII);
  });

  it('deduplicates', () => {
    const perms = parsePermissions('read,read,read');
    expect(perms).toHaveLength(1);
  });

  it('throws on unknown permission', () => {
    expect(() => parsePermissions('read,unknown')).toThrow('Unknown permission');
  });

  it('throws on empty input', () => {
    expect(() => parsePermissions('')).toThrow('At least one permission');
  });

  it('validates cumulative encoding', () => {
    // financial_medium without financial_small should fail
    expect(() => parsePermissions('financial_medium')).toThrow();
  });
});

describe('serializeBigInt', () => {
  it('converts bigint to string', () => {
    expect(serializeBigInt(123n)).toBe('123');
  });

  it('handles nested objects', () => {
    const result = serializeBigInt({ a: 1n, b: { c: 2n } });
    expect(result).toEqual({ a: '1', b: { c: '2' } });
  });

  it('handles arrays', () => {
    expect(serializeBigInt([1n, 2n])).toEqual(['1', '2']);
  });

  it('passes through primitives', () => {
    expect(serializeBigInt('hello')).toBe('hello');
    expect(serializeBigInt(42)).toBe(42);
    expect(serializeBigInt(null)).toBeNull();
    expect(serializeBigInt(undefined)).toBeUndefined();
  });

  it('converts Buffer to hex', () => {
    const buf = Buffer.from([0xde, 0xad]);
    expect(serializeBigInt(buf)).toBe('dead');
  });
});

describe('truncateHex', () => {
  it('truncates long hex values', () => {
    const big = 0x1234567890abcdef1234567890abcdef1234567890abcdefn;
    const result = truncateHex(big);
    expect(result).toMatch(/^0x.+\.\.\..+$/);
  });

  it('does not truncate short values', () => {
    expect(truncateHex(0xabcdn)).toBe('0xabcd');
  });
});

describe('parseKeyFile', () => {
  it('accepts 32 raw bytes', () => {
    const buf = Buffer.alloc(32, 0xaa);
    expect(parseKeyFile(buf)).toEqual(buf);
  });

  it('accepts 64 hex chars', () => {
    const hex = 'a'.repeat(64);
    const buf = Buffer.from(hex, 'utf-8');
    const result = parseKeyFile(buf);
    expect(result).toEqual(Buffer.from(hex, 'hex'));
  });

  it('accepts hex with 0x prefix', () => {
    const hex = '0x' + 'b'.repeat(64);
    const buf = Buffer.from(hex, 'utf-8');
    const result = parseKeyFile(buf);
    expect(result).toEqual(Buffer.from('b'.repeat(64), 'hex'));
  });

  it('rejects invalid content', () => {
    expect(() => parseKeyFile(Buffer.from('short'))).toThrow('Invalid key file');
  });
});

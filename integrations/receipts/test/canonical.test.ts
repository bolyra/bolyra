import { canonicalize } from '../src/canonical';

describe('canonicalize', () => {
  it('sorts keys alphabetically', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it('sorts nested objects recursively', () => {
    const obj = { z: { b: 1, a: 2 }, a: 1 };
    const result = canonicalize(obj);
    expect(result).toBe('{"a":1,"z":{"a":2,"b":1}}');
  });

  it('preserves array order (does not sort arrays)', () => {
    expect(canonicalize({ arr: [3, 1, 2] })).toBe('{"arr":[3,1,2]}');
  });

  it('handles null values', () => {
    expect(canonicalize({ b: null, a: 1 })).toBe('{"a":1,"b":null}');
  });

  it('handles undefined values (dropped by JSON.stringify)', () => {
    expect(canonicalize({ b: undefined, a: 1 })).toBe('{"a":1}');
  });

  it('produces deterministic output regardless of insertion order', () => {
    const a = canonicalize({ x: 1, y: 2, z: 3 });
    const b = canonicalize({ z: 3, x: 1, y: 2 });
    expect(a).toBe(b);
  });
});

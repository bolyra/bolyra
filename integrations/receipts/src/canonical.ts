const UNREPRESENTABLE_KEY = '__proto__';

/**
 * Deterministic JSON: object keys sorted, arrays in order.
 *
 * Throws a TypeError when an object that JSON.stringify visits as a member of
 * the value (at any depth, including objects inside arrays) has an OWN key
 * named "__proto__" (JSON.parse creates one from the text `{"__proto__": ...}`).
 * The guard covers plain JSON data. It does not see non-index properties set
 * on an array, or the original object when a `toJSON` method replaces it.
 * The sorted copy below is built by assignment, and assigning to that name
 * sets the copy's prototype instead of creating a key, so the member would be
 * absent from the output. A value with such a member therefore has no exact
 * canonical form here, and it is refused rather than serialized without it.
 *
 * Also throws a TypeError for a number that is not finite, or is negative
 * zero. JSON.stringify writes those as `null` and `0`, so each would share a
 * canonical form with a different value. JSON.parse yields them from ordinary
 * text such as `1e400` and `-0`.
 *
 * Callers that verify (verifyReceipt, verifyReceiptChain) treat the throw as
 * a failed verification; callers that sign or hash propagate it.
 */
export function canonicalize(obj: unknown): string {
  return JSON.stringify(obj, (_key, value) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      if (Object.prototype.hasOwnProperty.call(value, UNREPRESENTABLE_KEY)) {
        throw new TypeError('canonicalize: an object has an own "__proto__" key, which has no canonical form');
      }
      return Object.keys(value).sort().reduce((sorted, k) => {
        sorted[k] = (value as Record<string, unknown>)[k];
        return sorted;
      }, {} as Record<string, unknown>);
    }
    if (typeof value === 'number' && (!Number.isFinite(value) || Object.is(value, -0))) {
      throw new TypeError('canonicalize: a number is non-finite or negative zero, which has no canonical form');
    }
    return value;
  });
}

/**
 * Minimal JSON-Schema validator covering EXACTLY the vocabulary the two extracted
 * EVC schemas (§2.2 request, §3.4 verdict) use. Any other keyword anywhere in a
 * schema tree is an error: this validator must never silently ignore a rule.
 */
const VALIDATION_KEYWORDS = new Set(['type', 'required', 'properties', 'additionalProperties', 'enum', 'const', 'oneOf', 'minItems', 'items', 'minLength', 'exclusiveMinimum']);
const METADATA_KEYWORDS = new Set(['$schema', '$id', 'title']);

export function assertSupportedSchema(schema, path = '$') {
  if (typeof schema !== 'object' || schema === null || Array.isArray(schema)) throw new Error(`unsupported schema node at ${path}`);
  for (const key of Object.keys(schema)) {
    if (!VALIDATION_KEYWORDS.has(key) && !METADATA_KEYWORDS.has(key)) throw new Error(`unsupported schema keyword "${key}" at ${path}`);
  }
  if (schema.properties) for (const [k, v] of Object.entries(schema.properties)) assertSupportedSchema(v, `${path}.properties.${k}`);
  if (typeof schema.additionalProperties === 'object' && schema.additionalProperties !== null) assertSupportedSchema(schema.additionalProperties, `${path}.additionalProperties`);
  if (schema.items) assertSupportedSchema(schema.items, `${path}.items`);
  if (schema.oneOf) { if (!Array.isArray(schema.oneOf)) throw new Error(`oneOf must be an array at ${path}`); schema.oneOf.forEach((s, i) => assertSupportedSchema(s, `${path}.oneOf[${i}]`)); }
  return true;
}

function typeOk(type, v) {
  switch (type) {
    case 'object': return typeof v === 'object' && v !== null && !Array.isArray(v);
    case 'array': return Array.isArray(v);
    case 'string': return typeof v === 'string';
    case 'integer': return typeof v === 'number' && Number.isInteger(v);
    case 'number': return typeof v === 'number' && Number.isFinite(v);
    case 'boolean': return typeof v === 'boolean';
    case 'null': return v === null;
    default: throw new Error(`unsupported type "${type}"`);
  }
}

function check(schema, v, path, errors) {
  if (schema.type !== undefined) { const types = Array.isArray(schema.type) ? schema.type : [schema.type]; if (!types.some((t) => typeOk(t, v))) { errors.push(`${path}: expected ${types.join('|')}`); return; } }
  if (schema.const !== undefined && v !== schema.const) errors.push(`${path}: expected const ${JSON.stringify(schema.const)}`);
  if (schema.enum !== undefined && !schema.enum.includes(v)) errors.push(`${path}: not in enum`);
  if (schema.minLength !== undefined && typeof v === 'string' && v.length < schema.minLength) errors.push(`${path}: shorter than minLength ${schema.minLength}`);
  if (schema.exclusiveMinimum !== undefined && typeof v === 'number' && !(v > schema.exclusiveMinimum)) errors.push(`${path}: not > ${schema.exclusiveMinimum}`);
  if (schema.minItems !== undefined && Array.isArray(v) && v.length < schema.minItems) errors.push(`${path}: fewer than minItems ${schema.minItems}`);
  if (schema.items !== undefined && Array.isArray(v)) v.forEach((item, i) => check(schema.items, item, `${path}[${i}]`, errors));
  if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
    if (schema.required) for (const r of schema.required) if (!Object.prototype.hasOwnProperty.call(v, r)) errors.push(`${path}: missing required "${r}"`);
    const props = schema.properties ?? {};
    for (const [k, val] of Object.entries(v)) {
      if (Object.prototype.hasOwnProperty.call(props, k)) check(props[k], val, `${path}.${k}`, errors);
      else if (schema.additionalProperties === false) errors.push(`${path}: additional property "${k}"`);
      else if (typeof schema.additionalProperties === 'object' && schema.additionalProperties !== null) check(schema.additionalProperties, val, `${path}.${k}`, errors);
    }
  }
  if (schema.oneOf) {
    const matches = schema.oneOf.map((s) => { const e = []; check(s, v, path, e); return e.length === 0; }).filter(Boolean).length;
    if (matches !== 1) errors.push(`${path}: oneOf matched ${matches} branches`);
  }
}

export function validate(schema, instance) {
  assertSupportedSchema(schema);
  const errors = [];
  check(schema, instance, '$', errors);
  return { ok: errors.length === 0, errors };
}

#!/usr/bin/env node
/**
 * validate_schema.js — AJV-based JSON Schema validation for test vector files.
 *
 * Validates all *.json files in spec/test-vectors/ (except schema.json itself)
 * against the canonical schema.json. Intended as a pre-commit check or CI gate.
 *
 * Usage:
 *   node spec/test-vectors/scripts/validate_schema.js
 *
 * Exit code 0 = all files valid. Non-zero = at least one validation error.
 */

const path = require('path');
const fs = require('fs');

let Ajv;
try {
  Ajv = require('ajv');
} catch {
  // Try ajv/dist/2020 for JSON Schema draft 2020-12
  try {
    Ajv = require('ajv/dist/2020');
  } catch {
    console.error('Error: ajv not found. Install it: npm install --save-dev ajv');
    process.exit(1);
  }
}

let addFormats;
try {
  addFormats = require('ajv-formats');
} catch {
  // ajv-formats is optional — date-time validation won't work without it
  addFormats = null;
}

const VECTORS_DIR = path.resolve(__dirname, '..');
const SCHEMA_PATH = path.join(VECTORS_DIR, 'schema.json');

function main() {
  console.log('Bolyra Test Vector Schema Validation (L1)');
  console.log('');

  if (!fs.existsSync(SCHEMA_PATH)) {
    console.error(`Schema not found: ${SCHEMA_PATH}`);
    process.exit(1);
  }

  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, 'utf-8'));

  // Use Ajv 2020 if available (for draft 2020-12), otherwise standard Ajv
  let ajv;
  try {
    const Ajv2020 = require('ajv/dist/2020');
    ajv = new Ajv2020({ allErrors: true, strict: false });
  } catch {
    ajv = new Ajv({ allErrors: true, strict: false });
  }

  if (addFormats) {
    addFormats(ajv);
  }

  const validate = ajv.compile(schema);

  const vectorFiles = fs.readdirSync(VECTORS_DIR)
    .filter((f) => f.endsWith('.json') && f !== 'schema.json')
    .sort();

  if (vectorFiles.length === 0) {
    console.error('No vector files found.');
    process.exit(1);
  }

  let allValid = true;

  for (const file of vectorFiles) {
    const filePath = path.join(VECTORS_DIR, file);
    process.stdout.write(`  ${file}: `);

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      const valid = validate(data);

      if (valid) {
        console.log('VALID');
      } else {
        console.log('INVALID');
        for (const err of validate.errors) {
          console.error(`    ${err.instancePath || '/'}: ${err.message}`);
          if (err.params) {
            console.error(`      params: ${JSON.stringify(err.params)}`);
          }
        }
        allValid = false;
      }
    } catch (parseErr) {
      console.log('PARSE ERROR');
      console.error(`    ${parseErr.message}`);
      allValid = false;
    }
  }

  console.log('');
  console.log(allValid ? 'All vector files are schema-valid.' : 'Some vector files failed validation.');

  if (!allValid) {
    process.exit(1);
  }
}

main();

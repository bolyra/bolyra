#!/usr/bin/env npx tsx
import { runDemo } from './demo-runner.js';

runDemo()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Demo failed:', err);
    process.exit(1);
  });

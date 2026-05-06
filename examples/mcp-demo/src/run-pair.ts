/**
 * Convenience runner: `ts-node src/run-pair.ts <server> <client>`
 *
 * Each client spawns its own server (per MCP stdio convention), so this is
 * really just an alias to dispatch into the right client script.
 */

import './shared'; // ensure SDK loads cleanly before client tries

const [, , serverKind, clientKind] = process.argv;
if (
  (serverKind !== 'broken' && serverKind !== 'fixed') ||
  (clientKind !== 'attacker' && clientKind !== 'legit')
) {
  // eslint-disable-next-line no-console
  console.error('usage: run-pair.ts <broken|fixed> <attacker|legit>');
  process.exit(2);
}

(async () => {
  if (clientKind === 'attacker') {
    process.argv = [process.argv[0], 'attacker-client.ts', serverKind];
    await import('./attacker-client');
  } else {
    process.argv = [process.argv[0], 'legit-client.ts', serverKind];
    await import('./legit-client');
  }
})();

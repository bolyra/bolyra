/** Child-process entry: one portal, one process, one HOME (its own local nonce store). */
import { createPortal } from './portal';
import { verifierSpec } from './paths';

const audience = process.env.PORTAL_AUDIENCE;
if (!audience) { console.error('PORTAL_AUDIENCE is required'); process.exit(2); }
const server = createPortal({
  audience,
  routes: { '/public/stats': 'read:public-stats', '/internal/files': 'read:internal-files' },
  expectedAgent: { agent_name: 'stats-research-agent', program: 'demo', model: 'opus-4.1' },
  verifier: verifierSpec(),
});
server.listen(0, '127.0.0.1', () => {
  const addr = server.address();
  process.stdout.write(JSON.stringify({ port: typeof addr === 'object' && addr ? addr.port : 0 }) + '\n');
});
for (const sig of ['SIGTERM', 'SIGINT'] as const) process.on(sig, () => server.close(() => process.exit(0)));

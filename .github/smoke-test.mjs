// Fresh-install smoke test: verifies published packages work
import { createDevIdentities } from '@bolyra/sdk';
import { createAuthReceipt, signReceipt, verifyReceipt } from '@bolyra/receipts';

async function main() {
  console.log('1. Creating dev identities...');
  const { human, agent } = await createDevIdentities();
  console.log(`   Human commitment: ${human.commitment}`);
  console.log(`   Agent commitment: ${agent.commitment}`);

  console.log('2. Creating and signing a receipt...');
  const receipt = createAuthReceipt({
    rootDid: 'did:bolyra:dev:test',
    actingDid: 'did:bolyra:dev:test',
    credentialCommitment: agent.commitment.toString(),
    effectiveCommitment: agent.commitment.toString(),
    allowed: true,
    score: 100,
    permissionBitmask: '255',
    chainDepth: 0,
    humanProof: { proof: ['0'] },
    agentProof: { proof: ['0'] },
    humanPublicSignals: ['0'],
    agentPublicSignals: ['0'],
    bundleVersion: 1,
    nonce: '12345',
  }, { issuer: 'smoke-test', keyId: 'test-key-1' });

  const TEST_KEY = '0x' + '01'.repeat(32);
  const signed = signReceipt(receipt, {
    issuer: 'smoke-test',
    keyId: 'test-key-1',
    privateKey: TEST_KEY,
  });
  console.log(`   Receipt ID: ${signed.id}`);
  console.log(`   Signer: ${signed.signature.signer}`);

  console.log('3. Verifying receipt...');
  const valid = verifyReceipt(signed);
  if (!valid) throw new Error('Receipt verification failed!');
  console.log('   ✓ Receipt valid');

  console.log('');
  console.log('✓ All smoke tests passed');
}

main().catch(e => { console.error('FAIL:', e.message); process.exit(1); });

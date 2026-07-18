import { buildDecisionReceiptInput, type DecisionFacts } from '../src/index';

// The @bolyra/receipts verify CLI requires commerce.intentHash to be bare
// 64-char hex (verify-cli.ts: /^[0-9a-fA-F]{64}$/), matching the reference
// golden corpus. An mpp-emitted receipt must satisfy the same validator, or
// `bolyra-receipt-verify` rejects it as "commerce.intentHash must be a 64-char
// hex string".
const HEX64 = /^[0-9a-fA-F]{64}$/;

const facts: DecisionFacts = {
  request: {
    agent_name: 'shopper-bot',
    project_key: 'api.merchant.example',
    program: 'mpp',
    model: 'demo-model',
    granted_capabilities: ['mpp:financial:small'],
  } as DecisionFacts['request'],
  tier: 'small',
  amountUsd: '25',
};

describe('buildDecisionReceiptInput commerce.intentHash', () => {
  test('is bare 64-hex, accepted by the @bolyra/receipts verify CLI regex', () => {
    const input = buildDecisionReceiptInput(facts);
    expect(input.commerce.intentHash).toMatch(HEX64);
  });

  test('denied decisions also emit a CLI-valid intentHash', () => {
    const input = buildDecisionReceiptInput({
      ...facts,
      denial: { code: 'request_mismatch', message: 'over tier' },
    });
    expect(input.commerce.intentHash).toMatch(HEX64);
  });
});

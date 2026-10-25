import { runExample } from '../examples/approval-binding';

describe('examples/approval-binding', () => {
  it('matched arguments dispatch once, sign an observation and verify the link offline', async () => {
    const { matched } = await runExample();
    expect(matched.outcome).toBe('returned');
    expect(matched.dispatchCount).toBe(1);
    expect(matched.observation).toBe(true);
    expect(matched.value).toEqual({ refundId: 'rf_0001', orderId: 'ord_8a21', amount: 42.5 });
    expect(matched.link?.ok).toBe(true);
    expect(matched.link?.checks.map((c) => c.status)).toEqual(Array(9).fill('PASS'));
  });

  it('a changed amount is blocked with zero dispatches and no observation', async () => {
    const { changed } = await runExample();
    expect(changed.outcome).toBe('blocked');
    expect(changed.code).toBe('arguments_mismatch');
    expect(changed.dispatchCount).toBe(0);
    expect(changed.observation).toBe(false);
  });
});

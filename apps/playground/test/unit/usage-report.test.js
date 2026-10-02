import { test } from 'node:test';
import assert from 'node:assert/strict';
import { summarize, formatReport } from '../../tools/usage-report.mjs';

// CloudFront standard log fields (tab-separated): date time edge bytes c-ip method host stem status referer ua query ...
const line = (date, ip, stem, query = '-', ua = 'Mozilla/5.0%20(Macintosh)%20Chrome/152.0.0.0%20Safari/537.36', status = '200') =>
  [date, '12:00:00', 'IAD89', '10', ip, 'GET', 'd.cloudfront.net', stem, status, '-', ua, query].join('\t');

test('counts allowlisted events per day, raw vs filtered, rejects anything else, ignores probes', () => {
  const lines = [
    '#Version: 1.0',
    line('2026-10-02', '1.1.1.1', '/playground'),
    line('2026-10-02', '1.1.1.1', '/e', 'v=1&ev=interacted'),
    line('2026-10-02', '1.1.1.1', '/e', 'v=1&ev=tab_decode'),
    line('2026-10-02', '2.2.2.2', '/e', 'v=1&ev=tab_decode'),
    line('2026-10-02', '3.3.3.3', '/e', 'v=1&ev=tab_decode', 'python-requests/2.31'),       // bot UA
    line('2026-10-02', '4.4.4.4', '/.env'),                                                   // scanner probe
    line('2026-10-02', '4.4.4.4', '/e', 'v=1&ev=run_decode'),                                 // from a scanner address
    line('2026-10-02', '5.5.5.5', '/e', 'v=1&ev=secret'),                                     // not allowlisted
    line('2026-10-02', '5.5.5.5', '/e', 'v=2&ev=tab_decode'),                                 // wrong version
    line('2026-10-02', '5.5.5.5', '/e', 'v=1&ev=tab_decode&x=1'),                             // extra param
    line('2026-10-02', '6.6.6.6', '/e'),                                                      // verify.sh HEAD probe, no query
    line('2026-10-01', '1.1.1.1', '/e', 'v=1&ev=decode_ok'),
  ];
  const s = summarize(lines, { since: '2026-10-02' });
  assert.deepEqual(Object.keys(s.days), ['2026-10-02']);
  const d = s.days['2026-10-02'];
  assert.equal(d.raw.tab_decode, 3); assert.equal(d.filtered.tab_decode, 2);
  assert.equal(d.raw.run_decode, 1); assert.equal(d.filtered.run_decode ?? 0, 0);
  assert.equal(d.rejected, 3);
  assert.equal(d.probes, 1);
  assert.equal(d.loads.raw, 1); assert.equal(d.loads.filtered, 1);
  const text = formatReport(s);
  assert.match(text, /first occurrences per page load/);
  assert.match(text, /not people/);
  assert.match(text, /not evidence of demand/);
  assert.ok(!text.includes('1.1.1.1'), 'report never prints addresses');
});

import { monthsBetween } from '../../tools/usage-report.mjs';
test('monthsBetween enumerates every calendar month in the range (Codex review R1)', () => {
  assert.deepEqual(monthsBetween('2026-08-01', '2026-10-02'), ['2026-08', '2026-09', '2026-10']);
  assert.deepEqual(monthsBetween('2025-11-15', '2026-02-01'), ['2025-11', '2025-12', '2026-01', '2026-02']);
  assert.deepEqual(monthsBetween('2026-10-02', '2026-10-02'), ['2026-10']);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const { lookupPatchMonth, needsPatchMonth, lookupUrl } = require('../../src/sources/msrcLookup');

test('reads the fix month from the update guide response', async () => {
  const body = JSON.stringify({ value: [{ cveNumber: 'CVE-2026-68820', releaseNumber: '2026-Aug', releaseDate: '2026-08-11T07:00:00-07:00' }] });
  let asked;
  const month = await lookupPatchMonth('CVE-2026-68820', async (u) => { asked = u; return body; });
  assert.equal(month, '2026-08');
  assert.equal(asked, lookupUrl('CVE-2026-68820'));
  assert.match(asked, /cveNumber%20eq%20'CVE-2026-68820'/);
});

test('unknown CVE gives null', async () => {
  assert.equal(await lookupPatchMonth('CVE-1', async () => '{"value":[]}'), null);
});

test('only exploited Windows items without a fix month need a lookup', () => {
  assert.equal(needsPatchMonth({ exploited: true, products: ['ws2022'], cves: ['CVE-1'], patchMonth: null }), true);
  assert.equal(needsPatchMonth({ exploited: true, products: ['ws2022'], cves: ['CVE-1'], patchMonth: '2026-08' }), false);
  assert.equal(needsPatchMonth({ exploited: true, products: ['vmware'], cves: ['CVE-1'], patchMonth: null }), false);
  assert.equal(needsPatchMonth({ exploited: true, products: ['ws2022'], cves: ['CVE-1'], patchMonth: null, patchLookupAt: '2026-10-12' }), false);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const { nextPatchTuesday, safeToDeploy } = require('../../src/core/patchCycle');

const pad = (n) => String(n).padStart(2, '0');
const ymd = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;

test('next patch tuesday from before, after and on the day', () => {
  assert.equal(ymd(nextPatchTuesday(new Date(2026, 9, 10))), '2026-10-13');
  assert.equal(ymd(nextPatchTuesday(new Date(2026, 9, 14))), '2026-11-10');
  assert.equal(ymd(nextPatchTuesday(new Date(2026, 9, 13, 18, 0))), '2026-10-13');
});

test('month starting on a tuesday', () => {
  // Sept 1 2026 is a Tuesday -> second Tuesday is Sept 8.
  assert.equal(ymd(nextPatchTuesday(new Date(2026, 8, 1))), '2026-09-08');
});

test('december rolls over to january', () => {
  assert.equal(ymd(nextPatchTuesday(new Date(2026, 11, 20))), '2027-01-12');
});

const ki = (version, status, daysAgo, now) => ({
  kind: 'known-issue', status, products: [version],
  published: new Date(now.getTime() - daysAgo * 86400000).toISOString().slice(0, 10),
});

test('safe to deploy: recent open issue is caution, old issue is clean', () => {
  const now = new Date('2026-10-10T12:00:00Z');
  const res = safeToDeploy({ items: [ki('ws2022', 'open', 10, now), ki('ws2022', 'resolved', 5, now), ki('ws2019', 'open', 60, now)] }, now);
  assert.deepEqual(res, [
    { version: 'ws2016', status: 'clean', openIssues: 0, resolved: 0 },
    { version: 'ws2019', status: 'clean', openIssues: 0, resolved: 0 },
    { version: 'ws2022', status: 'caution', openIssues: 1, resolved: 1 },
    { version: 'ws2025', status: 'clean', openIssues: 0, resolved: 0 },
  ]);
});

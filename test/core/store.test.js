const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { makeItem } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const { createStore } = require('../../src/core/store');

const cfg = loadConfig();
const tmpFile = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'radar-')), 'state.json');
const recent = new Date(Date.now() - 86400000).toISOString();
const kev = (cve = 'CVE-2026-1') => makeItem({ id: 'kev:' + cve, source: 'cisa-kev', title: 'Win RCE', kind: 'vuln', exploited: true, cves: [cve], products: ['ws2019'], published: recent });
const msrc = (cve = 'CVE-2026-1') => makeItem({ id: 'msrc:' + cve, source: 'msrc', title: 'Win RCE', kind: 'vuln', cvss: 9.8, cves: [cve], products: ['ws2022'], published: recent });

test('same CVE from two sources merges into one item', () => {
  const s = createStore(tmpFile(), cfg);
  const first = s.merge([kev()]);
  const second = s.merge([msrc()]);
  assert.equal(first.length, 1);
  assert.equal(second.length, 0);
  const items = s.snapshot().items;
  assert.equal(items.length, 1);
  assert.deepEqual(items[0].sources.sort(), ['cisa-kev', 'msrc']);
  assert.deepEqual(items[0].products, ['ws2019', 'ws2022']);
  assert.equal(items[0].exploited, true);
  assert.equal(items[0].cvss, 9.8);
  assert.equal(items[0].key, 'CVE-2026-1');
  assert.equal(items[0].tier, 'act');
});

test('duplicates within one merge call count once', () => {
  const s = createStore(tmpFile(), cfg);
  assert.equal(s.merge([kev(), msrc()]).length, 1);
});

test('read state survives save and reload', () => {
  const f = tmpFile();
  const s = createStore(f, cfg);
  s.merge([kev()]);
  s.markRead('CVE-2026-1');
  s.save();
  const s2 = createStore(f, cfg);
  assert.equal(s2.snapshot().items[0].read, true);
});

test('source health counts consecutive failures and resets on success', () => {
  const s = createStore(tmpFile(), cfg);
  const at = new Date().toISOString();
  s.recordSource('a', 'A', { ok: false, error: 'x' }, at);
  s.recordSource('a', 'A', { ok: false, error: 'x' }, at);
  s.recordSource('a', 'A', { ok: true, count: 3 }, at);
  assert.equal(s.snapshot().sources.find((x) => x.id === 'a').consecutiveFailures, 0);
  for (let i = 0; i < 3; i++) s.recordSource('b', 'B', { ok: false, error: 'boom' }, at);
  const b = s.snapshot().sources.find((x) => x.id === 'b');
  assert.equal(b.consecutiveFailures, 3);
  assert.equal(b.lastError, 'boom');
});

test('first sync marks everything read and exploited keys notified', () => {
  const s = createStore(tmpFile(), cfg);
  assert.equal(s.isFirstSync(), true);
  s.merge([kev(), msrc('CVE-2026-9')]);
  s.completeSync();
  assert.equal(s.isFirstSync(), false);
  assert.ok(s.snapshot().items.every((i) => i.read));
  assert.ok(s.notifiedKeys().has('CVE-2026-1'));
  assert.ok(!s.notifiedKeys().has('CVE-2026-9'));
});

test('corrupt state file is set aside and store starts empty', () => {
  const f = tmpFile();
  fs.writeFileSync(f, '{not json');
  const s = createStore(f, cfg);
  assert.equal(s.snapshot().items.length, 0);
  assert.ok(fs.readdirSync(path.dirname(f)).some((n) => n.includes('.corrupt-')));
});

test('discarded tier is not in snapshot', () => {
  const s = createStore(tmpFile(), cfg);
  s.merge([makeItem({ id: 'z', source: 'nvd', title: 'other', kind: 'vuln', products: [] })]);
  assert.equal(s.snapshot().items.length, 0);
});

test('old items pruned on save except unread act', () => {
  const f = tmpFile();
  const s = createStore(f, cfg);
  const old = new Date(Date.now() - 200 * 86400000).toISOString();
  s.merge([
    makeItem({ id: 'old-watch', source: 'rh', title: 'old', kind: 'known-issue', products: ['ws2019'], published: old }),
    makeItem({ id: 'old-act', source: 'kev', title: 'old act', kind: 'vuln', exploited: true, exploitedAt: recent, products: ['ws2019'], published: old }),
  ]);
  s.save();
  const keys = createStore(f, cfg).snapshot().items.map((i) => i.key);
  assert.deepEqual(keys, ['old-act']);
});

test('pruned items do not come back as new', () => {
  const f = tmpFile();
  const s = createStore(f, cfg);
  const old = new Date(Date.now() - 200 * 86400000).toISOString();
  const it = makeItem({ id: 'old-watch', source: 'rh', title: 'old', kind: 'known-issue', products: ['ws2019'], published: old });
  s.merge([it]);
  s.save();
  assert.equal(s.merge([it]).length, 0);
});

test('snapshot is newest first', () => {
  const s = createStore(tmpFile(), cfg);
  s.merge([
    makeItem({ id: 'a', source: 'rh', title: 'a', kind: 'known-issue', products: ['ws2019'], published: '2026-10-01T00:00:00Z' }),
    makeItem({ id: 'b', source: 'rh', title: 'b', kind: 'known-issue', products: ['ws2019'], published: '2026-10-05T00:00:00Z' }),
  ]);
  assert.deepEqual(s.snapshot().items.map((i) => i.key), ['b', 'a']);
});

test('known issue listed on two version pages merges into one item with both versions', () => {
  const s = createStore(tmpFile(), cfg);
  const mk = (v) => makeItem({ id: 'rh:usb', source: 'release-health', title: 'USB', kind: 'known-issue', status: 'open', products: [v], published: recent });
  assert.equal(s.merge([mk('ws2019'), mk('ws2025')]).length, 1);
  assert.deepEqual(s.snapshot().items[0].products, ['ws2019', 'ws2025']);
});

test('a re-fetched item from the same source refreshes its title and summary', () => {
  const s = createStore(tmpFile(), cfg);
  const mk = (title) => makeItem({ id: 'chrome:1', source: 'chrome', title, summary: title, kind: 'vuln', severity: 'critical', products: ['chrome'], published: recent });
  s.merge([mk('Chrome 1 for Desktop')]);
  s.merge([mk('Chrome 1 for Windows')]);
  assert.equal(s.snapshot().items[0].title, 'Chrome 1 for Windows');
  // another source merging the same CVE does not overwrite the title
  s.merge([makeItem({ id: 'nvd:x', source: 'nvd', title: 'Other wording', kind: 'vuln', severity: 'critical', products: ['chrome'], published: recent })]);
  assert.equal(s.snapshot().items.find((i) => i.key === 'chrome:1').title, 'Chrome 1 for Windows');
});

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { makeItem } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const { createStore } = require('../../src/core/store');
const { runRefresh } = require('../../src/core/refresh');

const cfg = loadConfig();
const tmp = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'radar-')), 's.json');
const now = () => new Date('2026-10-10T12:00:00Z');
const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString();
const src = (id, get) => ({ id, label: id, urls: [`https://x.test/${id}`], parse: () => get() });
const run = (store, sources) => runRefresh({ sources, store, config: cfg, httpGet: async () => 'b', now, sleep: async () => {} });

const msrcItem = (cve, pub = daysAgo(3)) => makeItem({ id: `msrc:${cve}`, source: 'msrc', title: cve, kind: 'vuln', severity: 'important', cvss: 7.8, cves: [cve], products: ['ws2022'], published: pub });
const kevItem = (cve, pub = daysAgo(1)) => makeItem({ id: `kev:${cve}`, source: 'cisa-kev', title: cve, kind: 'vuln', exploited: true, cves: [cve], products: ['ws2019', 'ws2022', 'ws2025'], published: pub });

test('item that becomes exploited later (KEV after MSRC) notifies once and turns unread', async () => {
  const store = createStore(tmp(), cfg);
  let msrc = []; let kev = [kevItem('CVE-2026-0001')];
  const sources = [src('msrc', () => msrc), src('cisa-kev', () => kev)];
  await run(store, sources); // first sync of both sources
  msrc = [msrcItem('CVE-2026-0002')];
  await run(store, sources);
  kev = [kevItem('CVE-2026-0001'), kevItem('CVE-2026-0002')];
  const r = await run(store, sources);
  assert.deepEqual(r.toNotify.map((i) => i.key), ['CVE-2026-0002']);
  const it = store.snapshot().items.find((i) => i.key === 'CVE-2026-0002');
  assert.equal(it.tier, 'act');
  assert.equal(it.read, false);
  assert.equal((await run(store, sources)).toNotify.length, 0);
});

test('old pruned CVE later added to KEV is re-admitted and notifies', async () => {
  const f = tmp();
  let store = createStore(f, cfg);
  let msrc = [msrcItem('CVE-2025-0009', daysAgo(200))];
  let kev = [kevItem('CVE-2026-0001')];
  const sources = [src('msrc', () => msrc), src('cisa-kev', () => kev)];
  await run(store, sources); // first sync; old msrc item stored then pruned on save
  store = createStore(f, cfg);
  msrc = [];
  kev = [kevItem('CVE-2026-0001'), kevItem('CVE-2025-0009', daysAgo(0))];
  const r = await run(store, sources);
  assert.deepEqual(r.toNotify.map((i) => i.key), ['CVE-2025-0009']);
});

test('act items are not pruned and so do not come back unread', async () => {
  const f = tmp();
  const store = createStore(f, cfg);
  const old = makeItem({ id: 'kev:OLD', source: 'cisa-kev', title: 'old cve, newly exploited', kind: 'vuln', exploited: true, exploitedAt: daysAgo(5), products: ['vmware'], published: daysAgo(900) });
  const sources = [src('cisa-kev', () => [old])];
  await run(store, sources);
  const again = createStore(f, cfg);
  await run(again, sources);
  const it = again.snapshot().items.find((i) => i.key === 'kev:OLD');
  assert.equal(it.read, true);
});

test('offline first launch: a source first succeeding later does not flood notifications', async () => {
  const store = createStore(tmp(), cfg);
  let kevUp = false;
  const sources = [src('msrc', () => [msrcItem('CVE-2026-0003')]), { id: 'cisa-kev', label: 'KEV', urls: ['k'], parse: () => { if (!kevUp) throw new Error('offline'); return [kevItem('CVE-2020-1111', daysAgo(2000)), kevItem('CVE-2026-0003')]; } }];
  await run(store, sources);
  kevUp = true;
  const r = await run(store, sources);
  assert.equal(r.toNotify.length, 0);
  assert.ok(store.snapshot().items.filter((i) => i.tier === 'act').every((i) => i.read));
  // A genuinely new exploited CVE after KEV's first sync does notify.
  const prev = sources[1].parse;
  sources[1].parse = () => [...prev(), kevItem('CVE-2026-0004')];
  assert.deepEqual((await run(store, sources)).toNotify.map((i) => i.key), ['CVE-2026-0004']);
});

test('all sources offline on first launch, then online: no flood', async () => {
  const store = createStore(tmp(), cfg);
  let up = false;
  const sources = [{ id: 'cisa-kev', label: 'KEV', urls: ['k'], parse: () => { if (!up) throw new Error('offline'); return [kevItem('CVE-2020-2222', daysAgo(3000))]; } }];
  await run(store, sources);
  up = true;
  assert.equal((await run(store, sources)).toNotify.length, 0);
});

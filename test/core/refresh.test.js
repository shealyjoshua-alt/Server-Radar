const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { makeItem, ParseError } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const { createStore } = require('../../src/core/store');
const { runRefresh } = require('../../src/core/refresh');
const { HttpError } = require('../../src/sources/http');

const cfg = loadConfig();
const tmpStore = () => createStore(path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'radar-')), 's.json'), cfg);
const now = () => new Date('2026-10-10T12:00:00Z');
const noSleep = async () => {};

const exploited = (cve, source = 'fake-a') => makeItem({ id: `${source}:${cve}`, source, title: cve, kind: 'vuln', exploited: true, cves: [cve], products: ['ws2022'], published: '2026-10-09T00:00:00Z' });

function fakeSource(id, parse, extra = {}) {
  return { id, label: id.toUpperCase(), urls: [`https://example.test/${id}`], parse, ...extra };
}

test('one failing source does not stop the others', async () => {
  const store = tmpStore();
  const A = fakeSource('a', () => [exploited('CVE-2026-1')]);
  const B = fakeSource('b', () => []);
  const C = fakeSource('c', () => { throw new ParseError('format changed'); });
  const httpGet = async (url) => { if (url.endsWith('/b')) throw new Error('ENOTFOUND'); return 'body'; };
  const res = await runRefresh({ sources: [A, B, C], store, config: cfg, httpGet, now, sleep: noSleep });
  assert.equal(res.newItems.length, 1);
  const health = Object.fromEntries(store.snapshot().sources.map((s) => [s.id, s]));
  assert.equal(health.a.consecutiveFailures, 0);
  assert.equal(health.a.lastOk, '2026-10-10T12:00:00.000Z');
  assert.equal(health.b.consecutiveFailures, 1);
  assert.match(health.b.lastError, /ENOTFOUND/);
  assert.equal(health.c.consecutiveFailures, 1);
  assert.match(health.c.lastError, /format changed/);
});

test('first run never notifies; new exploited item later notifies once across sources', async () => {
  const store = tmpStore();
  let batch = [exploited('CVE-2026-1')];
  const A = fakeSource('a', () => batch);
  const httpGet = async () => 'body';
  const run = () => runRefresh({ sources: [A], store, config: cfg, httpGet, now, sleep: noSleep });

  assert.equal((await run()).toNotify.length, 0);
  assert.equal(store.isFirstSync(), false);

  batch = [exploited('CVE-2026-1'), exploited('CVE-2026-2')];
  const second = await run();
  assert.deepEqual(second.toNotify.map((i) => i.key), ['CVE-2026-2']);

  batch = [exploited('CVE-2026-2', 'fake-b')];
  assert.equal((await run()).toNotify.length, 0);
});

test('cvss-only critical never notifies', async () => {
  const store = tmpStore();
  store.completeSync();
  const A = fakeSource('a', () => [makeItem({ id: 'x', source: 'a', title: 't', kind: 'vuln', cvss: 9.8, cves: ['CVE-2026-5'], products: ['ws2019'] })]);
  const res = await runRefresh({ sources: [A], store, config: cfg, httpGet: async () => 'b', now, sleep: noSleep });
  assert.equal(res.newItems.length, 1);
  assert.equal(res.toNotify.length, 0);
});

test('minIntervalMs is respected between a source\'s urls', async () => {
  const store = tmpStore();
  const waits = [];
  const A = fakeSource('a', (bodies) => { assert.equal(bodies.length, 3); return []; }, { urls: ['u1', 'u2', 'u3'], minIntervalMs: 6500 });
  await runRefresh({ sources: [A], store, config: cfg, httpGet: async (u) => u, now, sleep: async (ms) => { waits.push(ms); } });
  assert.deepEqual(waits, [6500, 6500]);
});

test('allow404 passes null for a missing document', async () => {
  const store = tmpStore();
  let got;
  const A = fakeSource('a', (bodies) => { got = bodies; return []; }, { urls: ['cur', 'prev'], allow404: true });
  const httpGet = async (u) => { if (u === 'cur') throw new HttpError(404, u); return 'prev-body'; };
  await runRefresh({ sources: [A], store, config: cfg, httpGet, now, sleep: noSleep });
  assert.deepEqual(got, [null, 'prev-body']);
  assert.equal(store.snapshot().sources[0].consecutiveFailures, 0);
});

test('404 without allow404 is a failure', async () => {
  const store = tmpStore();
  const A = fakeSource('a', () => []);
  await runRefresh({ sources: [A], store, config: cfg, httpGet: async (u) => { throw new HttpError(404, u); }, now, sleep: noSleep });
  assert.equal(store.snapshot().sources[0].consecutiveFailures, 1);
});

test('request objects and source headers are passed to httpGet', async () => {
  const store = tmpStore();
  const calls = [];
  const A = { id: 'a', label: 'A', headers: { Accept: 'application/json' }, requests: [{ url: 'p', method: 'POST', body: '{}', headers: { 'Content-Type': 'application/json' } }], parse: () => [] };
  await runRefresh({ sources: [A], store, config: cfg, httpGet: async (u, o) => { calls.push([u, o]); return ''; }, now, sleep: noSleep });
  assert.equal(calls[0][0], 'p');
  assert.equal(calls[0][1].method, 'POST');
  assert.equal(calls[0][1].body, '{}');
  assert.deepEqual(calls[0][1].headers, { Accept: 'application/json', 'Content-Type': 'application/json' });
});

test('state is saved to disk', async () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'radar-')), 's.json');
  const store = createStore(file, cfg);
  await runRefresh({ sources: [fakeSource('a', () => [exploited('CVE-2026-7')])], store, config: cfg, httpGet: async () => 'b', now, sleep: noSleep });
  assert.ok(fs.existsSync(file));
});

test('source index lists all nine sources with unique ids', () => {
  const sources = require('../../src/sources');
  assert.equal(sources.length, 13);
  assert.equal(new Set(sources.map((s) => s.id)).size, 13);
  for (const s of sources) {
    assert.equal(typeof s.parse, 'function');
    assert.ok((s.requests && s.requests.length) || (s.urls && s.urls.length), s.id);
  }
});

test('a source summary is kept with the snapshot', async () => {
  const store = tmpStore();
  const A = { id: 'msrc', label: 'M', urls: ['u'], parse: () => [], summarize: (bodies) => ({ seen: bodies.length }) };
  await runRefresh({ sources: [A], store, config: cfg, httpGet: async () => 'b', now, sleep: noSleep });
  assert.deepEqual(store.snapshot().meta.msrc, { seen: 1 });
});

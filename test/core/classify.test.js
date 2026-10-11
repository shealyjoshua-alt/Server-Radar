const test = require('node:test');
const assert = require('node:assert/strict');
const { makeItem } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const { tierFor, notifyKey, shouldNotify } = require('../../src/core/classify');

const cfg = loadConfig();
const mk = (f) => makeItem({ id: 'x', source: 'test', title: 't', kind: 'vuln', ...f });
const ctx = (over = {}) => ({ firstSync: false, notifiedKeys: new Set(), ...over });

test('rule 1: exploited in scope is act', () => {
  assert.equal(tierFor(mk({ exploited: true, products: ['ws2019'] }), cfg), 'act');
});

test('cvss 9.8 unexploited is watch, not act, and does not notify', () => {
  const it = mk({ id: 'x', source: 'msrc', cvss: 9.8, products: ['ws2022'] });
  assert.equal(tierFor(it, cfg), 'watch');
  assert.equal(shouldNotify(it, ctx(), cfg), false);
});

test('act now means actively exploited within the last 90 days', () => {
  const recent = new Date(Date.now() - 10 * 86400000).toISOString();
  const old = new Date(Date.now() - 120 * 86400000).toISOString();
  assert.equal(tierFor(mk({ exploited: true, products: ['ws2022'], published: recent }), cfg), 'act');
  assert.equal(tierFor(mk({ exploited: true, products: ['ws2022'], published: old }), cfg), null);
  // exploitedAt (when it became exploited) wins over the original publish date
  assert.equal(tierFor(mk({ exploited: true, products: ['ws2022'], published: old, exploitedAt: recent }), cfg), 'act');
});

test('unexploited azure-cloud-only CVEs go to the azure section', () => {
  assert.equal(tierFor(mk({ cvss: 10, severity: 'critical', products: ['azure'] }), cfg), 'azure');
  assert.equal(tierFor(mk({ exploited: true, products: ['azure'] }), cfg), 'act');
});

test('routine important windows CVEs are dropped, agent/vmware important stay', () => {
  assert.equal(tierFor(mk({ severity: 'important', cvss: 7.8, products: ['ws2019', 'ws2022'] }), cfg), null);
  assert.equal(tierFor(mk({ severity: 'important', products: ['splunkuf'] }), cfg), 'watch');
  assert.equal(tierFor(mk({ severity: 'important', products: ['vmware'] }), cfg), 'watch');
  assert.equal(tierFor(mk({ severity: 'critical', products: ['ws2025'] }), cfg), 'watch');
});

test('rule 3: gov incident is watch, commercial incident is azure, neither notifies', () => {
  const gov = mk({ kind: 'incident', gov: true, products: ['azure'] });
  const com = mk({ kind: 'incident', gov: false, products: ['azure'] });
  assert.equal(tierFor(gov, cfg), 'watch');
  assert.equal(tierFor(com, cfg), 'azure');
  assert.equal(shouldNotify(gov, ctx(), cfg), false);
  assert.equal(shouldNotify(com, ctx(), cfg), false);
});

test('rule 4: maintenance and retirement are watch', () => {
  assert.equal(tierFor(mk({ kind: 'maintenance', products: ['azure'] }), cfg), 'watch');
  assert.equal(tierFor(mk({ kind: 'retirement', products: ['azure'] }), cfg), 'watch');
});

test('rule 5: known issue in scope is watch', () => {
  assert.equal(tierFor(mk({ kind: 'known-issue', products: ['ws2025'] }), cfg), 'watch');
});

test('rule 6: important vmware vuln is watch, moderate is discarded', () => {
  assert.equal(tierFor(mk({ severity: 'important', products: ['vmware'] }), cfg), 'watch');
  assert.equal(tierFor(mk({ severity: 'critical', cvss: 8.1, products: ['vmware'] }), cfg), 'watch');
  assert.equal(tierFor(mk({ severity: 'moderate', products: ['vmware'] }), cfg), null);
});

test('rule 7: agent together with windows is watch', () => {
  assert.equal(tierFor(mk({ kind: 'update', products: ['crowdstrike', 'ws2022'] }), cfg), 'watch');
  assert.equal(tierFor(mk({ kind: 'update', products: ['splunkuf'] }), cfg), null);
});

test('rule 8: update matching interest keyword is interest', () => {
  assert.equal(tierFor(mk({ kind: 'update', source: 'azure-updates', title: 'Generally available: Azure Arc for servers', products: ['azure'] }), cfg), 'interest');
});

test('rule 9: release in scope is interest', () => {
  assert.equal(tierFor(mk({ kind: 'release', title: 'vCenter 9.1', products: ['vmware'] }), cfg), 'interest');
});

test('rule 10: other azure updates go to azure section', () => {
  assert.equal(tierFor(mk({ kind: 'update', source: 'azure-updates', title: 'Public preview: Cosmos DB thing', products: ['azure'] }), cfg), 'azure');
});

test('exploited but out of scope is discarded', () => {
  assert.equal(tierFor(mk({ exploited: true, products: [] }), cfg), null);
});

test('notifyKey prefers first CVE', () => {
  assert.equal(notifyKey(mk({ id: 'kev:CVE-1', cves: ['CVE-2026-1'] })), 'CVE-2026-1');
  assert.equal(notifyKey(mk({ id: 'vmsa:1' })), 'vmsa:1');
});

test('exploited notifies once by CVE across sources', () => {
  const a = mk({ id: 'kev:CVE-2026-1', source: 'cisa-kev', exploited: true, cves: ['CVE-2026-1'], products: ['ws2019'] });
  const b = { ...a, id: 'msrc:CVE-2026-1', source: 'msrc' };
  const keys = new Set();
  assert.equal(shouldNotify(a, ctx({ notifiedKeys: keys }), cfg), true);
  keys.add(notifyKey(a));
  assert.equal(shouldNotify(b, ctx({ notifiedKeys: keys }), cfg), false);
});

test('first sync never notifies', () => {
  const a = mk({ exploited: true, cves: ['CVE-2026-2'], products: ['ws2019'] });
  assert.equal(shouldNotify(a, ctx({ firstSync: true }), cfg), false);
});

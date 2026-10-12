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

test('important domain controller CVE is kept in keep an eye on', () => {
  assert.equal(tierFor(mk({ severity: 'important', cvss: 8.1, products: ['dc', 'ws2022'] }), cfg), 'watch');
});

test('only critical or high vulnerabilities are shown', () => {
  // scored: CVSS 7.0+ only
  assert.equal(tierFor(mk({ severity: 'important', cvss: 6.5, products: ['dc', 'ws2022'] }), cfg), null);
  assert.equal(tierFor(mk({ severity: 'important', cvss: 7.0, products: ['dc', 'ws2022'] }), cfg), 'watch');
  assert.equal(tierFor(mk({ severity: 'critical', cvss: 5.9, products: ['ws2022'] }), cfg), null);
  // unscored: needs a vendor critical/high rating
  assert.equal(tierFor(mk({ severity: null, products: ['splunkuf'] }), cfg), null);
  assert.equal(tierFor(mk({ severity: 'important', products: ['vmware'] }), cfg), 'watch');
  // a scored exploited item below 7 is hidden too
  assert.equal(tierFor(mk({ exploited: true, cvss: 5.5, products: ['ws2022'] }), cfg), null);
  // unscored CISA KEV entries (actively exploited) still show
  assert.equal(tierFor(mk({ exploited: true, severity: 'critical', products: ['ws2022'] }), cfg), 'act');
});

test('non-vulnerability items are not affected by the severity rule', () => {
  assert.equal(tierFor(mk({ kind: 'known-issue', products: ['ws2022'] }), cfg), 'watch');
});

test('windows vulns fixed by patches already applied are hidden', () => {
  const c = { ...cfg, patchedThrough: '2026-09' };
  const recent = new Date(Date.now() - 5 * 86400000).toISOString();
  assert.equal(tierFor(mk({ exploited: true, products: ['ws2022'], patchMonth: '2026-09', published: recent }), c), null);
  assert.equal(tierFor(mk({ exploited: true, products: ['ws2022'], patchMonth: '2026-07', published: recent }), c), null);
  assert.equal(tierFor(mk({ exploited: true, products: ['ws2022'], patchMonth: '2026-10', published: recent }), c), 'act');
  assert.equal(tierFor(mk({ cvss: 9.8, products: ['ws2022', 'dc'], patchMonth: '2026-09' }), c), null);
  // not Windows, or not a vulnerability: unaffected
  assert.equal(tierFor(mk({ exploited: true, products: ['vmware'], patchMonth: '2026-09', published: recent }), c), 'act');
  assert.equal(tierFor(mk({ kind: 'known-issue', products: ['ws2022'], patchMonth: '2026-09' }), c), 'watch');
  // no setting: nothing hidden
  assert.equal(tierFor(mk({ exploited: true, products: ['ws2022'], patchMonth: '2026-09', published: recent }), { ...cfg, patchedThrough: undefined }), 'act');
});

test('azure items for non-US regions only are dropped', () => {
  const az = (title, extra = {}) => mk({ kind: 'update', source: 'azure-updates', title, products: ['azure'], ...extra });
  assert.equal(tierFor(az('[Launched] Generally Available: Azure Arc-enabled SQL Server in Germany West Central'), cfg), null);
  assert.equal(tierFor(az('Generally Available: Azure Database for PostgreSQL flexible server in Italy North'), cfg), null);
  assert.equal(tierFor(az('Announcing: Multiparty private offers expands to Hong Kong'), cfg), null);
  assert.equal(tierFor(mk({ kind: 'incident', source: 'azure-status', title: 'Active - Storage - West Europe', products: ['azure'] }), cfg), null);
});

test('azure items naming a US region, or no region, are kept', () => {
  const az = (title, extra = {}) => mk({ kind: 'update', source: 'azure-updates', title, products: ['azure'], ...extra });
  assert.equal(tierFor(az('Generally Available: Azure Database for PostgreSQL flexible server in East US 3'), cfg), 'azure');
  assert.equal(tierFor(az('Generally Available: Azure Monitor Auxiliary Logs Plan in Azure Government and China regions', { gov: true }), cfg), 'interest');
  assert.equal(tierFor(az('Retirement: Azure Deployment Environments will be retired on February 22, 2027', { kind: 'retirement' }), cfg), 'watch');
  assert.equal(tierFor(az('Public Preview: Azure Arc for servers in all regions'), cfg), 'interest');
  // "us" as a word in a sentence is not a US region and does not save a foreign-only item
  assert.equal(tierFor(az('Tell us what you think: new feature in Japan East'), cfg), null);
});

test('region rule only applies to Azure feeds', () => {
  assert.equal(tierFor(mk({ kind: 'known-issue', source: 'release-health', title: 'Issue affecting devices in Germany', products: ['ws2022'] }), cfg), 'watch');
});

test('resolved incidents go to the Azure section, not keep an eye on', () => {
  assert.equal(tierFor(mk({ kind: 'incident', status: 'resolved', gov: true, source: 'azure-history', products: ['azure'] }), cfg), 'azure');
});

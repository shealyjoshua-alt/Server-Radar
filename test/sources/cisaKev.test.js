const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ParseError } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const kev = require('../../src/sources/cisaKev');

const cfg = loadConfig();
const body = fs.readFileSync(path.join(__dirname, '../fixtures/cisa-kev/kev.json'), 'utf8');
const items = kev.parse([body], cfg);
const byCve = (c) => items.find((i) => i.cves[0] === c);

test('module shape', () => {
  assert.equal(kev.id, 'cisa-kev');
  assert.equal(kev.urls[0], 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
});

test('windows entry maps to all server versions and is exploited', () => {
  const it = byCve('CVE-2021-34527');
  assert.deepEqual(it.products, ['ws2019', 'ws2022', 'ws2025']);
  assert.equal(it.exploited, true);
  assert.equal(it.kind, 'vuln');
  assert.equal(it.id, 'kev:CVE-2021-34527');
  assert.equal(it.url, 'https://nvd.nist.gov/vuln/detail/CVE-2021-34527');
  assert.match(it.summary, /Required action:/);
});

test('vmware vcenter entry maps to vmware', () => {
  assert.deepEqual(byCve('CVE-2021-22005').products, ['vmware']);
});

test('vmware "Multiple Products" entry maps to vmware', () => {
  assert.deepEqual(byCve('CVE-2020-3950').products, ['vmware']);
});

test('non-windows microsoft product is out of scope', () => {
  assert.deepEqual(byCve('CVE-2016-3235').products, []);
});

test('unrelated vendor is out of scope', () => {
  const other = items.filter((i) => !/Microsoft|VMware/.test(i.title + i.summary));
  assert.ok(other.length > 0);
  assert.ok(other.some((i) => i.products.length === 0));
});

test('empty object throws ParseError', () => {
  assert.throws(() => kev.parse(['{}'], cfg), ParseError);
});

test('non-json throws ParseError', () => {
  assert.throws(() => kev.parse(['not json'], cfg), ParseError);
});

test('microsoft windows component products map to all servers', () => {
  const doc = { vulnerabilities: ['Win32k', 'Netlogon', 'SMBv1', 'Internet Explorer', 'DirectX'].map((product, i) => ({
    cveID: `CVE-2026-90${i}`, vendorProject: 'Microsoft', product, vulnerabilityName: `${product} bug`, dateAdded: '2026-10-01', shortDescription: 'Microsoft component vulnerability.', requiredAction: 'Patch.' })) };
  for (const it of kev.parse([JSON.stringify(doc)], cfg)) assert.deepEqual(it.products.filter((p) => p.startsWith('ws')), ['ws2019', 'ws2022', 'ws2025'], it.title);
});

test('microsoft non-windows products stay out of scope', () => {
  const doc = { vulnerabilities: ['Office', 'Exchange Server', 'SharePoint', 'Edge'].map((product, i) => ({
    cveID: `CVE-2026-91${i}`, vendorProject: 'Microsoft', product, vulnerabilityName: `${product} bug`, dateAdded: '2026-10-01', shortDescription: 'Microsoft product vulnerability.', requiredAction: 'Patch.' })) };
  for (const it of kev.parse([JSON.stringify(doc)], cfg)) assert.deepEqual(it.products, [], it.title);
});

test('KEV Netlogon entry is a domain controller item on all servers', () => {
  const doc = { vulnerabilities: [{ cveID: 'CVE-2020-1472', vendorProject: 'Microsoft', product: 'Netlogon', vulnerabilityName: 'Microsoft Netlogon Privilege Escalation', dateAdded: '2026-10-01', shortDescription: 'Netlogon elevation of privilege.', requiredAction: 'Patch.' }] };
  assert.deepEqual(kev.parse([JSON.stringify(doc)], cfg)[0].products, ['dc', 'ws2019', 'ws2022', 'ws2025']);
});

test('browser tags only for Google/Mozilla entries', () => {
  const v = (vendorProject, product, shortDescription) => ({ cveID: `CVE-2026-8${vendorProject.length}${product.length}`, vendorProject, product, vulnerabilityName: `${vendorProject} ${product}`, dateAdded: '2026-10-01', shortDescription, requiredAction: 'Patch.' });
  const out = kev.parse([JSON.stringify({ vulnerabilities: [
    v('Ray-Project', 'Ray', 'Code injection reachable from a browser such as Chrome or Firefox.'),
    v('Google', 'Chromium V8', 'Google Chromium V8 type confusion.'),
    v('Mozilla', 'Firefox', 'Mozilla Firefox use-after-free.'),
  ] })], cfg);
  assert.deepEqual(out.map((i) => i.products), [[], ['chrome'], ['firefox']]);
});

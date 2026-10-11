const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ParseError } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const nvd = require('../../src/sources/nvd');

const cfg = loadConfig();
const body = fs.readFileSync(path.join(__dirname, '../fixtures/nvd/crowdstrike.json'), 'utf8');
const items = nvd.parse([body], cfg);

test('builds one url per agent keyword for the last 30 days', () => {
  const urls = nvd.nvdUrls(new Date('2026-10-10T00:00:00Z'));
  assert.equal(urls.length, 5);
  assert.ok(urls.every((u) => u.startsWith('https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=')));
  assert.ok(urls[0].includes('pubStartDate=2026-09-10T00:00:00.000Z'));
  assert.ok(urls[0].includes('pubEndDate=2026-10-10T00:00:00.000Z'));
  assert.ok(urls.some((u) => u.includes('keywordSearch=CrowdStrike%20Falcon')));
  assert.equal(nvd.minIntervalMs, 6500);
});

test('crowdstrike cves map to crowdstrike with cvss and severity', () => {
  const cs = items.filter((i) => i.products.includes('crowdstrike'));
  assert.ok(cs.length > 0);
  for (const i of cs) {
    assert.match(i.id, /^nvd:CVE-/);
    assert.equal(i.cves.length, 1);
    assert.equal(typeof i.cvss, 'number');
    assert.ok(['critical', 'important', 'moderate', 'low'].includes(i.severity));
  }
});

test('empty vulnerabilities array is valid', () => {
  assert.deepEqual(nvd.parse(['{"vulnerabilities":[]}'], cfg), []);
});

test('missing vulnerabilities throws ParseError', () => {
  assert.throws(() => nvd.parse(['{"message":"rate limited"}'], cfg), ParseError);
});

test('high maps to important and prefers v4 over v3', () => {
  const doc = { vulnerabilities: [{ cve: { id: 'CVE-2026-1', published: '2026-10-01T00:00:00.000', descriptions: [{ lang: 'en', value: 'Splunk Universal Forwarder flaw' }],
    metrics: { cvssMetricV31: [{ cvssData: { baseScore: 6.5, baseSeverity: 'MEDIUM' } }], cvssMetricV40: [{ cvssData: { baseScore: 8.7, baseSeverity: 'HIGH' } }] } } }] };
  const [it] = nvd.parse([JSON.stringify(doc)], cfg);
  assert.equal(it.cvss, 8.7);
  assert.equal(it.severity, 'important');
  assert.deepEqual(it.products, ['splunkuf']);
});

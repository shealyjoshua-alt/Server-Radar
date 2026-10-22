const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ParseError } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const az = require('../../src/sources/azureStatus');

const cfg = loadConfig();
const fx = (n) => fs.readFileSync(path.join(__dirname, `../fixtures/azure-status/${n}`), 'utf8');

test('module uses the canonical status feed', () => {
  assert.equal(az.id, 'azure-status');
  assert.deepEqual(az.urls, ['https://rssfeed.azure.status.microsoft/en-us/status/feed/']);
});

test('empty live feed is valid and yields nothing', () => {
  assert.deepEqual(az.parse([fx('feed-empty.xml')], cfg), []);
});

test('gov incident, commercial incident and maintenance', () => {
  const items = az.parse([fx('feed-synthetic.xml')], cfg);
  const gov = items.find((i) => i.id === 'azstatus:TEST-GOV-1');
  const com = items.find((i) => i.id === 'azstatus:TEST-COM-1');
  const maint = items.find((i) => i.id === 'azstatus:TEST-MAINT-1');
  assert.equal(gov.kind, 'incident');
  assert.equal(gov.gov, true);
  assert.equal(com.gov, false);
  assert.equal(maint.kind, 'maintenance');
  assert.equal(maint.gov, true);
  assert.ok(items.every((i) => i.products.includes('azure')));
  assert.equal(gov.published, '2026-10-10T14:30:00.000Z');
});

test('rss without channel throws ParseError', () => {
  assert.throws(() => az.parse(['<rss version="2.0"></rss>'], cfg), ParseError);
});

test('summary lists the Gov incidents active in this fetch', () => {
  assert.deepEqual(az.summarize([fx('feed-synthetic.xml')], cfg), { activeGov: ['azstatus:TEST-GOV-1'] });
  assert.deepEqual(az.summarize([fx('feed-empty.xml')], cfg), { activeGov: [] });
});

test('Entra outages are tagged entra', () => {
  const rss = '<rss version="2.0"><channel><title>Azure Status</title><item><guid>E1</guid><link>https://azure.status.microsoft/</link><title>Active - Microsoft Entra ID - US Gov Virginia - Sign-in failures</title><description>Customers may fail to authenticate.</description><pubDate>Thu, 22 Oct 2026 14:00:00 Z</pubDate></item></channel></rss>';
  const [it] = az.parse([rss], cfg);
  assert.deepEqual(it.products, ['azure', 'entra']);
  assert.equal(it.gov, true);
});

test('summary lists active Entra outages in any cloud', () => {
  const rss = '<rss version="2.0"><channel><title>Azure Status</title><item><guid>G1</guid><link>https://azure.status.microsoft/</link><title>Active - Azure Active Directory - Multiple regions - Sign-in failures</title><description>Authentication failures.</description><pubDate>Thu, 22 Oct 2026 14:00:00 Z</pubDate></item></channel></rss>';
  assert.deepEqual(az.summarize([rss], cfg), { activeGov: ['azstatus:G1'] });
});

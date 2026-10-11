const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ParseError } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const nagios = require('../../src/sources/nagios');

const cfg = loadConfig();
const body = fs.readFileSync(path.join(__dirname, '../fixtures/nagios/ncpa.json'), 'utf8');
const items = nagios.parse([body], cfg);

test('module reads NCPA disclosures from the WordPress API', () => {
  assert.equal(nagios.id, 'nagios');
  assert.deepEqual(nagios.urls, ['https://www.nagios.com/wp-json/wp/v2/security-disclosure?sd-product=625&per_page=100']);
});

test('each disclosure becomes an in-scope nagios vuln', () => {
  assert.equal(items.length, 2);
  const it = items.find((i) => i.title === 'NCPA 3.1.4');
  assert.deepEqual(it.products, ['nagios']);
  assert.equal(it.kind, 'vuln');
  assert.equal(it.severity, null); // Nagios gives no rating
  assert.match(it.summary, /bundled Python/);
  assert.equal(it.url, 'https://www.nagios.com/security-disclosures/ncpa/ncpa-3-1-4/');
  assert.equal(it.id, 'nagios:ncpa-3-1-4');
});

test('non-array body throws ParseError', () => {
  assert.throws(() => nagios.parse(['{"code":"rest_no_route"}'], cfg), ParseError);
});

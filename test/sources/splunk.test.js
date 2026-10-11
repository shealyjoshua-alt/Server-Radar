const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ParseError } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const splunk = require('../../src/sources/splunk');

const cfg = loadConfig();
const body = fs.readFileSync(path.join(__dirname, '../fixtures/splunk/feed.xml'), 'utf8');
const items = splunk.parse([body], cfg);

test('module shape', () => {
  assert.equal(splunk.id, 'splunk');
  assert.deepEqual(splunk.urls, ['https://advisory.splunk.com/feed.xml']);
});

test('parses all rss items with SVD ids', () => {
  assert.equal(items.length, 30);
  assert.ok(items.every((i) => /^splunk:SVD-\d{4}-\d{4}$/.test(i.id) && i.kind === 'vuln'));
});

test('universal forwarder advisory is splunkuf and important', () => {
  const uf = items.filter((i) => /Universal Forwarder/.test(i.title));
  assert.ok(uf.length > 0);
  assert.ok(uf.every((i) => i.products.includes('splunkuf') && i.severity === 'important'));
  assert.match(uf[0].published, /^\d{4}-\d{2}-\d{2}T/);
});

test('splunk enterprise or add-on advisory is out of scope', () => {
  const aws = items.find((i) => /Add-on for Amazon Web Services/.test(i.title));
  assert.deepEqual(aws.products, []);
});

test('rss without channel throws ParseError', () => {
  assert.throws(() => splunk.parse(['<rss></rss>'], cfg), ParseError);
});

test('channel with no items throws ParseError', () => {
  assert.throws(() => splunk.parse(['<rss version="2.0"><channel><title>x</title></channel></rss>'], cfg), ParseError);
});

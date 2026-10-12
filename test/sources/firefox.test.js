const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ParseError } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const firefox = require('../../src/sources/firefox');

const cfg = loadConfig();
const items = firefox.parse([fs.readFileSync(path.join(__dirname, '../fixtures/firefox/advisories.html'), 'utf8')], cfg);

test('module reads Mozilla security advisories', () => {
  assert.equal(firefox.id, 'firefox');
  assert.deepEqual(firefox.urls, ['https://www.mozilla.org/en-US/security/advisories/']);
});

test('firefox advisories become firefox items with impact and date', () => {
  const it = items.find((i) => i.id === 'mfsa:2026-104');
  assert.equal(it.title, 'Security Vulnerabilities fixed in Firefox 157.0.1');
  assert.equal(it.severity, 'moderate');
  assert.equal(it.published, '2026-10-06');
  assert.deepEqual(it.products, ['firefox']);
  assert.equal(it.url, 'https://www.mozilla.org/en-US/security/advisories/mfsa2026-104/');
  assert.equal(items.find((i) => i.id === 'mfsa:2026-100').severity, 'important');
});

test('thunderbird advisories are out of scope', () => {
  assert.ok(items.filter((i) => /Thunderbird/.test(i.title)).every((i) => i.products.length === 0));
});

test('only advisories from the 60 days before the newest one are kept', () => {
  assert.ok(items.length > 5);
  assert.ok(items.every((i) => i.published >= '2026-08-07'), 'older than 60 days before Oct 6');
});

test('page without advisories throws ParseError', () => {
  assert.throws(() => firefox.parse(['<html><h2>Nothing</h2></html>'], cfg), ParseError);
});

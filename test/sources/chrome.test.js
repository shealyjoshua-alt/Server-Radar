const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ParseError } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const chrome = require('../../src/sources/chrome');

const cfg = loadConfig();
const body = fs.readFileSync(path.join(__dirname, '../fixtures/chrome/stable.xml'), 'utf8');
const items = chrome.parse([body], cfg);

test('module reads the Chrome Releases stable-updates feed', () => {
  assert.equal(chrome.id, 'chrome');
  assert.match(chrome.urls[0], /^https:\/\/chromereleases\.googleblog\.com\/feeds\/posts\/default\/-\/Stable%20updates/);
});

test('one item per Windows/desktop stable release (the build Windows Server runs), other platforms skipped', () => {
  assert.equal(items.length, 3);
  assert.ok(items.every((i) => i.products.includes('chrome') && i.kind === 'vuln'));
});

test('release item summarises its security fixes', () => {
  const it = items.find((i) => i.id === 'chrome:155.0.8059.39');
  assert.match(it.title, /^Chrome 155\.0\.8059\.39 for Windows: \d+ security fixes \(4 critical, \d+ high\)$/);
  assert.equal(it.severity, 'critical');
  assert.ok(it.cves.includes('CVE-2026-106382'));
  assert.equal(it.exploited, false);
  assert.equal(it.published, '2026-10-06T17:17:52.425Z');
  assert.match(it.url, /^https:\/\/chromereleases\.googleblog\.com\//);
});

test('in-the-wild exploit marks the release exploited and puts that CVE first', () => {
  const xml = body.replace('updated to 155.0.8059.39', 'updated to 155.0.8059.39 (Google is aware that an exploit for CVE-2026-106197 exists in the wild.)');
  const it = chrome.parse([xml], cfg).find((i) => i.id === 'chrome:155.0.8059.39');
  assert.equal(it.exploited, true);
  assert.equal(it.cves[0], 'CVE-2026-106197');
});

test('feed without entries throws ParseError', () => {
  assert.throws(() => chrome.parse(['<feed xmlns="http://www.w3.org/2005/Atom"></feed>'], cfg), ParseError);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ParseError } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const php = require('../../src/sources/php');

const cfg = loadConfig();
const body = fs.readFileSync(path.join(__dirname, '../fixtures/php/feed.atom'), 'utf8');
const items = php.parse([body], cfg);

test('module reads the php.net news feed', () => {
  assert.equal(php.id, 'php');
  assert.deepEqual(php.urls, ['https://www.php.net/feed.atom']);
});

test('the security advisory becomes a critical PHP item with both CVEs', () => {
  const adv = items.find((i) => i.id.startsWith('php:advisory:'));
  assert.equal(adv.title, 'Security advisory: Critical remote code execution vulnerabilities, update now');
  assert.deepEqual(adv.cves, ['CVE-2026-109618', 'CVE-2026-109619']);
  assert.equal(adv.severity, 'critical');
  assert.equal(adv.kind, 'vuln');
  assert.deepEqual(adv.products, ['php']);
  assert.equal(adv.published.slice(0, 10), '2026-10-21');
  assert.match(adv.summary, /unauthenticated remote code execution/);
  assert.match(adv.url, /^https:\/\/www\.php\.net\/archive\/2026\.php#2026-10-21/);
});

test('security releases on the same day are grouped into one item', () => {
  const rel = items.filter((i) => i.id.startsWith('php:releases:'));
  const oct21 = rel.find((i) => i.id === 'php:releases:2026-10-21');
  assert.equal(oct21.title, 'PHP security releases: 8.5.12, 8.4.27, 8.3.36, 8.2.35');
  assert.equal(oct21.kind, 'release');
  assert.ok(rel.find((i) => i.id === 'php:releases:2026-09-24'));
});

test('summary: latest advisory with fixed versions and mitigations', () => {
  const { advisory } = php.summarize([body], cfg);
  assert.equal(advisory.date, '2026-10-21');
  assert.deepEqual(advisory.cves, ['CVE-2026-109618', 'CVE-2026-109619']);
  assert.deepEqual(advisory.fixed, ['8.5.12', '8.4.27', '8.3.36', '8.2.35']);
  assert.match(advisory.risk, /^Who is at risk: all PHP installations serving web requests/);
  assert.ok(advisory.mitigations.some((m) => /session\.upload_progress\.enabled=0/.test(m)));
  assert.ok(advisory.mitigations.some((m) => /memory_limit=-1/.test(m)));
  assert.match(advisory.url, /php\.net\/archive\/2026\.php#2026-10-21/);
});

test('feed without entries throws ParseError', () => {
  assert.throws(() => php.parse(['<feed xmlns="http://www.w3.org/2005/Atom"></feed>'], cfg), ParseError);
});

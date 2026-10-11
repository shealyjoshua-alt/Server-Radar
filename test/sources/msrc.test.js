const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ParseError } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const msrc = require('../../src/sources/msrc');

const cfg = loadConfig();
const body = fs.readFileSync(path.join(__dirname, '../fixtures/msrc/2026-Sep.json'), 'utf8');
const items = msrc.parse([null, body], cfg);
const byCve = (c) => items.find((i) => i.cves[0] === c);

test('module shape and monthly urls', () => {
  assert.equal(msrc.id, 'msrc');
  assert.equal(msrc.allow404, true);
  assert.deepEqual(msrc.msrcUrls(new Date(2026, 0, 5)), [
    'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jan',
    'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2025-Dec',
  ]);
  assert.equal(msrc.headers.Accept, 'application/json');
});

test('exploited entry is flagged and mapped to server version', () => {
  const it = byCve('CVE-2026-85880');
  assert.equal(it.exploited, true);
  assert.ok(it.products.includes('ws2019'));
  assert.equal(it.severity, 'important');
  assert.equal(it.id, 'msrc:CVE-2026-85880');
  assert.equal(it.url, 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-85880');
});

test('second exploited entry maps to 2025', () => {
  const it = byCve('CVE-2026-81963');
  assert.equal(it.exploited, true);
  assert.ok(it.products.includes('ws2025'));
});

test('windows 11 only entry is out of scope', () => {
  assert.deepEqual(byCve('CVE-2026-68842').products, []);
});

test('azure linux package cve is out of scope', () => {
  assert.deepEqual(byCve('CVE-2026-100075').products, []);
});

test('non-exploited entries are not flagged', () => {
  assert.equal(byCve('CVE-2026-68842').exploited, false);
});

test('cvss is the max base score', () => {
  const it = byCve('CVE-2026-100075');
  assert.ok(it.cvss >= 9);
});

test('a server 2022 entry has ws2022', () => {
  assert.ok(items.some((i) => i.products.includes('ws2022') && !i.exploited));
});

test('all-null bodies throw ParseError', () => {
  assert.throws(() => msrc.parse([null, null], cfg), ParseError);
});

test('document without Vulnerability throws ParseError', () => {
  assert.throws(() => msrc.parse(['{"ProductTree":{}}'], cfg), ParseError);
});

test('document with zero vulnerabilities throws ParseError', () => {
  assert.throws(() => msrc.parse(['{"Vulnerability":[]}', null], cfg), ParseError);
});

test('vulnerability titles are matched too (domain controller topics)', () => {
  const doc = { ProductTree: { FullProductName: [{ ProductID: '1', Value: 'Windows Server 2022' }] }, DocumentTracking: { CurrentReleaseDate: '2026-10-13' },
    Vulnerability: [{ CVE: 'CVE-2026-7777', Title: { Value: 'Windows Kerberos Elevation of Privilege Vulnerability' }, ProductStatuses: [{ ProductID: ['1'] }], Threats: [], CVSSScoreSets: [{ BaseScore: 8.1 }] }] };
  const [it] = msrc.parse([JSON.stringify(doc)], cfg);
  assert.deepEqual(it.products, ['dc', 'ws2022']);
});

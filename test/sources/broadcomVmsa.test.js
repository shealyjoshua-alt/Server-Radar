const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ParseError } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const vmsa = require('../../src/sources/broadcomVmsa');

const cfg = loadConfig();
const fx = (n) => fs.readFileSync(path.join(__dirname, `../fixtures/broadcom-vmsa/${n}.json`), 'utf8');
const items = vmsa.parse([fx('vc'), fx('se')], cfg);
const byAdv = (id) => items.find((i) => i.id === `vmsa:${id}`);

test('module posts to the advisory list endpoint for VC and SE segments', () => {
  assert.equal(vmsa.id, 'broadcom-vmsa');
  assert.equal(vmsa.requests.length, 2);
  for (const r of vmsa.requests) {
    assert.equal(r.method, 'POST');
    assert.match(r.url, /getSecurityAdvisoryList$/);
  }
  assert.deepEqual(vmsa.requests.map((r) => JSON.parse(r.body).segment), ['VC', 'SE']);
});

test('vcenter/esx advisory maps to vmware with CVEs and date', () => {
  const it = byAdv('VMSA-2026-0006.1');
  assert.deepEqual(it.products, ['vmware']);
  assert.equal(it.cves.length, 5);
  assert.equal(it.cves[0], 'CVE-2026-59309');
  assert.equal(it.severity, 'critical');
  assert.equal(it.cvss, 9.0);
  assert.equal(it.published, '2026-07-29');
  assert.match(it.url, /^https:\/\/support\.broadcom\.com\//);
});

test('workstation/fusion-only advisory is out of scope', () => {
  assert.deepEqual(byAdv('VMSA-2026-0007').products, []);
});

test('high severity maps to important without cvss', () => {
  const it = byAdv('VMSA-2025-0016');
  assert.equal(it.severity, 'important');
  assert.equal(it.cvss, null);
});

test('carbon black advisory maps to carbonblack', () => {
  const cb = items.filter((i) => /Carbon Black/.test(i.title));
  assert.ok(cb.length > 0);
  assert.ok(cb.every((i) => i.products.includes('carbonblack')));
});

test('advisory without VMSA id uses document id', () => {
  const cb = items.find((i) => /Carbon Black/.test(i.title));
  assert.match(cb.id, /^vmsa:/);
});

test('garbage body throws ParseError', () => {
  assert.throws(() => vmsa.parse(['<html>', fx('se')], cfg), ParseError);
  assert.throws(() => vmsa.parse(['{"success":false}', fx('se')], cfg), ParseError);
});

test('empty advisory list throws ParseError', () => {
  assert.throws(() => vmsa.parse(['{"success":true,"data":{"list":[]}}', fx('se')], cfg), ParseError);
});

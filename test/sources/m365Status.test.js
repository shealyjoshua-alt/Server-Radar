const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ParseError } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const m365 = require('../../src/sources/m365Status');

const cfg = loadConfig();
const available = fs.readFileSync(path.join(__dirname, '../fixtures/m365-status/mac-available.json'), 'utf8');
// Synthetic outage post in the same shape as the live API (no outage was posted on 2026-10-22).
const outage = JSON.stringify({ Id: 'abc-123', AuthoredDateTime: '2026-10-22T14:00:00+00:00', LastUpdatedTime: '2026-10-22T15:00:00+00:00',
  Title: 'Users may be unable to sign in to Microsoft 365 services', Message: '<div>Microsoft Entra ID authentication failures affecting <b>GCC</b> and commercial tenants.</div>', Status: 'ServiceDegradation' });

test('module reads the public Microsoft 365 status post', () => {
  assert.equal(m365.id, 'm365-status');
  assert.deepEqual(m365.urls, ['https://status.cloud.microsoft/api/posts/mac']);
});

test('no outage posted: no items, nothing active', () => {
  assert.deepEqual(m365.parse([available], cfg), []);
  assert.deepEqual(m365.summarize([available], cfg), { active: [] });
});

test('an outage post becomes an active Microsoft 365 incident', () => {
  const [it] = m365.parse([outage], cfg);
  assert.equal(it.id, 'm365:abc-123');
  assert.equal(it.kind, 'incident');
  assert.equal(it.title, 'Users may be unable to sign in to Microsoft 365 services');
  assert.deepEqual(it.products, ['entra', 'm365']);
  assert.equal(it.gov, true); // mentions GCC
  assert.match(it.summary, /authentication failures/);
  assert.equal(it.published, '2026-10-22T14:00:00.000Z');
  assert.deepEqual(m365.summarize([outage], cfg), { active: ['m365:abc-123'] });
});

test('unexpected shape throws ParseError', () => {
  assert.throws(() => m365.parse(['{"nope":1}'], cfg), ParseError);
  assert.throws(() => m365.parse(['<html>'], cfg), ParseError);
});

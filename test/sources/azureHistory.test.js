const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ParseError } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const hist = require('../../src/sources/azureHistory');

const cfg = loadConfig();
const html = fs.readFileSync(path.join(__dirname, '../fixtures/azure-history/history.html'), 'utf8');
const items = hist.parse([html], cfg);

test('module reads the Azure status history page', () => {
  assert.equal(hist.id, 'azure-history');
  assert.deepEqual(hist.urls, ['https://azure.status.microsoft/en-us/status/history/']);
});

test('each post-incident entry becomes a resolved incident', () => {
  assert.equal(items.length, 3);
  const it = items.find((i) => i.id === 'azhist:7Q30-010');
  assert.equal(it.kind, 'incident');
  assert.equal(it.status, 'resolved');
  assert.equal(it.published, '2026-09-30');
  assert.match(it.title, /Multiple services experiencing connectivity issues/);
  assert.equal(it.gov, false);
  assert.deepEqual(it.products, ['azure']);
});

test('an entry whose review names a US Gov region is a Gov outage', () => {
  const g = html.replace('Incorrect Region: correction', 'Impacted regions: US Gov Virginia. Incorrect Region: correction');
  assert.equal(hist.parse([g], cfg).find((i) => i.id === 'azhist:7Q30-010').gov, true);
});

test('page without entries throws ParseError', () => {
  assert.throws(() => hist.parse(['<html><body>nothing</body></html>'], cfg), ParseError);
});

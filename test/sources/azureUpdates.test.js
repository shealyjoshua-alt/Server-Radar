const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ParseError } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const upd = require('../../src/sources/azureUpdates');

const cfg = loadConfig();
const items = upd.parse([fs.readFileSync(path.join(__dirname, '../fixtures/azure-updates/rss.xml'), 'utf8')], cfg);

test('module shape', () => {
  assert.equal(upd.id, 'azure-updates');
  assert.deepEqual(upd.urls, ['https://www.microsoft.com/releasecommunications/api/v2/azure/rss']);
});

test('all items parsed with azure product and guid ids', () => {
  assert.equal(items.length, 200);
  assert.ok(items.every((i) => i.products.includes('azure') && /^azupd:\S+$/.test(i.id)));
});

test('retirement category becomes retirement kind', () => {
  const r = items.find((i) => i.id === 'azupd:570313');
  assert.equal(r.kind, 'retirement');
  assert.equal(items.filter((i) => i.kind === 'retirement').length, 26);
});

test('launch is update kind with date', () => {
  const u = items.find((i) => i.id === 'azupd:574430');
  assert.equal(u.kind, 'update');
  assert.equal(u.published, '2026-10-08T22:51:01.000Z');
});

test('azure government items are flagged gov', () => {
  assert.ok(items.some((i) => i.gov && /Azure Gover/.test(i.title)));
});

test('rss without channel throws ParseError', () => {
  assert.throws(() => upd.parse(['<rss version="2.0"></rss>'], cfg), ParseError);
});

test('channel with no items throws ParseError', () => {
  assert.throws(() => upd.parse(['<rss version="2.0"><channel><title>x</title></channel></rss>'], cfg), ParseError);
});

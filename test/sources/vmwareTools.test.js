const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ParseError } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const tools = require('../../src/sources/vmwareTools');

const cfg = { ...loadConfig(), vmwareToolsVersions: ['13.0.5', '13.1.0'] };
const html = fs.readFileSync(path.join(__dirname, '../fixtures/vmware-tools/releases.html'), 'utf8');

test('module reads the VMware Tools release index', () => {
  assert.equal(tools.id, 'vmware-tools');
  assert.deepEqual(tools.urls, ['https://packages.vmware.com/tools/releases/']);
});

test('compareVersions orders numerically', () => {
  assert.ok(tools.compareVersions('13.0.10', '13.0.5') > 0);
  assert.ok(tools.compareVersions('13.1.0', '13.0.10') > 0);
  assert.equal(tools.compareVersions('13.1.0', '13.1.0'), 0);
});

test('a release newer than everything installed becomes a VMware release item', () => {
  const items = tools.parse([html], cfg);
  assert.deepEqual(items.map((i) => i.id), ['vmtools:13.1.5']);
  assert.equal(items[0].kind, 'release');
  assert.deepEqual(items[0].products, ['vmware']);
  assert.equal(items[0].title, 'VMware Tools 13.1.5 available (you run 13.0.5, 13.1.0)');
  assert.equal(items[0].url, 'https://packages.vmware.com/tools/releases/13.1.5/');
});

test('summary: latest version and what each installed version is behind', () => {
  assert.deepEqual(tools.summarize([html], cfg), {
    latest: '13.1.5',
    installed: [
      { version: '13.0.5', newer: ['13.0.10', '13.1.0', '13.1.5'] },
      { version: '13.1.0', newer: ['13.1.5'] },
    ],
  });
});

test('index without versions throws ParseError', () => {
  assert.throws(() => tools.parse(['<html></html>'], cfg), ParseError);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadConfig } = require('../../src/core/match');
const msrc = require('../../src/sources/msrc');

const cfg = loadConfig();
const sep = fs.readFileSync(path.join(__dirname, '../fixtures/msrc/2026-Sep.json'), 'utf8');

test('summarizes each monthly release for Windows Server', () => {
  const { months } = msrc.summarize([null, sep], cfg);
  assert.equal(months.length, 1);
  const m = months[0];
  assert.equal(m.month, '2026-09');
  assert.equal(m.label, 'September 2026');
  assert.equal(m.url, 'https://msrc.microsoft.com/update-guide/releaseNote/2026-Sep');
  assert.deepEqual(m.kbs, { ws2019: 'KB5122876', ws2022: 'KB5122882', ws2025: 'KB5122871' });
  assert.ok(m.serverCves > 0);
  assert.equal(m.exploited, 2);
  assert.ok(m.top.length > 0 && m.top.length <= 6);
  assert.ok(m.top.every((t) => t.cvss === null || t.cvss >= 7), 'critical/high only');
  assert.ok(m.top[0].exploited, 'exploited listed first');
});

test('a month with no Windows Server CVEs yet is left out', () => {
  const doc = { DocumentTracking: { Identification: { ID: { Value: '2026-Oct' } } }, ProductTree: { FullProductName: [{ ProductID: '1', Value: 'azl3 kernel on Azure Linux 3.0' }] },
    Vulnerability: [{ CVE: 'CVE-1', Title: { Value: 'x' }, ProductStatuses: [{ ProductID: ['1'] }], Threats: [], Remediations: [] }] };
  assert.deepEqual(msrc.summarize([JSON.stringify(doc), sep], cfg).months.map((m) => m.month), ['2026-09']);
});

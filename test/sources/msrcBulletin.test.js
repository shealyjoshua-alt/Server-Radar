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

test('lists every patch per Server version: cumulative, .NET, hotpatch, store', () => {
  const P = (id, Value) => ({ ProductID: id, Value });
  const R = (kb, ids, SubType = 'Security Update', url = `https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB${kb}`) => ({ Type: 2, SubType, Description: { Value: kb }, ProductID: ids, URL: url });
  const doc = { DocumentTracking: { Identification: { ID: { Value: '2026-Oct' } } },
    ProductTree: { FullProductName: [P('1', 'Windows Server 2022'), P('2', 'Windows Server 2022 (Server Core installation)'),
      P('3', 'Microsoft .NET Framework 3.5 AND 4.8 on Windows Server 2022'), P('4', 'HEVC Video Extensions from Device Manufacturer on Windows Server 2022'), P('5', 'Windows Server 2025')] },
    Vulnerability: [
      { CVE: 'CVE-1', Title: { Value: 'a' }, ProductStatuses: [{ ProductID: ['1', '2', '5'] }], Threats: [], CVSSScoreSets: [{ BaseScore: 8 }],
        Remediations: [R('5130001', ['1', '2']), R('5130009', ['5']), R('5130010', ['5'], 'Security Hotpatch Update')] },
      { CVE: 'CVE-2', Title: { Value: 'b' }, ProductStatuses: [{ ProductID: ['1', '3'] }], Threats: [], CVSSScoreSets: [{ BaseScore: 7 }],
        Remediations: [R('5130001', ['1']), R('5130002', ['3'])] },
      { CVE: 'CVE-3', Title: { Value: 'c' }, ProductStatuses: [{ ProductID: ['4'] }], Threats: [], CVSSScoreSets: [{ BaseScore: 7.8 }],
        Remediations: [{ Type: 2, SubType: 'Security Update', Description: { Value: 'Update Information' }, ProductID: ['4'], URL: 'https://apps.microsoft.com/store/detail/hevc' }] },
    ] };
  const [m] = msrc.summarize([JSON.stringify(doc)], cfg).months;
  assert.deepEqual(m.patches.ws2022, [
    { kb: 'KB5130001', label: 'Monthly cumulative update', cves: 2, url: 'https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5130001' },
    { kb: 'KB5130002', label: '.NET Framework 3.5 and 4.8 cumulative update', cves: 1, url: 'https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5130002' },
    { kb: null, label: 'HEVC Video Extensions from Device Manufacturer (Microsoft Store)', cves: 1, url: 'https://apps.microsoft.com/store/detail/hevc' },
  ]);
  assert.deepEqual(m.patches.ws2025.map((p) => [p.kb, p.label]), [['KB5130009', 'Monthly cumulative update'], ['KB5130010', 'Hotpatch update']]);
  assert.equal(m.kbs.ws2022, 'KB5130001');
});

test('september fixture lists the cumulative update first for each version', () => {
  const [m] = msrc.summarize([null, sep], cfg).months;
  assert.equal(m.patches.ws2019[0].kb, 'KB5122876');
  assert.equal(m.patches.ws2019[0].label, 'Monthly cumulative update');
});

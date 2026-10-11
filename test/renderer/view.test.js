const test = require('node:test');
const assert = require('node:assert/strict');
const V = require('../../src/renderer/view');

const base = (over) => ({ key: Math.random().toString(36).slice(2), title: 't', url: 'https://example.com/', published: '2026-10-09T00:00:00Z', summary: '', cves: [], cvss: null, exploited: false, kind: 'vuln', status: null, products: ['ws2022'], gov: false, tier: 'watch', read: false, sources: ['msrc'], ...over });
const vmWith = (items, sources = []) => ({
  snapshot: { items, sources, updatedAt: '2026-10-10T12:00:00Z' },
  icon: { color: 'green', count: 0, tooltip: 'All clear' },
  tiles: { windows: { unread: 0, color: 'green' }, vmware: { unread: 0, color: 'green' }, azure: { unread: 0, color: 'green' }, agents: { unread: 0, color: 'green' } },
  patchTuesday: new Date(2026, 9, 13).toISOString(),
  safe: [{ version: 'ws2022', status: 'caution', openIssues: 1, resolved: 0 }],
  configNote: { crowdstrike: 'CrowdStrike tech alerts are behind the customer portal; coverage here is public CVEs, Microsoft notes and community reports.' },
});

test('escapeHtml escapes markup and quotes', () => {
  assert.equal(V.escapeHtml('<a href="x">&\'</a>'), '&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;');
});

test('safeUrl allows only http and https', () => {
  assert.equal(V.safeUrl('https://a.b/c'), 'https://a.b/c');
  assert.equal(V.safeUrl('javascript:alert(1)'), '#');
  assert.equal(V.safeUrl('  JavaScript:alert(1)'), '#');
  assert.equal(V.safeUrl('file:///etc/passwd'), '#');
  assert.equal(V.safeUrl('not a url'), '#');
});

test('feed text is escaped', () => {
  const vm = vmWith([base({ title: '<img src=x onerror=alert(1)>', summary: '<script>x</script>', url: 'javascript:alert(1)', tier: 'act' })]);
  const html = V.renderFeed(vm, { products: [] });
  assert.ok(!html.includes('<img'));
  assert.ok(!html.includes('<script'));
  assert.ok(html.includes('&lt;img'));
  assert.ok(!html.includes('javascript:'));
});

test('tiers render in order act, watch, interest with headings', () => {
  const html = V.renderFeed(vmWith([base({ tier: 'interest', title: 'I' }), base({ tier: 'act', title: 'A' }), base({ tier: 'watch', title: 'W' })]), { products: [] });
  const a = html.indexOf('Act now'); const w = html.indexOf('Keep an eye on'); const i = html.indexOf('Might interest you');
  assert.ok(a >= 0 && a < w && w < i);
});

test('azure-only tier items are not in the feed', () => {
  const html = V.renderFeed(vmWith([base({ tier: 'azure', title: 'AzureOnly' })]), { products: [] });
  assert.ok(!html.includes('AzureOnly'));
});

test('empty tier shows Nothing here.', () => {
  const html = V.renderFeed(vmWith([]), { products: [] });
  assert.equal(html.split('Nothing here.').length - 1, 3);
});

test('filter ws2022 hides vmware-only items', () => {
  const html = V.renderFeed(vmWith([base({ title: 'Win', products: ['ws2022'] }), base({ title: 'VM', products: ['vmware'] })]), { products: ['ws2022'] });
  assert.ok(html.includes('Win'));
  assert.ok(!html.includes('>VM<'));
});

test('gov filter keeps gov items only', () => {
  const html = V.renderFeed(vmWith([base({ title: 'GovThing', products: ['azure'], gov: true }), base({ title: 'Commercial', products: ['azure'] })]), { products: ['gov'] });
  assert.ok(html.includes('GovThing'));
  assert.ok(!html.includes('Commercial'));
});

test('tags reflect item state', () => {
  const html = V.renderFeed(vmWith([
    base({ tier: 'act', exploited: true, title: 'e' }),
    base({ tier: 'act', cvss: 9.8, title: 'c' }),
    base({ kind: 'known-issue', status: 'resolved', fixedBy: 'KB1', title: 'f' }),
    base({ kind: 'known-issue', status: 'open', title: 'k' }),
    base({ kind: 'incident', gov: true, products: ['azure'], title: 'g' }),
    base({ kind: 'retirement', products: ['azure'], title: 'r' }),
    base({ tier: 'interest', kind: 'update', products: ['azure'], title: 'n' }),
  ]), { products: [] });
  for (const tag of ['EXPLOITED', 'CRITICAL', 'FIXED', 'KNOWN ISSUE', 'AZURE GOV', 'RETIRING', 'NEW TECH']) assert.ok(html.includes(tag), tag);
});

test('unread items are marked and carry mark-read buttons', () => {
  const it = base({ key: 'CVE-2026-1' });
  const html = V.renderFeed(vmWith([it]), { products: [] });
  assert.match(html, /class="item[^"]*unread/);
  assert.match(html, /data-action="mark-read" data-key="CVE-2026-1"/);
});

test('filter chips include all products and crowdstrike note when selected', () => {
  const vm = vmWith([]);
  const chips = V.renderFilters(vm, { products: [] });
  for (const label of ['Server 2019', 'Server 2022', 'Server 2025', 'VMware', 'Azure', 'Azure Gov', 'CrowdStrike', 'Carbon Black', 'Nagios', 'Splunk UF']) assert.ok(chips.includes(label), label);
  assert.ok(!chips.includes('customer portal'));
  assert.ok(V.renderFilters(vm, { products: ['crowdstrike'] }).includes('customer portal'));
});

test('patch bar shows days until Patch Tuesday and safe-to-deploy', () => {
  const html = V.renderPatchBar(vmWith([]), new Date(2026, 9, 10, 9, 0));
  assert.match(html, /3 days/);
  assert.match(html, /Server 2022/);
  assert.match(html, /Caution/);
});

test('patch bar says today on patch tuesday', () => {
  assert.match(V.renderPatchBar(vmWith([]), new Date(2026, 9, 13, 9, 0)), /today/i);
});

test('patch bar lists upcoming maintenance escaped', () => {
  const html = V.renderPatchBar(vmWith([base({ kind: 'maintenance', products: ['azure'], title: 'Maint <b>x</b>' })]), new Date(2026, 9, 10));
  assert.ok(html.includes('Maint &lt;b&gt;x&lt;/b&gt;'));
});

test('tiles show four groups', () => {
  const html = V.renderTiles(vmWith([]));
  for (const label of ['Windows Server', 'VMware', 'Azure', 'Agents']) assert.ok(html.includes(label));
});

test('azure section lists azure items of any tier, gov tagged', () => {
  const html = V.renderAzure(vmWith([base({ sources: ['azure-updates'], tier: 'azure', title: 'Plain' }), base({ sources: ['azure-updates'], tier: 'watch', gov: true, title: 'GovRet' }), base({ title: 'NotAzure' })]));
  assert.ok(html.includes('Plain') && html.includes('GovRet') && html.includes('GOV'));
  assert.ok(!html.includes('NotAzure'));
});

test('source footer shows failing source error text escaped', () => {
  const html = V.renderSources(vmWith([], [{ id: 'msrc', label: 'Microsoft', lastOk: null, lastError: '<b>boom</b>', consecutiveFailures: 3 }]));
  assert.ok(html.includes('&lt;b&gt;boom&lt;/b&gt;'));
  assert.ok(html.includes('Microsoft'));
});

test('each tier shows all unread plus at most 20 read items, with a show-all control', () => {
  const items = [];
  for (let i = 0; i < 5; i++) items.push(base({ key: `u${i}`, title: `Unread${i}` }));
  for (let i = 0; i < 30; i++) items.push(base({ key: `r${i}`, title: `Read${i}`, read: true }));
  const html = V.renderFeed(vmWith(items), { products: [] });
  assert.equal((html.match(/class="item /g) || []).length, 25);
  assert.match(html, /data-action="show-all" data-tier="watch">Show all 35/);
  const all = V.renderFeed(vmWith(items), { products: [], expanded: ['watch'] });
  assert.equal((all.match(/class="item /g) || []).length, 35);
  assert.ok(!all.includes('data-action="show-all" data-tier="watch"'));
});

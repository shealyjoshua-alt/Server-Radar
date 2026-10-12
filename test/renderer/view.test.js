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
  assert.match(html, />In 3 days</);
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

test('azure section lists only azure government items', () => {
  const html = V.renderAzure(vmWith([base({ sources: ['azure-updates'], tier: 'azure', title: 'Plain' }), base({ sources: ['azure-updates'], tier: 'watch', gov: true, title: 'GovRet' }), base({ sources: ['azure-status'], kind: 'incident', gov: true, title: 'GovIncident' }), base({ title: 'NotAzure' })]));
  assert.ok(html.includes('GovRet') && html.includes('GovIncident'));
  assert.ok(!html.includes('Plain'));
  assert.ok(!html.includes('NotAzure'));
});

test('azure section empty state mentions government', () => {
  assert.match(V.renderAzure(vmWith([base({ sources: ['azure-updates'], title: 'Plain' })])), /No Azure Government items/);
});

test('source footer shows failing source error text escaped', () => {
  const html = V.renderSources(vmWith([], [{ id: 'msrc', label: 'Microsoft', lastOk: null, lastError: '<b>boom</b>', consecutiveFailures: 3 }]));
  assert.ok(html.includes('&lt;b&gt;boom&lt;/b&gt;'));
  assert.ok(html.includes('Microsoft'));
});

const daysAgoIso = (n) => new Date(Date.now() - n * 86400000).toISOString();

test('keep an eye on shows the 8 most important recent items, then See more', () => {
  const items = [];
  for (let i = 0; i < 12; i++) items.push(base({ key: `ret${i}`, kind: 'retirement', products: ['azure'], title: `Retire${i}`, published: daysAgoIso(1) }));
  items.push(base({ key: 'ki', kind: 'known-issue', status: 'open', title: 'OpenIssue', published: daysAgoIso(5) }));
  items.push(base({ key: 'cv', cvss: 9.8, title: 'HighScore', published: daysAgoIso(10) }));
  items.push(base({ key: 'old', cvss: 9.8, title: 'OldHighScore', published: daysAgoIso(60) }));
  const html = V.renderFeed(vmWith(items), { products: [] });
  const watch = html.slice(html.indexOf('Keep an eye on'), html.indexOf('Might interest you'));
  assert.equal((watch.match(/class="item /g) || []).length, 8);
  assert.ok(watch.indexOf('HighScore') < watch.indexOf('OpenIssue'));
  assert.ok(watch.indexOf('OpenIssue') < watch.indexOf('Retire'));
  assert.ok(!watch.includes('OldHighScore'));
  assert.match(watch, /data-action="show-all" data-tier="watch">See more \(15\)/);
});

test('see more expands a tier to everything', () => {
  const items = [];
  for (let i = 0; i < 12; i++) items.push(base({ key: `r${i}`, kind: 'retirement', products: ['azure'], published: daysAgoIso(i) }));
  const html = V.renderFeed(vmWith(items), { products: [], expanded: ['watch'] });
  assert.equal((html.match(/class="item /g) || []).length, 12);
  assert.ok(!html.includes('data-tier="watch">See more'));
});

test('might interest you shows the 5 newest', () => {
  const items = [];
  for (let i = 0; i < 9; i++) items.push(base({ key: `n${i}`, tier: 'interest', kind: 'update', products: ['azure'], title: `New${i}x`, published: daysAgoIso(i) }));
  const html = V.renderFeed(vmWith(items), { products: [] });
  const interest = html.slice(html.indexOf('Might interest you'));
  assert.equal((interest.match(/class="item /g) || []).length, 5);
  assert.ok(interest.includes('New0x') && !interest.includes('New5x'));
  assert.match(interest, /See more \(9\)/);
});

test('act now is never capped', () => {
  const items = [];
  for (let i = 0; i < 15; i++) items.push(base({ key: `a${i}`, tier: 'act', exploited: true, published: daysAgoIso(i) }));
  const html = V.renderFeed(vmWith(items), { products: [] });
  assert.equal((html.match(/class="item /g) || []).length, 15);
});

test('a quiet month says so but still offers See more', () => {
  const html = V.renderFeed(vmWith([base({ key: 'o', kind: 'retirement', products: ['azure'], published: daysAgoIso(90) })]), { products: [] });
  const watch = html.slice(html.indexOf('Keep an eye on'), html.indexOf('Might interest you'));
  assert.match(watch, /Nothing new in the last 30 days/);
  assert.match(watch, /See more \(1\)/);
});

test('collapsed keep-an-eye-on mixes kinds: at most 3 of a kind before filling', () => {
  const items = [];
  for (let i = 0; i < 10; i++) items.push(base({ key: `c${i}`, cvss: 9.8, title: `Crit${i}x`, published: daysAgoIso(1) }));
  items.push(base({ key: 'ki', kind: 'known-issue', status: 'open', title: 'OpenIssue', published: daysAgoIso(3) }));
  items.push(base({ key: 'vm', severity: 'important', products: ['vmware'], title: 'VmwareThing', published: daysAgoIso(4) }));
  const html = V.renderFeed(vmWith(items), { products: [] });
  const titles = [...html.slice(html.indexOf('Keep an eye on'), html.indexOf('Might interest you')).matchAll(/data-url="[^"]*">([^<]+)</g)].map((m) => m[1]);
  assert.equal(titles.length, 8);
  assert.deepEqual(titles.slice(0, 5).filter((t) => !t.startsWith('Crit')), ['OpenIssue', 'VmwareThing']);
});

test('tiles are buttons that filter to their group', () => {
  const html = V.renderTiles(vmWith([]), { products: [] });
  for (const g of ['windows', 'vmware', 'azure', 'agents']) assert.match(html, new RegExp(`data-action="tile" data-group="${g}"`));
  assert.ok(!html.includes('tile on'));
});

test('the tile matching the current filter is highlighted', () => {
  const html = V.renderTiles(vmWith([]), { products: [...V.GROUP_FILTERS.windows] });
  assert.match(html, /class="tile [^"]*\bon\b[^"]*" data-action="tile" data-group="windows"/);
  assert.equal((html.match(/\bon\b"/g) || []).length + (html.match(/ on /g) || []).length > 0, true);
});

test('group filters cover the right products', () => {
  assert.deepEqual(V.GROUP_FILTERS.windows, ['ws2019', 'ws2022', 'ws2025']);
  assert.deepEqual(V.GROUP_FILTERS.vmware, ['vmware']);
  assert.deepEqual(V.GROUP_FILTERS.azure, ['gov']);
  assert.deepEqual(V.GROUP_FILTERS.agents, ['crowdstrike', 'carbonblack', 'nagios', 'splunkuf']);
});

test('a tile filter shows a banner with Show everything', () => {
  const html = V.renderFilters(vmWith([]), { products: [...V.GROUP_FILTERS.vmware] });
  assert.match(html, /Showing only VMware/);
  assert.match(html, /data-action="clear-filters"/);
  assert.ok(!V.renderFilters(vmWith([]), { products: [] }).includes('clear-filters'));
});

test('domain controllers tile and filter exist', () => {
  const vm = vmWith([]);
  vm.tiles.dc = { unread: 2, color: 'amber' };
  assert.match(V.renderTiles(vm, { products: [] }), /data-group="dc"><h4>Domain Controllers/);
  assert.deepEqual(V.GROUP_FILTERS.dc, ['dc']);
  assert.ok(V.renderFilters(vm, { products: [] }).includes('data-filter="dc">Domain Controllers'));
  assert.match(V.renderFilters(vm, { products: ['dc'] }), /Showing only Domain Controllers/);
});

test('patch bar uses the viewer\'s own calendar, not the server\'s UTC date', () => {
  const vm = vmWith([]);
  vm.patchTuesday = '2026-10-13T00:00:00.000Z'; // what a UTC build server sends
  const html = V.renderPatchBar(vm, new Date(2026, 9, 12, 20, 0)); // Mon Oct 12, 8 PM local
  assert.match(html, />Tomorrow</);
  assert.match(html, /2026-10-13/);
});

test('patch bar on the day itself says today', () => {
  assert.match(V.renderPatchBar(vmWith([]), new Date(2026, 9, 13, 23, 30)), />Today</);
});

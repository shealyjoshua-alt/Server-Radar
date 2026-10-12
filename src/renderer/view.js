// Pure HTML-string renderers for the dashboard. Loaded by Node tests (module.exports)
// and by the renderer page (window.RadarView). All feed text goes through escapeHtml.
(function (root) {
  const PatchCycle = typeof module !== 'undefined' && module.exports ? require('../core/patchCycle') : root.RadarPatchCycle;
  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  const escapeHtml = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ESC[c]);

  function safeUrl(u) {
    try {
      const url = new URL(String(u).trim());
      return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : '#';
    } catch {
      return '#';
    }
  }

  const PRODUCT_LABELS = {
    ws2019: 'Server 2019', ws2022: 'Server 2022', ws2025: 'Server 2025', vmware: 'VMware', azure: 'Azure',
    gov: 'Azure Gov', dc: 'Domain Controllers', crowdstrike: 'CrowdStrike', carbonblack: 'Carbon Black', nagios: 'Nagios', splunkuf: 'Splunk UF',
  };
  const FILTERS = ['ws2019', 'ws2022', 'ws2025', 'dc', 'vmware', 'azure', 'gov', 'crowdstrike', 'carbonblack', 'nagios', 'splunkuf'];
  const SOURCE_LABELS = {
    'cisa-kev': 'CISA KEV', msrc: 'Microsoft', 'release-health': 'Release health', 'broadcom-vmsa': 'Broadcom',
    splunk: 'Splunk', nagios: 'Nagios', nvd: 'NVD', 'azure-status': 'Azure status', 'azure-updates': 'Azure Updates',
  };
  // Tile -> filter chips it selects (a tile click shows just that area).
  const GROUP_FILTERS = {
    windows: ['ws2019', 'ws2022', 'ws2025'],
    vmware: ['vmware'],
    azure: ['gov'],
    agents: ['crowdstrike', 'carbonblack', 'nagios', 'splunkuf'],
    dc: ['dc'],
  };
  const TILES = [['windows', 'Windows Server'], ['vmware', 'VMware'], ['azure', 'Azure Gov'], ['agents', 'Agents'], ['dc', 'Domain Controllers']];
  const TIERS = [['act', 'Act now'], ['watch', 'Keep an eye on'], ['interest', 'Might interest you']];
  const DAY = 86400000;
  const RECENT_DAYS = 30;
  // Act now (zero-days) is never capped.
  const TIER_CAP = { watch: 8, interest: 5 };
  const PER_KIND = 3;
  const AGENT_IDS = ['crowdstrike', 'carbonblack', 'nagios', 'splunkuf'];

  // Lower is more important (Keep an eye on ranking).
  function importance(it) {
    if (it.cvss != null && it.cvss >= 9) return 0;
    if (it.kind === 'known-issue' && it.status !== 'resolved') return 1;
    if (it.kind === 'vuln' && it.products.some((p) => p === 'vmware' || AGENT_IDS.includes(p))) return 2;
    if (it.kind === 'vuln' && it.severity === 'critical') return 3;
    if (it.kind === 'incident' || it.kind === 'maintenance') return 4;
    if (it.kind === 'retirement') return 5;
    if (it.kind === 'known-issue') return 6;
    return 7;
  }

  function tagFor(it) {
    if (it.exploited) return ['EXPLOITED', 'red'];
    if (it.tier === 'act') return ['CRITICAL', 'red'];
    if (it.kind === 'known-issue') return it.status === 'resolved' ? ['FIXED', 'green'] : ['KNOWN ISSUE', 'amber'];
    if (it.kind === 'incident') return it.gov ? ['AZURE GOV', 'amber'] : ['INCIDENT', 'amber'];
    if (it.kind === 'maintenance') return ['MAINTENANCE', 'amber'];
    if (it.kind === 'retirement') return ['RETIRING', 'blue'];
    if (it.tier === 'interest') return ['NEW TECH', 'blue'];
    return ['VULN', 'amber'];
  }

  const fmtDate = (iso) => (iso ? String(iso).slice(0, 10) : '');
  const tag = ([text, color]) => `<span class="tag t-${color}">${escapeHtml(text)}</span>`;
  const link = (it) => `<a class="title" href="#" data-url="${escapeHtml(safeUrl(it.url))}">${escapeHtml(it.title)}</a>`;

  function matchesFilters(it, filters) {
    const sel = (filters && filters.products) || [];
    if (!sel.length) return true;
    return sel.some((f) => (f === 'gov' ? it.gov : it.products.includes(f)));
  }

  function renderItem(it) {
    const chips = it.products.map((p) => `<span class="chip">${escapeHtml(PRODUCT_LABELS[p] || p)}</span>`).join('');
    const sources = (it.sources || [it.source]).map((s) => escapeHtml(SOURCE_LABELS[s] || s)).join(', ');
    const extra = [
      it.cvss != null ? `CVSS ${escapeHtml(it.cvss)}` : '',
      it.fixedBy && it.fixedBy !== 'resolved' ? `Fixed in ${escapeHtml(it.fixedBy)}` : '',
    ].filter(Boolean).join(' · ');
    return `<article class="item tier-${escapeHtml(it.tier)}${it.read ? '' : ' unread'}" id="item-${escapeHtml(it.key)}" data-key="${escapeHtml(it.key)}">
  <div class="item-head">${tag(tagFor(it))}${link(it)}</div>
  ${it.summary ? `<p class="summary">${escapeHtml(it.summary)}</p>` : ''}
  <div class="meta"><span>${sources}</span><span>${escapeHtml(fmtDate(it.published))}</span>${extra ? `<span>${extra}</span>` : ''}${chips}
  ${it.read ? '' : `<button class="mark-read" data-action="mark-read" data-key="${escapeHtml(it.key)}">Mark read</button>`}</div>
</article>`;
  }

  function renderFeed(vm, filters) {
    const items = vm.snapshot.items.filter((it) => matchesFilters(it, filters));
    const expanded = (filters && filters.expanded) || [];
    return TIERS.map(([tier, heading]) => {
      const mine = items.filter((it) => it.tier === tier);
      const unread = mine.filter((it) => !it.read).length;
      const cap = TIER_CAP[tier];
      let shown = mine;
      if (cap && !expanded.includes(tier)) {
        // Collapsed view: the most important items from the last 30 days only.
        const cutoff = new Date(Date.now() - RECENT_DAYS * DAY).toISOString();
        const ranked = mine.filter((it) => (it.published || '') >= cutoff)
          .sort((a, b) => importance(a) - importance(b) || (b.published || '').localeCompare(a.published || ''));
        // Mix kinds: up to PER_KIND of each importance level first, then fill by rank.
        const perKind = {};
        const first = ranked.filter((it) => (perKind[importance(it)] = (perKind[importance(it)] || 0) + 1) <= PER_KIND);
        shown = [...first, ...ranked.filter((it) => !first.includes(it))].slice(0, cap);
      }
      const more = shown.length < mine.length
        ? `<button class="show-all" data-action="show-all" data-tier="${tier}">See more (${mine.length})</button>` : '';
      let body;
      if (!mine.length) body = '<p class="empty">Nothing here.</p>';
      else if (!shown.length) body = `<p class="empty">Nothing new in the last ${RECENT_DAYS} days.</p>${more}`;
      else body = shown.map(renderItem).join('\n') + more;
      return `<section class="tier tier-${tier}"><h2>${heading}<span class="count">${unread ? `${unread} unread` : ''}</span></h2>${body}</section>`;
    }).join('\n');
  }

  function renderFilters(vm, filters) {
    const sel = (filters && filters.products) || [];
    const chips = FILTERS.map((f) => `<button class="filter${sel.includes(f) ? ' on' : ''}" data-action="filter" data-filter="${f}">${escapeHtml(PRODUCT_LABELS[f])}</button>`).join('');
    const note = sel.includes('crowdstrike') ? `<p class="note">${escapeHtml(vm.configNote.crowdstrike)}</p>` : '';
    const group = activeGroup(filters);
    const banner = sel.length
      ? `<div class="banner"><span>Showing only ${escapeHtml(group ? TILES.find(([k]) => k === group)[1] : sel.map((f) => PRODUCT_LABELS[f]).join(', '))}</span><button data-action="clear-filters">Show everything</button></div>`
      : '';
    return `${banner}<div class="filters">${chips}</div>${note}`;
  }

  const sameSet = (a, b) => a.length === b.length && a.every((x) => b.includes(x));
  const activeGroup = (filters) => Object.keys(GROUP_FILTERS).find((g) => sameSet((filters && filters.products) || [], GROUP_FILTERS[g]));

  function renderTiles(vm, filters) {
    const active = activeGroup(filters);
    return TILES.map(([k, label]) => {
      const t = vm.tiles[k] || { unread: 0, color: 'green' };
      return `<button class="tile c-${escapeHtml(t.color)}${active === k ? ' on' : ''}" data-action="tile" data-group="${k}"><h4>${label}</h4><div class="big">${t.unread || '✓'}</div><span class="sub">${t.unread ? 'unread' : 'nothing new'}</span></button>`;
    }).join('');
  }

  function daysUntil(target, today) {
    const t = new Date(target);
    const a = new Date(t.getFullYear(), t.getMonth(), t.getDate());
    const b = new Date(today.getFullYear(), today.getMonth(), today.getDate());
    return Math.round((a - b) / DAY);
  }

  function renderPatchBar(vm, today) {
    // Computed from the viewer's calendar: a server's UTC date can be a day off locally.
    const ptDay = PatchCycle.nextPatchTuesday(today);
    const d = daysUntil(ptDay, today);
    const when = d <= 0 ? 'today' : d === 1 ? 'tomorrow' : `in ${d} days`;
    const pt = ptDay;
    const ptDate = `${pt.getFullYear()}-${String(pt.getMonth() + 1).padStart(2, '0')}-${String(pt.getDate()).padStart(2, '0')}`;
    const items = vm.snapshot.items;
    const maint = items.filter((i) => i.kind === 'maintenance').slice(0, 3);
    const vmware = items.filter((i) => i.products.includes('vmware')).slice(0, 3);
    const safe = vm.safe.map((s) => `<span class="safe s-${s.status}">${escapeHtml(PRODUCT_LABELS[s.version])}: ${s.status === 'caution' ? `Caution — ${s.openIssues} known issue${s.openIssues === 1 ? '' : 's'}` : 'Clean'}${s.resolved ? ` · ${s.resolved} fixed` : ''}</span>`).join('');
    const list = (title, arr) => `<div class="pc-col"><h4>${title}</h4>${arr.length ? arr.map((i) => `<div class="pc-row">${link(i)} <span class="date">${escapeHtml(fmtDate(i.published))}</span></div>`).join('') : '<div class="pc-row empty">None</div>'}</div>`;
    return `<div class="pc-head"><div class="pt"><span class="pt-label">Patch Tuesday</span><span class="pt-when">${when}</span><span class="date">${escapeHtml(ptDate)}</span></div><div class="safe-list"><h4>Safe to deploy?</h4>${safe}</div></div>
<div class="pc-cols">${list('Azure maintenance', maint)}${list('Recent VMware', vmware)}</div>`;
  }

  function renderAzure(vm) {
    // Only what touches the Azure Government tenant.
    const items = vm.snapshot.items.filter((i) => i.gov).slice(0, 150);
    if (!items.length) return '<p class="empty">No Azure Government items right now.</p>';
    return items.map((i) => `<div class="az-row">${i.kind === 'incident' ? tag(['INCIDENT', 'amber']) : ''}${i.kind === 'retirement' ? tag(['RETIRING', 'blue']) : ''}${link(i)} <span class="date">${escapeHtml(fmtDate(i.published))}</span></div>`).join('');
  }

  function renderSources(vm) {
    return vm.snapshot.sources.map((s) => {
      const bad = s.consecutiveFailures > 0;
      const status = bad ? `failed ${s.consecutiveFailures}× — ${escapeHtml(s.lastError || 'error')}` : `ok ${escapeHtml(s.lastOk ? new Date(s.lastOk).toLocaleString() : '')}`;
      return `<span class="src-health${bad ? ' bad' : ''}" title="${escapeHtml(s.lastError || '')}">${escapeHtml(s.label)}: ${status}</span>`;
    }).join('');
  }

  const api = { GROUP_FILTERS, escapeHtml, safeUrl, renderFeed, renderFilters, renderTiles, renderPatchBar, renderAzure, renderSources, FILTERS };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.RadarView = api;
})(typeof window !== 'undefined' ? window : globalThis);

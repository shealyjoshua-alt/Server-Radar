// Wires the pure renderers (view.js) to the preload bridge (window.radar).
(function () {
  const V = window.RadarView;
  const FILTER_KEY = 'radar.filters';
  let vm = null;
  let filters = { products: [] };
  try { filters = JSON.parse(localStorage.getItem(FILTER_KEY)) || filters; } catch { /* storage unavailable */ }

  const $ = (id) => document.getElementById(id);
  const saveFilters = () => { try { localStorage.setItem(FILTER_KEY, JSON.stringify({ products: filters.products })); } catch { /* ignore */ } };

  function render() {
    if (!vm) return;
    $('status-dot').className = `dot c-${vm.icon.color}`;
    $('status-dot').title = vm.icon.tooltip;
    $('updated').textContent = vm.snapshot.updatedAt ? `Updated ${new Date(vm.snapshot.updatedAt).toLocaleString()}` : 'Waiting for first refresh…';
    $('tiles').innerHTML = V.renderTiles(vm, filters);
    $('patchbar').innerHTML = V.renderPatchBar(vm, new Date()) + V.renderBulletin(vm, new Date());
    $('filters').innerHTML = V.renderFilters(vm, filters);
    $('feed').innerHTML = V.renderFeed(vm, filters);
    $('outages').innerHTML = V.renderGovOutages(vm, new Date());
    $('azure').innerHTML = V.renderAzure(vm);
    $('sources').innerHTML = V.renderSources(vm);
  }

  async function load() {
    vm = await window.radar.getViewModel();
    render();
  }

  function focusItem(key) {
    const el = document.getElementById(`item-${key}`);
    if (!el) return;
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.classList.add('focus');
    setTimeout(() => el.classList.remove('focus'), 4000);
  }

  document.addEventListener('click', async (e) => {
    const linkEl = e.target.closest('a[data-url]');
    if (linkEl) {
      e.preventDefault();
      if (linkEl.dataset.url !== '#') window.radar.openUrl(linkEl.dataset.url);
      return;
    }
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    if (action === 'mark-read') { vm = await window.radar.markRead(btn.dataset.key); render(); }
    if (action === 'mark-all-read') { vm = await window.radar.markAllRead(); render(); }
    if (action === 'refresh') {
      btn.disabled = true; btn.textContent = 'Refreshing…';
      try { vm = await window.radar.refresh(); render(); } finally { btn.disabled = false; btn.textContent = 'Refresh now'; }
    }
    if (action === 'tile') {
      const group = V.GROUP_FILTERS[btn.dataset.group];
      const same = group.length === filters.products.length && group.every((f) => filters.products.includes(f));
      filters = { products: same ? [] : [...group], expanded: [] };
      saveFilters();
      render();
      if (!same) $('feed-anchor').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    if (action === 'clear-filters') {
      filters = { products: [], expanded: [] };
      saveFilters();
      render();
    }
    if (action === 'show-all') {
      filters.expanded = [...(filters.expanded || []), btn.dataset.tier];
      render();
    }
    if (action === 'filter') {
      const f = btn.dataset.filter;
      filters.products = filters.products.includes(f) ? filters.products.filter((x) => x !== f) : [...filters.products, f];
      saveFilters();
      render();
    }
  });

  window.radar.onUpdate((next) => { vm = next; render(); });
  window.radar.onFocusItem((key) => { render(); focusItem(key); });
  load();
})();

// Phone/web stand-in for the Electron preload bridge: data comes from viewmodel.json
// (rebuilt hourly by the GitHub Action); "read" marks live in this browser's localStorage.
(function (root) {
  // Mirrors classify.AGENTS and status.js counting so the badge reflects this phone's read marks.
  const AGENTS = ['crowdstrike', 'carbonblack', 'nagios', 'splunkuf', 'chrome', 'firefox'];
  const GROUPS = {
    windows: (i) => i.products.some((p) => p.startsWith('ws')),
    vmware: (i) => i.products.includes('vmware'),
    azure: (i) => i.gov, // owner only cares about the Azure Government tenant
    agents: (i) => i.products.some((p) => AGENTS.includes(p)),
    dc: (i) => i.products.includes('dc'),
  };

  function applyReadState(vm, readKeys, greyAfter) {
    const items = vm.snapshot.items.map((i) => ({ ...i, read: readKeys.has(i.key) }));
    const unread = items.filter((i) => !i.read);
    const act = unread.filter((i) => i.tier === 'act').length;
    const watch = unread.filter((i) => i.tier === 'watch').length;
    const failing = vm.snapshot.sources.filter((s) => s.consecutiveFailures >= greyAfter);
    const color = act ? 'red' : failing.length ? 'grey' : watch ? 'amber' : 'green';
    const parts = [];
    if (act) parts.push(`${act} need action`);
    if (watch) parts.push(`${watch} to keep an eye on`);
    failing.forEach((s) => parts.push(`${s.label} not updating`));
    const tiles = {};
    for (const [name, inGroup] of Object.entries(GROUPS)) {
      const mine = unread.filter((i) => inGroup(i));
      tiles[name] = { unread: mine.length, color: mine.some((i) => i.tier === 'act') ? 'red' : mine.some((i) => i.tier === 'watch') ? 'amber' : 'green' };
    }
    return { ...vm, snapshot: { ...vm.snapshot, items }, icon: { color, count: act, tooltip: parts.join(' · ') || 'All clear' }, tiles };
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { applyReadState };
    return;
  }

  const KEY = 'radar.read';
  const load = () => { try { return new Set(JSON.parse(localStorage.getItem(KEY)) || []); } catch { return new Set(); } };
  const save = (s) => { try { localStorage.setItem(KEY, JSON.stringify([...s])); } catch { /* storage unavailable */ } };
  let raw = null;
  const fetchVm = async () => { raw = await (await fetch(`viewmodel.json?t=${Date.now()}`, { cache: 'no-store' })).json(); };
  const current = () => applyReadState(raw, load(), 3);

  root.radar = {
    getViewModel: async () => { await fetchVm(); return current(); },
    refresh: async () => { await fetchVm(); return current(); },
    markRead: async (key) => { const s = load(); s.add(key); save(s); return current(); },
    markAllRead: async () => { const s = load(); raw.snapshot.items.forEach((i) => s.add(i.key)); save(s); return current(); },
    openUrl: (url) => { window.open(url, '_blank', 'noopener'); },
    onUpdate: () => {},
    onFocusItem: () => {},
  };
})(typeof window !== 'undefined' ? window : globalThis);

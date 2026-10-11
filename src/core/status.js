const { AGENTS } = require('./classify');

const unread = (items, tier) => items.filter((i) => !i.read && i.tier === tier);

function iconState(snapshot, config) {
  const limit = config.greyAfterFailures || 3;
  const failing = snapshot.sources.filter((s) => s.consecutiveFailures >= limit);
  const act = unread(snapshot.items, 'act').length;
  const watch = unread(snapshot.items, 'watch').length;
  // Precedence red > grey > amber > green: a failing source never hides a red item.
  const color = act ? 'red' : failing.length ? 'grey' : watch ? 'amber' : 'green';
  const parts = [];
  if (act) parts.push(`${act} need action`);
  if (watch) parts.push(`${watch} to keep an eye on`);
  failing.forEach((s) => parts.push(`${s.label} not updating`));
  return { color, count: act, tooltip: parts.length ? parts.join(' · ') : 'All clear' };
}

const GROUPS = {
  windows: (i) => i.products.some((p) => p.startsWith('ws')),
  vmware: (i) => i.products.includes('vmware'),
  azure: (i) => i.gov, // owner only cares about the Azure Government tenant
  agents: (i) => i.products.some((p) => AGENTS.includes(p)),
  dc: (i) => i.products.includes('dc'),
};

function tileCounts(snapshot) {
  const out = {};
  for (const [name, inGroup] of Object.entries(GROUPS)) {
    const mine = snapshot.items.filter((i) => !i.read && inGroup(i));
    const color = mine.some((i) => i.tier === 'act') ? 'red' : mine.some((i) => i.tier === 'watch') ? 'amber' : 'green';
    out[name] = { unread: mine.length, color };
  }
  return out;
}

module.exports = { iconState, tileCounts };

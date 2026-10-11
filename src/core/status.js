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
  windows: (p) => p.startsWith('ws'),
  vmware: (p) => p === 'vmware',
  azure: (p) => p === 'azure',
  agents: (p) => AGENTS.includes(p),
};

function tileCounts(snapshot) {
  const out = {};
  for (const [name, test] of Object.entries(GROUPS)) {
    const mine = snapshot.items.filter((i) => !i.read && i.products.some(test));
    const color = mine.some((i) => i.tier === 'act') ? 'red' : mine.some((i) => i.tier === 'watch') ? 'amber' : 'green';
    out[name] = { unread: mine.length, color };
  }
  return out;
}

module.exports = { iconState, tileCounts };

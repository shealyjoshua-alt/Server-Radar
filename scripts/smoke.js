// Live smoke run: node scripts/smoke.js <state-file>
const { runRefresh } = require('../src/core/refresh');
const { createStore } = require('../src/core/store');
const { loadConfig } = require('../src/core/match');
const { httpGet } = require('../src/sources/http');
const config = loadConfig();
const store = createStore(process.argv[2], config);
const t = Date.now();
runRefresh({ sources: require('../src/sources'), store, config, httpGet }).then((r) => {
  const snap = store.snapshot();
  const tiers = {};
  snap.items.forEach((i) => { tiers[i.tier] = (tiers[i.tier] || 0) + 1; });
  console.log('new', r.newItems.length, 'notify', r.toNotify.length, 'secs', Math.round((Date.now() - t) / 1000), tiers);
  snap.sources.forEach((s) => console.log(s.consecutiveFailures ? 'FAIL' : 'ok  ', s.id, s.lastCount, s.lastError || ''));
});

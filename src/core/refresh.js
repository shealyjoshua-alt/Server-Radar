const { shouldNotify } = require('./classify');

const defaultSleep = (ms) => new Promise((r) => setTimeout(r, ms));

function requestsOf(source) {
  const list = source.requests || source.urls.map((url) => ({ url }));
  return list.map((r) => ({ ...r, headers: { ...(source.headers || {}), ...(r.headers || {}) } }));
}

async function fetchSource(source, httpGet, sleep) {
  const bodies = [];
  const reqs = requestsOf(source);
  for (let i = 0; i < reqs.length; i++) {
    if (i > 0 && source.minIntervalMs) await sleep(source.minIntervalMs);
    const { url, ...opts } = reqs[i];
    try {
      bodies.push(await httpGet(url, opts));
    } catch (e) {
      if (source.allow404 && e.status === 404) bodies.push(null);
      else throw e;
    }
  }
  return bodies;
}

async function runRefresh({ sources, store, config, httpGet, now = () => new Date(), sleep = defaultSleep }) {
  const results = await Promise.allSettled(sources.map(async (source) => {
    const bodies = await fetchSource(source, httpGet, sleep);
    return source.parse(bodies, config);
  }));

  const all = [];
  const okSources = [];
  results.forEach((r, i) => {
    const s = sources[i];
    const at = now().toISOString();
    if (r.status === 'fulfilled') {
      all.push(...r.value.map((it) => ({ ...it, via: s.id })));
      okSources.push(s.id);
      store.recordSource(s.id, s.label, { ok: true, count: r.value.length }, at);
    } else {
      store.recordSource(s.id, s.label, { ok: false, error: String((r.reason && r.reason.message) || r.reason) }, at);
    }
  });

  const newItems = store.merge(all);
  // A source's first successful fetch is its backlog: absorb it silently, even if
  // the app's first launch was offline and this happens days later.
  const silent = newItems.filter((it) => !store.isSourceSynced(it.via));
  store.absorbSilently(silent);
  const notifiedKeys = store.notifiedKeys();
  const toNotify = newItems.filter((it) => !silent.includes(it)
    && shouldNotify(it, { firstSync: false, notifiedKeys }, config));
  toNotify.forEach((it) => store.markNotified(it.key));
  okSources.forEach((id) => store.markSourceSynced(id));
  store.save();
  return { newItems, toNotify };
}

module.exports = { runRefresh };

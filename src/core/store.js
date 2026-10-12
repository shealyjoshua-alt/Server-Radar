const fs = require('node:fs');
const path = require('node:path');
const { tierFor, notifyKey } = require('./classify');

const PRUNE_DAYS = 180;
const STATUS_RANK = { open: 1, resolved: 2 };

function emptyState() {
  return { version: 1, synced: false, syncedSources: [], meta: {}, items: {}, seen: [], notified: [], sources: {}, updatedAt: null };
}

function load(file) {
  if (!fs.existsSync(file)) return emptyState();
  try {
    const s = JSON.parse(fs.readFileSync(file, 'utf8'));
    return { ...emptyState(), ...s };
  } catch {
    fs.renameSync(file, `${file}.corrupt-${Date.now()}`);
    return emptyState();
  }
}

const earliest = (a, b) => (!a ? b : !b ? a : a < b ? a : b);
const union = (a, b) => [...new Set([...(a || []), ...(b || [])])].sort();

function mergeInto(existing, item) {
  existing.products = union(existing.products, item.products);
  existing.cves = union(existing.cves, item.cves);
  existing.sources = union(existing.sources, [item.source]);
  if (item.exploited && !existing.exploited) existing.exploitedAt = item.exploitedAt || item.published || new Date().toISOString();
  existing.exploited = existing.exploited || item.exploited;
  if (item.cvss !== null && (existing.cvss === null || item.cvss > existing.cvss)) existing.cvss = item.cvss;
  if ((STATUS_RANK[item.status] || 0) > (STATUS_RANK[existing.status] || 0)) {
    existing.status = item.status;
    existing.fixedBy = item.fixedBy || existing.fixedBy;
  }
  existing.severity = existing.severity || item.severity;
  existing.patchMonth = existing.patchMonth || item.patchMonth;
  existing.gov = existing.gov || item.gov;
  existing.published = earliest(existing.published, item.published);
}

function createStore(file, config) {
  const state = load(file);
  const seen = new Set(state.seen);
  const notified = new Set(state.notified);
  const syncedSources = new Set(state.syncedSources);

  const retier = (it) => { it.tier = tierFor(it, config); };

  return {
    isFirstSync: () => !state.synced,

    // Returns items that are new, or that just became Act now / exploited (e.g. KEV
    // listing a CVE MSRC published earlier). Each returned item's `via` names the
    // source module that caused it, so refresh can stay silent for unsynced sources.
    merge(items) {
      const changed = new Map();
      for (const item of items) {
        const key = notifyKey(item);
        const via = item.via || item.source;
        const existing = state.items[key];
        if (existing) {
          const wasAct = existing.tier === 'act';
          const wasExploited = existing.exploited;
          mergeInto(existing, item);
          retier(existing);
          if ((!wasAct && existing.tier === 'act') || (!wasExploited && existing.exploited && existing.tier === 'act')) {
            existing.read = false;
            existing.via = via;
            changed.set(key, existing);
          }
        } else if (!seen.has(key) || (tierFor(item, config) === 'act' && !notified.has(key))) {
          // A pruned key is re-admitted only if it now needs action.
          const { via: _v, ...rest } = item;
          const stored = { ...rest, key, sources: [item.source], read: false, via };
          if (stored.exploited) stored.exploitedAt = item.exploitedAt || item.published || new Date().toISOString();
          retier(stored);
          state.items[key] = stored;
          seen.add(key);
          changed.set(key, stored);
        }
      }
      return [...changed.values()];
    },

    // Stored items (live objects) matching a predicate, for enrichment steps.
    itemsWhere: (fn) => Object.values(state.items).filter(fn),
    setFields(key, fields) {
      const it = state.items[key];
      if (!it) return;
      Object.assign(it, fields);
      retier(it);
    },

    setMeta(id, value) { state.meta = { ...(state.meta || {}), [id]: value }; },

    isSourceSynced: (id) => syncedSources.has(id),
    markSourceSynced(id) { syncedSources.add(id); state.synced = true; },
    // First successful fetch of a source: show its backlog as read and never notify for it.
    absorbSilently(items) {
      for (const it of items) {
        it.read = true;
        if (it.exploited) notified.add(it.key);
      }
    },

    markRead(key) { if (state.items[key]) state.items[key].read = true; },
    markAllRead() { for (const it of Object.values(state.items)) it.read = true; },
    markNotified(key) { notified.add(key); },
    notifiedKeys: () => new Set(notified),

    recordSource(id, label, result, at) {
      const prev = state.sources[id] || { id, label, lastOk: null, lastError: null, lastCount: 0, consecutiveFailures: 0 };
      const next = { ...prev, label };
      if (result.ok) {
        next.lastOk = at;
        next.lastCount = result.count;
        next.lastError = null;
        next.consecutiveFailures = 0;
      } else {
        next.lastError = result.error;
        next.lastErrorAt = at;
        next.consecutiveFailures = prev.consecutiveFailures + 1;
      }
      state.sources[id] = next;
    },

    completeSync() {
      if (state.synced) return;
      Object.values(state.sources).forEach((s) => syncedSources.add(s.id));
      for (const it of Object.values(state.items)) {
        it.read = true;
        if (it.exploited) notified.add(it.key);
      }
      state.synced = true;
    },

    snapshot() {
      // Tiers depend on age (exploited window), so recompute on every read.
      Object.values(state.items).forEach(retier);
      const items = Object.values(state.items)
        .filter((i) => i.tier !== null)
        .sort((a, b) => (b.published || '').localeCompare(a.published || ''));
      return {
        items: items.map((i) => ({ ...i })),
        sources: Object.values(state.sources).map((s) => ({ ...s })),
        firstSync: !state.synced,
        updatedAt: state.updatedAt,
        meta: { ...(state.meta || {}) },
      };
    },

    save() {
      const cutoff = new Date(Date.now() - PRUNE_DAYS * 86400000).toISOString();
      for (const [key, it] of Object.entries(state.items)) {
        // Act-now items are never pruned: dropping them would let a still-listed old
        // critical return as unread, and they are few.
        const keep = it.tier === 'act';
        if (!keep && it.published && it.published < cutoff) delete state.items[key];
      }
      state.seen = [...seen];
      state.notified = [...notified];
      state.syncedSources = [...syncedSources];
      state.updatedAt = new Date().toISOString();
      fs.mkdirSync(path.dirname(file), { recursive: true });
      const tmp = `${file}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(state));
      fs.renameSync(tmp, file);
    },
  };
}

module.exports = { createStore };

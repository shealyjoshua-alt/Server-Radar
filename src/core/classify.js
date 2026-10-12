const AGENTS = ['crowdstrike', 'carbonblack', 'nagios', 'splunkuf', 'chrome', 'firefox'];

const hasAny = (list, ids) => list.some((p) => ids.includes(p));
const isServerOrVmware = (p) => p.startsWith('ws') || p === 'vmware';

function mentionsInterest(item, config) {
  const text = `${item.title} ${item.summary}`.toLowerCase();
  return (config.interestKeywords || []).some((k) => text.includes(k.toLowerCase()));
}

const EXPLOITED_WINDOW_DAYS = 90;
const isServer = (p) => p.startsWith('ws');

function recentlyExploited(item) {
  const when = Date.parse(item.exploitedAt || item.published || '');
  return Number.isNaN(when) || Date.now() - when <= EXPLOITED_WINDOW_DAYS * 86400000;
}

// Rules are ordered; first match wins (spec "How items are sorted", as quieted by the
// owner on 2026-10-10: Act now = exploited in the last 90 days; CVSS 9+ alone is amber;
// Azure-cloud-only CVEs go to the Azure section; routine Important Windows CVEs dropped).
// Owner rule (2026-10-11): only Critical or High vulnerabilities are shown. Scored items
// need CVSS 7.0+; unscored ones need a vendor Critical/High rating (CISA KEV entries
// carry 'critical' because they are actively exploited).
function highEnough(item) {
  if (item.cvss !== null) return item.cvss >= 7.0;
  return item.exploited || item.severity === 'critical' || item.severity === 'important';
}

const AZURE_FEEDS = ['azure-updates', 'azure-status'];
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const wordIn = (text, word, flags) => new RegExp(`(?<![A-Za-z0-9])${escapeRe(word)}(?![A-Za-z0-9])`, flags).test(text);

// Owner only cares about the USA: an Azure item that names only non-US regions is dropped.
// "US" is matched case-sensitively so the word "us" in a sentence doesn't count.
function foreignOnlyAzure(item, config) {
  if (!AZURE_FEEDS.includes(item.source)) return false;
  const text = `${item.title} ${item.summary}`;
  const foreign = (config.foreignRegionMarkers || []).some((w) => wordIn(text, w, 'i'));
  if (!foreign) return false;
  const us = item.gov || (config.usRegionMarkers || []).some((w) => wordIn(text, w, w === 'US' || w === 'USA' ? '' : 'i'));
  return !us;
}

function tierFor(item, config) {
  if (foreignOnlyAzure(item, config)) return null;
  if (item.kind === 'vuln' && !highEnough(item)) return null;
  // Owner has applied Windows patches through config.patchedThrough ('YYYY-MM');
  // cumulative updates include every earlier fix.
  if (item.kind === 'vuln' && item.patchMonth && config.patchedThrough && item.patchMonth <= config.patchedThrough
      && item.products.some(isServer)) return null;
  const inScope = item.products.length > 0;
  const azureOnly = inScope && item.products.every((p) => p === 'azure');
  if (inScope && item.exploited) return recentlyExploited(item) ? 'act' : null;
  if (item.kind === 'vuln' && azureOnly) return 'azure';
  if (inScope && item.kind === 'vuln' && item.cvss !== null && item.cvss >= 9.0) return 'watch';
  if (item.kind === 'incident') return item.gov ? 'watch' : 'azure';
  if (item.kind === 'maintenance' || item.kind === 'retirement') return 'watch';
  if (item.kind === 'known-issue' && inScope) return 'watch';
  if (item.kind === 'vuln' && inScope && item.severity === 'critical') return 'watch';
  if (item.kind === 'vuln' && inScope && item.severity === 'important' && !item.products.every(isServer)) return 'watch';
  if (hasAny(item.products, AGENTS) && item.products.some(isServerOrVmware)) return 'watch';
  if ((item.kind === 'update' || item.kind === 'release') && mentionsInterest(item, config)) return 'interest';
  if (item.kind === 'release' && inScope) return 'interest';
  if (item.source === 'azure-updates') return 'azure';
  return null;
}

function notifyKey(item) {
  if (item.key) return item.key;
  return item.cves && item.cves.length ? item.cves[0] : item.id;
}

function shouldNotify(item, ctx, config) {
  return !ctx.firstSync
    && item.exploited
    && tierFor(item, config) === 'act'
    && !ctx.notifiedKeys.has(notifyKey(item));
}

module.exports = { tierFor, notifyKey, shouldNotify, AGENTS };

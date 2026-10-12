// Microsoft Security Update Guide, via the MSRC CVRF v3 API (one document per month).
const { makeItem, ParseError } = require('../core/item');
const { matchProducts } = require('../core/match');
const { monthFromRelease } = require('./msrcLookup');

const BASE = 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/';
const BROWSERS = ['chrome', 'firefox'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function msrcUrls(now) {
  const cur = new Date(now.getFullYear(), now.getMonth(), 1);
  const prev = new Date(now.getFullYear(), now.getMonth() - 1, 1);
  return [cur, prev].map((d) => `${BASE}${d.getFullYear()}-${MONTHS[d.getMonth()]}`);
}

const threatText = (v, type) => (v.Threats || [])
  .filter((t) => t.Type === type)
  .map((t) => (t.Description && t.Description.Value) || '');

function parseDoc(doc, config) {
  const release = doc.DocumentTracking && doc.DocumentTracking.Identification && doc.DocumentTracking.Identification.ID
    && doc.DocumentTracking.Identification.ID.Value;
  const patchMonth = monthFromRelease(release);
  const names = new Map(((doc.ProductTree && doc.ProductTree.FullProductName) || []).map((p) => [p.ProductID, p.Value]));
  const released = (doc.DocumentTracking && doc.DocumentTracking.CurrentReleaseDate) || '';
  return doc.Vulnerability.map((v) => {
    const productNames = (v.ProductStatuses || []).flatMap((s) => s.ProductID || []).map((id) => names.get(id) || '');
    const scores = (v.CVSSScoreSets || []).map((s) => s.BaseScore).filter((n) => typeof n === 'number');
    const severity = threatText(v, 3).find(Boolean);
    return makeItem({
      id: `msrc:${v.CVE}`,
      source: 'msrc',
      kind: 'vuln',
      title: (v.Title && v.Title.Value) || v.CVE,
      cves: [v.CVE],
      cvss: scores.length ? Math.max(...scores) : null,
      severity: severity ? severity.toLowerCase() : null,
      exploited: threatText(v, 1).some((d) => d.includes('Exploited:Yes')),
      // Microsoft re-publishes Chrome CVEs for Edge; those are Edge items, not Chrome/Firefox.
      products: matchProducts(`${[...new Set(productNames)].join(' | ')} | ${(v.Title && v.Title.Value) || ''}`, config).filter((p) => !BROWSERS.includes(p)),
      published: released,
      url: `https://msrc.microsoft.com/update-guide/vulnerability/${v.CVE}`,
      patchMonth,
    });
  });
}

const MONTH_NAMES = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
const SERVER_VERSIONS = ['ws2016', 'ws2019', 'ws2022', 'ws2025'];
const TOP_LIMIT = 6;

// Human label for one Vendor Fix: the OS cumulative update, a hotpatch, a .NET Framework
// cumulative update, or a component such as a Microsoft Store extension.
function patchLabel(productName, subType, url) {
  const family = productName.replace(/\s*\(Server Core installation\)/, '').replace(/ on Windows Server 20\d\d.*$/, '');
  if (/^Windows Server 20\d\d/.test(family)) {
    if (/hotpatch/i.test(subType || '')) return 'Hotpatch update';
    if (/servicing stack/i.test(subType || '')) return 'Servicing stack update';
    if (/monthly rollup/i.test(subType || '')) return 'Monthly rollup';
    if (/security only/i.test(subType || '')) return 'Security-only update';
    return 'Monthly cumulative update';
  }
  const net = /^Microsoft \.NET Framework (.+)$/.exec(family);
  if (net) return `.NET Framework ${net[1].replace(/ AND /g, ' and ')} cumulative update`;
  if (/apps\.microsoft\.com/.test(url || '')) return `${family} (Microsoft Store)`;
  return `${family} update`;
}

// One Patch Tuesday release, seen from Windows Server: the cumulative update KB per
// version (the most common Vendor Fix), counts, and the top Critical/High CVEs.
function summarizeDoc(doc, config) {
  const release = doc.DocumentTracking && doc.DocumentTracking.Identification && doc.DocumentTracking.Identification.ID
    && doc.DocumentTracking.Identification.ID.Value;
  const month = monthFromRelease(release);
  if (!month) return null;
  const products = (doc.ProductTree && doc.ProductTree.FullProductName) || [];
  const nameOf = new Map(products.map((p) => [p.ProductID, p.Value]));
  const versionOf = new Map(products.map((p) => [p.ProductID, matchProducts(p.Value, config).find((x) => SERVER_VERSIONS.includes(x))]));
  const kbCounts = Object.fromEntries(SERVER_VERSIONS.map((v) => [v, new Map()]));
  // version -> patch key -> { kb, label, cves:Set, url }
  const patchMaps = Object.fromEntries(SERVER_VERSIONS.map((v) => [v, new Map()]));
  const server = [];
  for (const v of doc.Vulnerability) {
    const versions = new Set((v.ProductStatuses || []).flatMap((s) => s.ProductID || []).map((id) => versionOf.get(id)).filter(Boolean));
    if (!versions.size) continue;
    for (const r of v.Remediations || []) {
      if (r.Type !== 2 || !r.Description) continue;
      const numeric = /^\d{6,8}$/.test(r.Description.Value);
      for (const id of r.ProductID || []) {
        const ver = versionOf.get(id);
        if (!ver) continue;
        if (numeric) kbCounts[ver].set(r.Description.Value, (kbCounts[ver].get(r.Description.Value) || 0) + 1);
        const label = patchLabel(nameOf.get(id) || '', r.SubType, r.URL);
        const key = numeric ? r.Description.Value : label;
        const entry = patchMaps[ver].get(key) || { kb: numeric ? `KB${r.Description.Value}` : null, label, cves: new Set(), url: r.URL || null };
        entry.cves.add(v.CVE);
        patchMaps[ver].set(key, entry);
      }
    }
    const t1 = threatText(v, 1).join(';');
    const scores = (v.CVSSScoreSets || []).map((s) => s.BaseScore).filter((n) => typeof n === 'number');
    const severity = (threatText(v, 3).find(Boolean) || '').toLowerCase() || null;
    server.push({
      cve: v.CVE,
      title: (v.Title && v.Title.Value) || v.CVE,
      cvss: scores.length ? Math.max(...scores) : null,
      severity,
      exploited: t1.includes('Exploited:Yes'),
      disclosed: t1.includes('Publicly Disclosed:Yes'),
      url: `https://msrc.microsoft.com/update-guide/vulnerability/${v.CVE}`,
    });
  }
  if (!server.length) return null;
  const kbs = {};
  for (const ver of SERVER_VERSIONS) {
    const best = [...kbCounts[ver].entries()].sort((a, b) => b[1] - a[1])[0];
    if (best) kbs[ver] = `KB${best[0]}`;
  }
  const patches = {};
  for (const ver of SERVER_VERSIONS) {
    const rows = [...patchMaps[ver].values()].map((e) => ({ kb: e.kb, label: e.label, cves: e.cves.size, url: e.url }));
    if (rows.length) patches[ver] = rows.sort((a, b) => b.cves - a.cves); // stable: ties keep publish order
  }
  const high = (c) => (c.cvss !== null ? c.cvss >= 7 : c.exploited || c.severity === 'critical' || c.severity === 'important');
  const top = server.filter(high).sort((a, b) => (b.exploited - a.exploited) || (b.disclosed - a.disclosed)
    || ((b.severity === 'critical') - (a.severity === 'critical')) || ((b.cvss || 0) - (a.cvss || 0))).slice(0, TOP_LIMIT);
  const [y, m] = month.split('-');
  return {
    month,
    label: `${MONTH_NAMES[Number(m) - 1]} ${y}`,
    url: `https://msrc.microsoft.com/update-guide/releaseNote/${release}`,
    serverCves: server.length,
    critical: server.filter((c) => c.severity === 'critical').length,
    exploited: server.filter((c) => c.exploited).length,
    disclosed: server.filter((c) => c.disclosed).length,
    kbs,
    patches,
    top,
  };
}

module.exports = {
  id: 'msrc',
  label: 'Microsoft Security Update Guide',
  allow404: true,
  headers: { Accept: 'application/json' },
  msrcUrls,
  get urls() { return msrcUrls(new Date()); },
  summarize(bodies, config) {
    const docs = bodies.filter((b) => b !== null).map((b) => JSON.parse(b)).filter((d) => Array.isArray(d.Vulnerability));
    const months = docs.map((d) => summarizeDoc(d, config)).filter(Boolean).sort((a, b) => b.month.localeCompare(a.month));
    return { months };
  },
  parse(bodies, config) {
    const docs = [];
    for (const body of bodies) {
      if (body === null) continue;
      let doc;
      try { doc = JSON.parse(body); } catch { throw new ParseError('MSRC: body is not JSON'); }
      if (Array.isArray(doc.Vulnerability)) docs.push(doc);
    }
    if (docs.length === 0 || docs.every((d) => d.Vulnerability.length === 0)) throw new ParseError('MSRC: no CVRF document with vulnerabilities');
    return docs.flatMap((d) => parseDoc(d, config));
  },
};

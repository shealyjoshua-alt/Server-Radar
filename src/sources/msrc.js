// Microsoft Security Update Guide, via the MSRC CVRF v3 API (one document per month).
const { makeItem, ParseError } = require('../core/item');
const { matchProducts } = require('../core/match');

const BASE = 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/';
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
      products: matchProducts([...new Set(productNames)].join(' | '), config),
      published: released,
      url: `https://msrc.microsoft.com/update-guide/vulnerability/${v.CVE}`,
    });
  });
}

module.exports = {
  id: 'msrc',
  label: 'Microsoft Security Update Guide',
  allow404: true,
  headers: { Accept: 'application/json' },
  msrcUrls,
  get urls() { return msrcUrls(new Date()); },
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

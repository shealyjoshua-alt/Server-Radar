// NVD CVE API 2.0 keyword searches for agents without a usable vendor feed (CrowdStrike etc.).
const { makeItem, ParseError } = require('../core/item');
const { matchProducts } = require('../core/match');

const KEYWORDS = ['CrowdStrike Falcon', 'Carbon Black', 'NSClient++', 'Nagios Cross-Platform Agent', 'Splunk Universal Forwarder', 'FileMaker'];
const DAY = 86400000;
const SEVERITY = { CRITICAL: 'critical', HIGH: 'important', MEDIUM: 'moderate', LOW: 'low' };

function nvdUrls(now) {
  const end = now.toISOString();
  const start = new Date(now.getTime() - 30 * DAY).toISOString();
  return KEYWORDS.map((k) => `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(k)}&pubStartDate=${start}&pubEndDate=${end}`);
}

function bestMetric(metrics = {}) {
  for (const key of ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30']) {
    const m = metrics[key] && metrics[key][0] && metrics[key][0].cvssData;
    if (m) return m;
  }
  return null;
}

module.exports = {
  id: 'nvd',
  label: 'NVD (agent and FileMaker CVEs)',
  minIntervalMs: 6500, // keyless NVD clients: 5 requests per 30 s
  nvdUrls,
  get urls() { return nvdUrls(new Date()); },
  parse(bodies, config) {
    const seen = new Set();
    return bodies.flatMap((body) => {
      let d;
      try { d = JSON.parse(body); } catch { throw new ParseError('NVD: body is not JSON'); }
      if (!d || !Array.isArray(d.vulnerabilities)) throw new ParseError('NVD: no vulnerabilities array');
      return d.vulnerabilities.map(({ cve }) => {
        if (seen.has(cve.id)) return null;
        seen.add(cve.id);
        const desc = ((cve.descriptions || []).find((x) => x.lang === 'en') || {}).value || '';
        const m = bestMetric(cve.metrics);
        return makeItem({
          id: `nvd:${cve.id}`,
          source: 'nvd',
          kind: 'vuln',
          title: `${cve.id}: ${desc.slice(0, 120)}`,
          summary: desc.slice(0, 400),
          cves: [cve.id],
          cvss: m ? m.baseScore : null,
          severity: m ? SEVERITY[String(m.baseSeverity).toUpperCase()] || null : null,
          products: matchProducts(desc, config),
          published: cve.published ? `${cve.published.replace(/Z$/, '')}Z` : '',
          url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
        });
      }).filter(Boolean);
    });
  },
};

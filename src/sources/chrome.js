// Chrome Releases blog, "Stable updates" Atom feed. One item per desktop stable release,
// summarising its security fixes; Google's "exploit ... exists in the wild" note marks it exploited.
const { XMLParser } = require('fast-xml-parser');
const { makeItem, ParseError } = require('../core/item');
const { stripHtml } = require('./rss');

const parser = new XMLParser({ ignoreAttributes: false, trimValues: true });
const text = (v) => (v && typeof v === 'object' ? v['#text'] || '' : v || '').toString();
const list = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

function toItem(entry) {
  const title = text(entry.title);
  if (!/for Desktop/i.test(title)) return null;
  const body = stripHtml(text(entry.content));
  const version = (body.match(/updated to (\d+(?:\.\d+)+)/i) || [])[1];
  if (!version) return null;
  const fixes = [...body.matchAll(/\]\s*(Critical|High|Medium|Low)\s+(CVE-\d{4}-\d+)/g)].map((m) => ({ sev: m[1].toLowerCase(), cve: m[2] }));
  const wild = [...body.matchAll(/exploit for (CVE-\d{4}-\d+) exists in the wild/gi)].map((m) => m[1]);
  const critical = fixes.filter((f) => f.sev === 'critical').length;
  const high = fixes.filter((f) => f.sev === 'high').length;
  const cves = [...new Set([...wild, ...fixes.map((f) => f.cve)])];
  const link = list(entry.link).find((l) => l['@_rel'] === 'alternate');
  return makeItem({
    id: `chrome:${version}`,
    source: 'chrome',
    kind: 'vuln',
    // Google's "Desktop" channel is the Windows build that Windows Server runs.
    title: `Chrome ${version} for Windows: ${fixes.length} security fixes (${critical} critical, ${high} high)`,
    summary: wild.length ? `Google reports an exploit in the wild for ${wild.join(', ')}.` : '',
    cves,
    exploited: wild.length > 0,
    severity: critical ? 'critical' : high ? 'important' : null,
    products: ['chrome'],
    published: entry.published ? new Date(text(entry.published)).toISOString() : '',
    url: link ? link['@_href'] : 'https://chromereleases.googleblog.com/',
  });
}

module.exports = {
  id: 'chrome',
  label: 'Chrome Releases',
  urls: ['https://chromereleases.googleblog.com/feeds/posts/default/-/Stable%20updates?max-results=25'],
  parse([body]) {
    let doc;
    try { doc = parser.parse(body || ''); } catch (e) { throw new ParseError(`Chrome: invalid XML (${e.message})`); }
    const entries = list(doc && doc.feed && doc.feed.entry);
    if (!entries.length) throw new ParseError('Chrome: feed has no entries');
    return entries.map(toItem).filter(Boolean);
  },
};

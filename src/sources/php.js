// php.net news (Atom). Security advisories become PHP items; routine security releases are
// grouped into one item per day. summarize() keeps the latest advisory for the PHP spotlight.
const { XMLParser } = require('fast-xml-parser');
const { makeItem, ParseError } = require('../core/item');

const MAX_ENTRIES = 60;
// php.net posts are inline XHTML; keep <content> as raw markup for blocks().
const parser = new XMLParser({ ignoreAttributes: false, trimValues: true, stopNodes: ['*.content'] });
const text = (v) => (v && typeof v === 'object' ? v['#text'] || '' : v || '').toString();
const list = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
const decode = (s) => s.replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'");

// Content HTML -> readable blocks (paragraphs / list items).
function blocks(html) {
  return decode(html).split(/<\/?(?:p|li|h\d|div|br)\b[^>]*>/i)
    .map((b) => b.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim()).filter(Boolean);
}

function entries(body) {
  let doc;
  try { doc = parser.parse(body || ''); } catch (e) { throw new ParseError(`PHP: invalid XML (${e.message})`); }
  const list_ = list(doc && doc.feed && doc.feed.entry);
  if (!list_.length) throw new ParseError('PHP: feed has no entries');
  return list_.slice(0, MAX_ENTRIES).map((e) => {
    const links = list(e.link).map((l) => l['@_href']).filter(Boolean);
    return {
      title: text(e.title).trim(),
      date: text(e.published || e.updated).slice(0, 10),
      published: new Date(text(e.published || e.updated)).toISOString(),
      url: (links.find((l) => /archive/.test(l)) || links[0] || 'https://www.php.net/').replace(/^http:/, 'https:'),
      blocks: blocks(text(e.content || e.summary)),
    };
  });
}

const isAdvisory = (e) => /^Security advisory/i.test(e.title);
const cvesIn = (e) => [...new Set(e.blocks.join(' ').match(/CVE-\d{4}-\d{4,}/g) || [])];

function advisorySummary(e) {
  const first = e.blocks[0] || '';
  const fixedMatch = /PHP ((?:\d+\.\d+\.\d+(?:,\s*|\s+and\s+)?)+)\s+fix/i.exec(first);
  const fixed = fixedMatch ? fixedMatch[1].match(/\d+\.\d+\.\d+/g) : [];
  const start = e.blocks.findIndex((b) => /If you cannot update/i.test(b));
  const mitigations = start < 0 ? [] : e.blocks.slice(start + 1)
    .filter((b) => /^(Set|Use|Consider|On PHP|Disable|Keep)\b/.test(b)).slice(0, 6).map((b) => b.slice(0, 240));
  return {
    date: e.date,
    title: e.title,
    cves: cvesIn(e),
    fixed,
    risk: (e.blocks.find((b) => /^Who is at risk/i.test(b)) || '').slice(0, 400),
    mitigations,
    url: e.url,
  };
}

module.exports = {
  id: 'php',
  label: 'php.net security news',
  urls: ['https://www.php.net/feed.atom'],
  parse([body]) {
    const all = entries(body);
    const items = all.filter(isAdvisory).map((e) => makeItem({
      id: `php:advisory:${e.date}`,
      source: 'php',
      kind: 'vuln',
      title: e.title,
      summary: (e.blocks[0] || '').slice(0, 400),
      cves: cvesIn(e),
      severity: /critical/i.test(e.title + e.blocks.join(' ')) ? 'critical' : 'important',
      products: ['php'],
      published: e.published,
      url: e.url,
    }));
    // Routine security releases: "PHP x.y.z Released!" posts that say "security release".
    const byDay = new Map();
    for (const e of all) {
      const m = /^PHP (\d+\.\d+\.\d+) Released/i.exec(e.title);
      if (!m || !/security release/i.test(e.blocks.join(' '))) continue;
      const day = byDay.get(e.date) || { versions: [], e };
      day.versions.push(m[1]);
      byDay.set(e.date, day);
    }
    for (const [date, { versions, e }] of byDay) {
      items.push(makeItem({
        id: `php:releases:${date}`,
        source: 'php',
        kind: 'release',
        title: `PHP security releases: ${versions.join(', ')}`,
        products: ['php'],
        published: e.published,
        url: e.url,
      }));
    }
    return items;
  },
  summarize([body]) {
    const adv = entries(body).find(isAdvisory);
    return { advisory: adv ? advisorySummary(adv) : null };
  },
};

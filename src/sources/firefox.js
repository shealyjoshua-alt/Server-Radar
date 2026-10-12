// Mozilla Foundation Security Advisories index (one entry per release, with Mozilla's impact rating).
// Structure: <h2>Month D, YYYY</h2><ul><li><a href="/…/mfsaYYYY-N/"><span class="level high">MFSA …</span> Title</a></li></ul>
const cheerio = require('cheerio/slim');
const { makeItem, ParseError } = require('../core/item');
const { matchProducts } = require('../core/match');

const BASE = 'https://www.mozilla.org';
const WINDOW_DAYS = 60;
const IMPACT = { critical: 'critical', high: 'important', moderate: 'moderate', low: 'low' };

function isoDay(s) {
  const t = Date.parse(`${s} UTC`);
  return Number.isNaN(t) ? '' : new Date(t).toISOString().slice(0, 10);
}

module.exports = {
  id: 'firefox',
  label: 'Mozilla security advisories',
  urls: [`${BASE}/en-US/security/advisories/`],
  parse([html], config) {
    const $ = cheerio.load(html || '');
    const items = [];
    $('h2').each((_, h2) => {
      const day = isoDay($(h2).text().trim());
      if (!day) return;
      $(h2).next('ul').find('li a[href*="mfsa"]').each((__, a) => {
        const href = $(a).attr('href');
        const m = /mfsa(\d{4})-(\d+)/.exec(href);
        if (!m) return;
        const level = ($(a).find('span.level').attr('class') || '').split(/\s+/).find((c) => IMPACT[c]);
        const title = $(a).clone().children('span').remove().end().text().replace(/\s+/g, ' ').trim();
        items.push(makeItem({
          id: `mfsa:${m[1]}-${m[2]}`,
          source: 'firefox',
          kind: 'vuln',
          title,
          severity: IMPACT[level] || null,
          products: matchProducts(title, config).filter((p) => p === 'firefox'),
          published: day,
          url: new URL(href, BASE).href,
        }));
      });
    });
    if (!items.length) throw new ParseError('Firefox: no advisories found (page format changed?)');
    // Recent releases only, anchored on the newest advisory so old branches drop off.
    const newest = items.map((i) => i.published).sort().pop();
    const cutoff = new Date(Date.parse(newest) - WINDOW_DAYS * 86400000).toISOString().slice(0, 10);
    return items.filter((i) => i.published >= cutoff);
  },
};

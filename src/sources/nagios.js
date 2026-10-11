// Nagios security disclosures for NCPA (WordPress REST API behind nagios.com/security-disclosures/ncpa/).
const { makeItem, ParseError } = require('../core/item');
const { matchProducts } = require('../core/match');
const { stripHtml } = require('./rss');

module.exports = {
  id: 'nagios',
  label: 'Nagios NCPA disclosures',
  urls: ['https://www.nagios.com/wp-json/wp/v2/security-disclosure?sd-product=625&per_page=100'],
  parse([body], config) {
    let posts;
    try { posts = JSON.parse(body); } catch { throw new ParseError('Nagios: body is not JSON'); }
    if (!Array.isArray(posts)) throw new ParseError('Nagios: expected an array of disclosures');
    return posts.map((p) => {
      const title = stripHtml(p.title && p.title.rendered);
      const rows = (p.acf && Array.isArray(p.acf.cve) ? p.acf.cve : []);
      const summary = rows.map((r) => r.vulnerability_summary).filter(Boolean).join(' ').slice(0, 400);
      const cveText = JSON.stringify(rows);
      return makeItem({
        id: `nagios:${p.slug}`,
        source: 'nagios',
        kind: 'vuln',
        title,
        summary,
        cves: [...new Set(cveText.match(/CVE-\d{4}-\d{4,}/g) || [])],
        severity: 'important',
        products: [...new Set(['nagios', ...matchProducts(`${title} ${summary}`, config)])].sort(),
        published: p.date_gmt ? `${p.date_gmt}Z` : p.date || '',
        url: p.link,
      });
    });
  },
};

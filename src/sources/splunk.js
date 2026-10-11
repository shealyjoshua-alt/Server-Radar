// Splunk security advisories RSS. Only Universal Forwarder advisories are in scope.
const { makeItem } = require('../core/item');
const { matchProducts } = require('../core/match');
const { parseRss, stripHtml } = require('./rss');

module.exports = {
  id: 'splunk',
  label: 'Splunk security advisories',
  urls: ['https://advisory.splunk.com/feed.xml'],
  parse([body], config) {
    return parseRss(body, 'Splunk').map((r) => {
      const summary = stripHtml(r.description).slice(0, 400);
      const svd = (r.title.match(/SVD-\d{4}-\d{4}/) || [r.guid])[0];
      return makeItem({
        id: `splunk:${svd}`,
        source: 'splunk',
        kind: 'vuln',
        title: r.title,
        summary,
        cves: [...new Set(`${r.title} ${r.description}`.match(/CVE-\d{4}-\d{4,}/g) || [])],
        // The feed has no severity field; use the advisory's own words, else unknown
        // (unknown-severity advisories are hidden; NVD supplies scored UF CVEs).
        severity: /\bcritical\b/i.test(summary) ? 'critical' : /\bhigh\b/i.test(summary) ? 'important' : null,
        products: matchProducts(`${r.title} ${summary}`, config),
        published: r.pubDate,
        url: r.link,
      });
    });
  },
};

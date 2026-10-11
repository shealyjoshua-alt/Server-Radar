// Azure Updates RSS: new features, previews, GA, retirements.
const { makeItem } = require('../core/item');
const { matchProducts } = require('../core/match');
const { parseRss, stripHtml } = require('./rss');
const { isGov } = require('./azure');

module.exports = {
  id: 'azure-updates',
  label: 'Azure Updates',
  urls: ['https://www.microsoft.com/releasecommunications/api/v2/azure/rss'],
  parse([body], config) {
    return parseRss(body, 'Azure Updates').map((r) => {
      const summary = stripHtml(r.description).slice(0, 400);
      const text = `${r.title} ${summary}`;
      const retirement = r.categories.some((c) => /retire/i.test(c)) || /^Retirement\b/i.test(r.title);
      return makeItem({
        id: `azupd:${r.guid}`,
        source: 'azure-updates',
        kind: retirement ? 'retirement' : 'update',
        title: r.title,
        summary,
        gov: isGov(text, config),
        products: [...new Set(['azure', ...matchProducts(text, config)])].sort(),
        published: r.pubDate,
        url: r.link,
      });
    });
  },
};

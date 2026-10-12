// Azure status RSS (active incidents). There is no separate Azure Government feed;
// Government incidents are recognised by region names (config.govMarkers).
const { makeItem } = require('../core/item');
const { parseRss, stripHtml } = require('./rss');
const { isGov } = require('./azure');

module.exports = {
  id: 'azure-status',
  label: 'Azure status',
  urls: ['https://rssfeed.azure.status.microsoft/en-us/status/feed/'],
  // Which Gov incidents are in the feed right now (the feed only carries active ones).
  summarize(bodies, config) {
    return { activeGov: module.exports.parse(bodies, config).filter((i) => i.gov && i.kind === 'incident').map((i) => i.id) };
  },
  parse([body], config) {
    // No active incidents is the normal state, so an empty feed is valid here.
    return parseRss(body, 'Azure status', { allowEmpty: true }).map((r) => {
      const summary = stripHtml(r.description).slice(0, 400);
      const text = `${r.title} ${summary}`;
      return makeItem({
        id: `azstatus:${r.guid}`,
        source: 'azure-status',
        kind: /planned maintenance/i.test(text) ? 'maintenance' : 'incident',
        title: r.title,
        summary,
        gov: isGov(text, config),
        products: ['azure'],
        published: r.pubDate,
        url: r.link || 'https://azure.status.microsoft/en-us/status/',
      });
    });
  },
};

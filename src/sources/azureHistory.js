// Azure status history: Microsoft's recent post-incident reviews (only the latest few major
// incidents are listed). Each becomes a resolved incident; a review naming a US Gov region is a Gov outage.
// Structure (Oct 2026): .incident-history-item > button header (.hide-text MM/DD/YYYY,
// .incident-history-title, .incident-history-tracking-id) + #incident-history-collapse-<id> body.
const cheerio = require('cheerio/slim');
const { makeItem, ParseError } = require('../core/item');
const { isGov, isEntra } = require('./azure');

const URL = 'https://azure.status.microsoft/en-us/status/history/';

function isoDay(mdy) {
  const m = /(\d{2})\/(\d{2})\/(\d{4})/.exec(mdy || '');
  return m ? `${m[3]}-${m[1]}-${m[2]}` : '';
}

module.exports = {
  id: 'azure-history',
  label: 'Azure status history',
  urls: [URL],
  parse([html], config) {
    const $ = cheerio.load(html || '');
    const items = $('.incident-history-item').toArray().map((el) => {
      const tracking = $(el).find('.incident-history-tracking-id').text().replace(/Tracking ID:/i, '').trim();
      const title = $(el).find('.incident-history-title').text().replace(/\s+/g, ' ').trim();
      if (!tracking || !title) return null;
      const body = $(`#incident-history-collapse-${tracking}`).text().replace(/\s+/g, ' ').trim();
      return makeItem({
        id: `azhist:${tracking}`,
        source: 'azure-history',
        kind: 'incident',
        status: 'resolved',
        title,
        summary: body.slice(0, 400),
        gov: isGov(`${title} ${body}`, config),
        products: isEntra(`${title} ${body}`) ? ['azure', 'entra'] : ['azure'],
        published: isoDay($(el).find('.hide-text').first().text()),
        url: `${URL}?trackingId=${encodeURIComponent(tracking)}`,
      });
    }).filter(Boolean);
    if (!items.length) throw new ParseError('Azure history: no incident entries (page format changed?)');
    return items;
  },
};

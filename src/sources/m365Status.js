// Microsoft's public status site (status.cloud.microsoft). Microsoft posts here only for major
// Microsoft 365 incidents (when admins can't reach Service Health); there is no public
// GCC-specific feed, so a post that mentions GCC is marked Gov, and every post is shown.
const { makeItem, ParseError } = require('../core/item');
const { stripHtml } = require('./rss');
const { isGov, isEntra, isGcc } = require('./azure');

const QUIET = ['Available', 'Operational'];

function post(body) {
  let d;
  try { d = JSON.parse(body); } catch { throw new ParseError('M365 status: body is not JSON'); }
  const p = Array.isArray(d) ? d[0] : d;
  if (!p || typeof p.Status !== 'string') throw new ParseError('M365 status: no Status field (format changed?)');
  return p;
}

function toItems(body, config) {
  const p = post(body);
  if (QUIET.includes(p.Status) || !p.Title) return [];
  const summary = stripHtml(p.Message).slice(0, 400);
  const text = `${p.Title} ${summary}`;
  return [makeItem({
    id: `m365:${p.Id || p.AuthoredDateTime}`,
    source: 'm365-status',
    kind: 'incident',
    title: p.Title,
    summary,
    products: [...(isEntra(text) ? ['entra'] : []), 'm365'],
    gov: isGcc(text) || isGov(text, config),
    published: new Date(p.AuthoredDateTime || p.LastUpdatedTime).toISOString(),
    url: 'https://status.cloud.microsoft/',
  })];
}

module.exports = {
  id: 'm365-status',
  label: 'Microsoft 365 status',
  urls: ['https://status.cloud.microsoft/api/posts/mac'],
  parse([body], config) { return toItems(body, config); },
  summarize([body], config) { return { active: toItems(body, config).map((i) => i.id) }; },
};

// Minimal RSS 2.0 reader shared by the RSS-based sources.
const { XMLParser } = require('fast-xml-parser');
const { ParseError } = require('../core/item');

const parser = new XMLParser({ ignoreAttributes: false, cdataPropName: false, trimValues: true });
const text = (v) => (v && typeof v === 'object' ? v['#text'] || '' : v || '').toString().trim();
const list = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

function parseRss(xml, label, { allowEmpty = false } = {}) {
  let doc;
  try { doc = parser.parse(xml || ''); } catch (e) { throw new ParseError(`${label}: invalid XML (${e.message})`); }
  const channel = doc && doc.rss && doc.rss.channel;
  if (!channel || typeof channel !== 'object') throw new ParseError(`${label}: RSS has no channel`);
  const entries = list(channel.item);
  if (!allowEmpty && entries.length === 0) throw new ParseError(`${label}: RSS has no items (format changed?)`);
  return entries.map((it) => ({
    title: text(it.title),
    link: text(it.link),
    description: text(it.description),
    guid: text(it.guid) || text(it.link),
    pubDate: it.pubDate ? new Date(text(it.pubDate)).toISOString() : '',
    categories: list(it.category).map(text),
  }));
}

const stripHtml = (s) => String(s || '').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();

module.exports = { parseRss, stripHtml };

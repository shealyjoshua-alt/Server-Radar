// Windows release health "known issues" pages, one per Server version.
// Structure (Oct 2026): <h2 id="known-issues"> is followed by a summary <table>; each
// row's first cell holds <div id="NNNNmsg">, a bold title and a short description;
// cells 2-4 are originating update (KB + date), status (+ fix KB) and last updated.
// Full text for each issue sits under <div id="NNNNmsgdesc"> further down the page.
const cheerio = require('cheerio/slim');
const { makeItem, ParseError } = require('../core/item');
const { matchProducts } = require('../core/match');

const PAGES = [
  ['ws2016', 'https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-1607-and-windows-server-2016'],
  ['ws2019', 'https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-1809-and-windows-server-2019'],
  ['ws2022', 'https://learn.microsoft.com/en-us/windows/release-health/status-windows-server-2022'],
  ['ws2025', 'https://learn.microsoft.com/en-us/windows/release-health/status-windows-server-2025'],
];

const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 80);
const firstDate = (s) => (s.match(/\d{4}-\d{2}-\d{2}/) || [''])[0];

function detailText($, id) {
  const start = $(`div[id="${id}desc"]`);
  if (!start.length) return '';
  const parts = [];
  for (let el = start.next(); el.length && !el.is('div[id$="msgdesc"]') && !el.is('h2, h3'); el = el.next()) {
    parts.push(el.text());
  }
  return parts.join(' ').replace(/\s+/g, ' ').trim();
}

function parsePage(html, version, pageUrl, config) {
  const $ = cheerio.load(html);
  const heading = $('h2').filter((_, el) => $(el).text().trim() === 'Known issues').first();
  if (!heading.length) throw new ParseError(`release health ${version}: no "Known issues" section`);
  const table = heading.nextAll('table').first();
  const rows = table.find('tbody tr').toArray();
  if (rows.length === 0) throw new ParseError(`release health ${version}: no known-issue rows (page format changed?)`);
  const items = rows.map((tr) => {
    const cells = $(tr).find('td');
    const first = cells.eq(0);
    const anchor = first.find('div[id$="msg"]').attr('id') || '';
    const title = first.find('b').first().text().trim();
    if (!title) return null;
    const short = first.text().replace(title, '').replace(/\s+/g, ' ').trim();
    const statusText = cells.eq(2).text().replace(/\s+/g, ' ').trim();
    const resolved = /^Resolved/i.test(statusText);
    const fixKb = (statusText.match(/KB\d{6,8}/) || [null])[0];
    const detail = detailText($, anchor);
    const summary = (short || detail).slice(0, 400);
    return makeItem({
      id: `rh:${version}:${slug(title)}`,
      source: 'release-health',
      kind: 'known-issue',
      title,
      summary,
      status: resolved ? 'resolved' : 'open',
      fixedBy: resolved ? fixKb || 'resolved' : null,
      // Only this page's version: issues often list every affected version, and each
      // version is resolved separately (different KBs, different dates).
      products: [...new Set([version, ...matchProducts(`${title} ${short} ${detail}`, config).filter((p) => !p.startsWith('ws'))])].sort(),
      published: firstDate(cells.eq(1).text()) || firstDate(cells.eq(3).text()),
      url: anchor ? `${pageUrl}#${anchor}desc` : pageUrl,
    });
  }).filter(Boolean);
  if (items.length === 0) throw new ParseError(`release health ${version}: rows had no titles (page format changed?)`);
  return items;
}

module.exports = {
  id: 'release-health',
  label: 'Windows release health',
  urls: PAGES.map(([, u]) => u),
  parse(bodies, config) {
    return bodies.flatMap((html, i) => parsePage(html || '', PAGES[i][0], PAGES[i][1], config));
  },
};

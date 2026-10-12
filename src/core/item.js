class ParseError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ParseError';
  }
}

const KINDS = ['vuln', 'known-issue', 'incident', 'maintenance', 'update', 'retirement', 'release'];

function makeItem(fields) {
  for (const k of ['id', 'source', 'title', 'kind']) {
    if (!fields || !fields[k]) throw new TypeError(`item missing ${k}`);
  }
  if (!KINDS.includes(fields.kind)) throw new TypeError(`unknown kind ${fields.kind}`);
  return {
    id: fields.id,
    source: fields.source,
    title: String(fields.title),
    url: fields.url || '',
    published: fields.published || '',
    summary: fields.summary || '',
    cves: fields.cves ? [...fields.cves] : [],
    cvss: typeof fields.cvss === 'number' && !Number.isNaN(fields.cvss) ? fields.cvss : null,
    severity: fields.severity || null,
    exploited: Boolean(fields.exploited),
    exploitedAt: fields.exploitedAt || null,
    kind: fields.kind,
    status: fields.status || null,
    products: fields.products ? [...fields.products] : [],
    gov: Boolean(fields.gov),
    fixedBy: fields.fixedBy || null,
    patchMonth: fields.patchMonth || null, // 'YYYY-MM' Patch Tuesday that fixed it (Microsoft)
  };
}

module.exports = { makeItem, ParseError, KINDS };

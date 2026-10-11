// Broadcom security advisories (VMware = segment VC, Carbon Black = segment SE).
// The public advisory page is rendered from this JSON list endpoint (POST).
const { makeItem, ParseError } = require('../core/item');
const { matchProducts } = require('../core/match');

const ENDPOINT = 'https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList';
const listRequest = (segment) => ({
  url: ENDPOINT,
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
  body: JSON.stringify({ pageNumber: 0, pageSize: 50, searchVal: '', segment, sortInfo: { column: '', order: '' } }),
});

const SEVERITY = { CRITICAL: 'critical', HIGH: 'important', IMPORTANT: 'important', MEDIUM: 'moderate', MODERATE: 'moderate', LOW: 'low' };

function isoDate(s) {
  const t = Date.parse(`${s} UTC`);
  return Number.isNaN(t) ? '' : new Date(t).toISOString().slice(0, 10);
}

function toItem(a, config) {
  const advisoryId = (a.title.match(/VMSA-\d{4}-\d{4}(\.\d+)?/) || [a.documentId])[0];
  const cves = [...new Set(`${a.affectedCve || ''} ${a.title}`.match(/CVE-\d{4}-\d{4,}/g) || [])];
  const severity = SEVERITY[String(a.severity || '').toUpperCase()] || null;
  return makeItem({
    id: `vmsa:${advisoryId}`,
    source: 'broadcom-vmsa',
    kind: 'vuln',
    title: a.title,
    summary: a.workAround && a.workAround !== 'None' ? `Workaround: ${a.workAround}` : '',
    cves,
    severity,
    // VMware's rating scale defines Critical as CVSSv3 9.0-10.0; the list gives no score,
    // so Critical is recorded at the scale's floor.
    cvss: severity === 'critical' ? 9.0 : null,
    products: matchProducts(`${a.title} ${a.supportProducts || ''}`, config),
    published: isoDate(a.published),
    url: a.notificationUrl || 'https://support.broadcom.com/web/ecx/security-advisory',
  });
}

module.exports = {
  id: 'broadcom-vmsa',
  label: 'Broadcom VMware / Carbon Black advisories',
  requests: [listRequest('VC'), listRequest('SE')],
  parse(bodies, config) {
    return bodies.flatMap((body) => {
      let d;
      try { d = JSON.parse(body); } catch { throw new ParseError('VMSA: body is not JSON'); }
      if (!d || !d.data || !Array.isArray(d.data.list) || d.data.list.length === 0) throw new ParseError('VMSA: no advisories in list');
      return d.data.list.map((a) => toItem(a, config));
    });
  },
};

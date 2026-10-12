// Looks up which Patch Tuesday fixed a CVE (Microsoft Security Update Guide API). Used for
// exploited Windows items that came only from CISA KEV, so "patched through" can hide them.
const MONTHS = { Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06', Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12' };

// "2026-Sep" -> "2026-09"; null if unrecognised.
function monthFromRelease(release) {
  const m = /^(\d{4})-([A-Z][a-z]{2})$/.exec(String(release || ''));
  return m && MONTHS[m[2]] ? `${m[1]}-${MONTHS[m[2]]}` : null;
}

const lookupUrl = (cve) => `https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability?$filter=cveNumber%20eq%20'${encodeURIComponent(cve)}'`;

async function lookupPatchMonth(cve, httpGet) {
  const d = JSON.parse(await httpGet(lookupUrl(cve), { headers: { Accept: 'application/json' } }));
  const hit = (d.value || []).find((v) => v.cveNumber === cve);
  return hit ? monthFromRelease(hit.releaseNumber) : null;
}

const needsPatchMonth = (item) => Boolean(item.exploited && !item.patchMonth && !item.patchLookupAt
  && item.cves && item.cves.length && item.products.some((p) => p.startsWith('ws')));

module.exports = { lookupPatchMonth, needsPatchMonth, lookupUrl, monthFromRelease };

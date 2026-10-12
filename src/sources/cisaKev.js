// CISA Known Exploited Vulnerabilities catalog (JSON feed).
const { makeItem, ParseError } = require('../core/item');
const { matchProducts } = require('../core/match');

const ALL_SERVERS = ['ws2016', 'ws2019', 'ws2022', 'ws2025'];
const NON_WINDOWS = /Office|Exchange|SharePoint|Outlook|Word|Excel|PowerPoint|Access|Publisher|Visio|Project|Skype|Teams|Lync|Dynamics|Visual Studio|VS Code|Edge|Xbox|Silverlight|Open Management Infrastructure|OMI|Forefront|System Center|SQL Server|Azure|\.NET/i;

function productsFor(v, config) {
  const products = new Set(matchProducts(`${v.vendorProject} ${v.product} ${v.shortDescription}`, config));
  // Descriptions often mention browsers in passing; only Google/Mozilla entries are browser bugs.
  if (!/^Google$/i.test(v.vendorProject)) products.delete('chrome');
  if (!/^Mozilla$/i.test(v.vendorProject)) products.delete('firefox');
  // KEV names Windows components ("Windows", "Win32k", "Netlogon", "SMBv1", "Internet Explorer")
  // without Server versions; err toward alerting for any Microsoft product that is not a
  // clearly separate application.
  const onlyRoleTopics = [...products].every((p) => p === 'dc');
  if (v.vendorProject === 'Microsoft' && !NON_WINDOWS.test(v.product) && onlyRoleTopics) {
    ALL_SERVERS.forEach((p) => products.add(p));
  }
  if (/^(VMware|Broadcom)$/i.test(v.vendorProject) && !/Workstation|Fusion/i.test(v.product)
      && /VMware|ESXi|vCenter|vSphere|Multiple Products|Cloud Foundation|Tools/i.test(v.product)) {
    products.add('vmware');
  }
  return [...products].sort();
}

module.exports = {
  id: 'cisa-kev',
  label: 'CISA KEV',
  urls: ['https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'],
  parse([body], config) {
    let data;
    try { data = JSON.parse(body); } catch { throw new ParseError('KEV: body is not JSON'); }
    if (!Array.isArray(data.vulnerabilities) || data.vulnerabilities.length === 0) {
      throw new ParseError('KEV: no vulnerabilities array');
    }
    return data.vulnerabilities.map((v) => makeItem({
      id: `kev:${v.cveID}`,
      source: 'cisa-kev',
      kind: 'vuln',
      title: v.vulnerabilityName,
      summary: `${v.shortDescription} Required action: ${v.requiredAction}`,
      cves: [v.cveID],
      exploited: true,
      severity: 'critical',
      published: v.dateAdded,
      url: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
      products: productsFor(v, config),
    }));
  },
};

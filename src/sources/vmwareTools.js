// VMware Tools release index (packages.vmware.com). Compares the latest releases with the
// versions the owner runs (config.vmwareToolsVersions); newer releases become VMware items.
const { makeItem, ParseError } = require('../core/item');

const INDEX = 'https://packages.vmware.com/tools/releases/';

function compareVersions(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d;
  }
  return 0;
}

function versionsIn(html) {
  const found = [...String(html || '').matchAll(/href="(\d+\.\d+\.\d+)\/"/g)].map((m) => m[1]);
  if (!found.length) throw new ParseError('VMware Tools: no versions in release index (format changed?)');
  return [...new Set(found)].sort(compareVersions);
}

const installedOf = (config) => [...(config.vmwareToolsVersions || [])].sort(compareVersions);

module.exports = {
  id: 'vmware-tools',
  label: 'VMware Tools releases',
  urls: [INDEX],
  compareVersions,
  parse([html], config) {
    const versions = versionsIn(html);
    const installed = installedOf(config);
    if (!installed.length) return [];
    const highest = installed[installed.length - 1];
    // The index has no dates; first sighting is close enough (the store keeps the earliest).
    const seenAt = new Date().toISOString();
    return versions.filter((v) => compareVersions(v, highest) > 0).map((v) => makeItem({
      id: `vmtools:${v}`,
      source: 'vmware-tools',
      kind: 'release',
      title: `VMware Tools ${v} available (you run ${installed.join(', ')})`,
      products: ['vmware'],
      published: seenAt,
      url: `${INDEX}${v}/`,
    }));
  },
  summarize([html], config) {
    const versions = versionsIn(html);
    return {
      latest: versions[versions.length - 1],
      installed: installedOf(config).map((version) => ({ version, newer: versions.filter((v) => compareVersions(v, version) > 0) })),
    };
  },
};

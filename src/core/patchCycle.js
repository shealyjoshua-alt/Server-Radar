// Shared by Node (main process, tests) and the dashboard pages (window.RadarPatchCycle).
(function (root) {
const VERSIONS = ['ws2019', 'ws2022', 'ws2025'];
const DAY = 86400000;

function secondTuesday(year, month) {
  const first = new Date(year, month, 1);
  const offset = (2 - first.getDay() + 7) % 7; // days to first Tuesday
  return new Date(year, month, 1 + offset + 7);
}

// Second Tuesday of this month, or next month's once that day has passed (local time).
function nextPatchTuesday(from) {
  const pt = secondTuesday(from.getFullYear(), from.getMonth());
  const startOfDay = new Date(from.getFullYear(), from.getMonth(), from.getDate());
  return startOfDay > pt ? secondTuesday(from.getFullYear(), from.getMonth() + 1) : pt;
}

function safeToDeploy(snapshot, now) {
  const cutoff = new Date(now.getTime() - 45 * DAY).toISOString().slice(0, 10);
  return VERSIONS.map((version) => {
    const issues = snapshot.items.filter((i) => i.kind === 'known-issue' && i.products.includes(version) && (i.published || '') >= cutoff);
    const openIssues = issues.filter((i) => i.status !== 'resolved').length;
    return { version, status: openIssues ? 'caution' : 'clean', openIssues, resolved: issues.length - openIssues };
  });
}

const api = { nextPatchTuesday, secondTuesday, safeToDeploy };
if (typeof module !== 'undefined' && module.exports) module.exports = api;
else root.RadarPatchCycle = api;
})(typeof window !== 'undefined' ? window : globalThis);

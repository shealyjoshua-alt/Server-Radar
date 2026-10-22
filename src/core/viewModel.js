const { iconState, tileCounts } = require('./status');
const { nextPatchTuesday, safeToDeploy } = require('./patchCycle');

const CROWDSTRIKE_NOTE = 'CrowdStrike tech alerts are behind the customer portal; coverage here is public CVEs, Microsoft notes and community reports.';

function buildViewModel(snapshot, config, now = new Date()) {
  return {
    snapshot,
    icon: iconState(snapshot, config),
    tiles: tileCounts(snapshot),
    patchTuesday: nextPatchTuesday(now).toISOString(),
    safe: safeToDeploy(snapshot, now),
    configNote: { crowdstrike: CROWDSTRIKE_NOTE },
    bulletins: (snapshot.meta && snapshot.meta.msrc && snapshot.meta.msrc.months) || [],
    patchedThrough: config.patchedThrough || null,
    php: (snapshot.meta && snapshot.meta.php) || null,
    vmwareTools: (snapshot.meta && snapshot.meta['vmware-tools']) || null,
    activeGovOutages: [
      ...((snapshot.meta && snapshot.meta['azure-status'] && snapshot.meta['azure-status'].activeGov) || []),
      ...((snapshot.meta && snapshot.meta['m365-status'] && snapshot.meta['m365-status'].active) || []),
    ],
  };
}

module.exports = { buildViewModel, CROWDSTRIKE_NOTE };

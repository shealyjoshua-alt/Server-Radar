const test = require('node:test');
const assert = require('node:assert/strict');
const { loadConfig } = require('../../src/core/match');
const { buildViewModel, CROWDSTRIKE_NOTE } = require('../../src/core/viewModel');

const cfg = loadConfig();

test('builds the dashboard view model from a snapshot', () => {
  const snapshot = { items: [{ key: 'a', tier: 'act', products: ['ws2022'], read: false, kind: 'vuln' }], sources: [], firstSync: false, updatedAt: null };
  const vm = buildViewModel(snapshot, cfg, new Date(2026, 9, 10));
  assert.equal(vm.icon.color, 'red');
  assert.equal(vm.tiles.windows.unread, 1);
  assert.equal(new Date(vm.patchTuesday).getDate(), 13);
  assert.equal(vm.safe.length, 4);
  assert.equal(vm.configNote.crowdstrike, CROWDSTRIKE_NOTE);
  assert.equal(CROWDSTRIKE_NOTE, 'CrowdStrike tech alerts are behind the customer portal; coverage here is public CVEs, Microsoft notes and community reports.');
  assert.equal(vm.snapshot, snapshot);
});

test('view model carries the bulletin and the patched-through month', () => {
  const snapshot = { items: [], sources: [], meta: { msrc: { months: [{ month: '2026-09' }] } } };
  const vm = buildViewModel(snapshot, { ...cfg, patchedThrough: '2026-09' }, new Date(2026, 9, 10));
  assert.deepEqual(vm.bulletins, [{ month: '2026-09' }]);
  assert.equal(vm.patchedThrough, '2026-09');
});

test('view model carries the active Gov outage ids', () => {
  const vm = buildViewModel({ items: [], sources: [], meta: { 'azure-status': { activeGov: ['azstatus:1'] } } }, cfg, new Date());
  assert.deepEqual(vm.activeGovOutages, ['azstatus:1']);
  assert.deepEqual(buildViewModel({ items: [], sources: [] }, cfg, new Date()).activeGovOutages, []);
});

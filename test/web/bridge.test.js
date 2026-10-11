const test = require('node:test');
const assert = require('node:assert/strict');
const { applyReadState } = require('../../web/bridge');

const vm = () => ({
  snapshot: { items: [
    { key: 'A', tier: 'act', products: ['ws2022'], read: false },
    { key: 'W', tier: 'watch', products: ['vmware'], read: false },
    { key: 'G', tier: 'watch', products: ['crowdstrike', 'ws2019'], read: false },
  ], sources: [{ id: 'msrc', label: 'Microsoft', consecutiveFailures: 0 }] },
  icon: {}, tiles: {},
});

test('read keys from this phone are applied and counts recomputed', () => {
  const out = applyReadState(vm(), new Set(['A']), 3);
  assert.equal(out.snapshot.items.find((i) => i.key === 'A').read, true);
  assert.equal(out.icon.color, 'amber');
  assert.equal(out.icon.count, 0);
  assert.deepEqual(out.tiles.windows, { unread: 1, color: 'amber' });
  assert.deepEqual(out.tiles.vmware, { unread: 1, color: 'amber' });
  assert.deepEqual(out.tiles.agents, { unread: 1, color: 'amber' });
});

test('unread act is red; failing source is grey when nothing red', () => {
  assert.equal(applyReadState(vm(), new Set(), 3).icon.color, 'red');
  const v = vm(); v.snapshot.sources[0].consecutiveFailures = 3;
  assert.equal(applyReadState(v, new Set(['A', 'W', 'G']), 3).icon.color, 'grey');
});

test('azure tile on the phone counts only government items', () => {
  const v = { snapshot: { items: [{ key: 'g', tier: 'watch', products: ['azure'], gov: true }, { key: 'c', tier: 'azure', products: ['azure'], gov: false }], sources: [] } };
  assert.deepEqual(applyReadState(v, new Set(), 3).tiles.azure, { unread: 1, color: 'amber' });
});

test('phone tiles include domain controllers', () => {
  const v = { snapshot: { items: [{ key: 'd', tier: 'act', products: ['dc', 'ws2022'] }], sources: [] } };
  assert.deepEqual(applyReadState(v, new Set(), 3).tiles.dc, { unread: 1, color: 'red' });
});

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadConfig } = require('../../src/core/match');
const { iconState, tileCounts } = require('../../src/core/status');

const cfg = loadConfig();
const item = (tier, products, read = false) => ({ key: Math.random().toString(36), tier, products, read });
const src = (id, label, consecutiveFailures) => ({ id, label, consecutiveFailures });
const snap = (items, sources = []) => ({ items, sources });

test('unread act is red with count even when a source is failing', () => {
  const s = iconState(snap([item('act', ['ws2022']), item('act', ['vmware']), item('act', ['ws2019'], true)], [src('cisa-kev', 'CISA KEV', 5)]), cfg);
  assert.equal(s.color, 'red');
  assert.equal(s.count, 2);
  assert.match(s.tooltip, /2 need action/);
  assert.match(s.tooltip, /CISA KEV not updating/);
});

test('no unread act and a source at 3 failures is grey', () => {
  const s = iconState(snap([item('watch', ['ws2022'])], [src('msrc', 'Microsoft', 3)]), cfg);
  assert.equal(s.color, 'grey');
  assert.equal(s.count, 0);
});

test('source at 2 failures with unread watch is amber', () => {
  assert.equal(iconState(snap([item('watch', ['ws2022'])], [src('msrc', 'Microsoft', 2)]), cfg).color, 'amber');
});

test('all read and healthy is green with count 0', () => {
  const s = iconState(snap([item('act', ['ws2022'], true), item('watch', ['vmware'], true)], [src('msrc', 'M', 0)]), cfg);
  assert.equal(s.color, 'green');
  assert.equal(s.count, 0);
});

test('recovered source is no longer grey', () => {
  assert.equal(iconState(snap([], [src('msrc', 'M', 0)]), cfg).color, 'green');
});

test('unread interest/azure items do not colour the icon', () => {
  assert.equal(iconState(snap([item('interest', ['azure']), item('azure', ['azure'])]), cfg).color, 'green');
});

test('tile counts group by product family with worst unread tier', () => {
  const t = tileCounts(snap([
    item('act', ['ws2022']), item('watch', ['ws2019']), item('watch', ['vmware']),
    item('watch', ['crowdstrike', 'ws2022']), item('interest', ['azure']), item('act', ['ws2025'], true),
  ]));
  assert.deepEqual(t.windows, { unread: 3, color: 'red' });
  assert.deepEqual(t.vmware, { unread: 1, color: 'amber' });
  assert.deepEqual(t.azure, { unread: 0, color: 'green' });
  assert.deepEqual(t.agents, { unread: 1, color: 'amber' });
});

test('azure tile counts only government items', () => {
  const gov = { ...item('watch', ['azure']), gov: true };
  const t = tileCounts(snap([gov, item('azure', ['azure']), item('interest', ['azure'])]));
  assert.deepEqual(t.azure, { unread: 1, color: 'amber' });
});

test('domain controllers tile counts dc items', () => {
  const t = tileCounts(snap([item('watch', ['dc', 'ws2022']), item('watch', ['ws2019'])]));
  assert.deepEqual(t.dc, { unread: 1, color: 'amber' });
});

test('chrome and firefox count as agents', () => {
  const t = tileCounts(snap([item('watch', ['chrome']), item('watch', ['firefox'])]));
  assert.deepEqual(t.agents, { unread: 2, color: 'amber' });
});

test('filemaker tile counts filemaker items', () => {
  assert.deepEqual(tileCounts(snap([item('watch', ['filemaker'])])).filemaker, { unread: 1, color: 'amber' });
});

test('servicenow tile counts servicenow items', () => {
  assert.deepEqual(tileCounts(snap([item('watch', ['servicenow'])])).servicenow, { unread: 1, color: 'amber' });
});

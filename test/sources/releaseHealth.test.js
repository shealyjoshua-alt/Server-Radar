const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ParseError } = require('../../src/core/item');
const { loadConfig } = require('../../src/core/match');
const rh = require('../../src/sources/releaseHealth');

const cfg = loadConfig();
const fx = (v) => fs.readFileSync(path.join(__dirname, `../fixtures/release-health/${v}.html`), 'utf8');
const bodies = [fx('2016'), fx('2019'), fx('2022'), fx('2025')];
const items = rh.parse(bodies, cfg);

test('module shape', () => {
  assert.equal(rh.id, 'release-health');
  assert.equal(rh.urls.length, 4);
  assert.match(rh.urls[0], /windows-server-2016$/);
});

test('each page yields known issues tagged with its version', () => {
  for (const v of ['ws2016', 'ws2019', 'ws2022', 'ws2025']) {
    const mine = items.filter((i) => i.url.includes(v.slice(2)));
    assert.ok(mine.length >= 1, v);
    assert.ok(mine.every((i) => i.products.includes(v) && i.kind === 'known-issue'));
  }
});

test('same issue on several version pages stays one item per version', () => {
  const usb = items.filter((i) => /USB audio/.test(i.title));
  assert.ok(usb.length >= 3);
  assert.deepEqual(usb.map((i) => i.id).filter((id) => !id.includes('ws2016')).sort(), [
    'rh:ws2019:usb-audio-devices-might-fail-to-start-or-produce-no-sound',
    'rh:ws2022:usb-audio-devices-might-fail-to-start-or-produce-no-sound',
    'rh:ws2025:usb-audio-devices-might-fail-to-start-or-produce-no-sound',
  ]);
  for (const it of usb) assert.equal(it.products.filter((p) => p.startsWith('ws')).length, 1);
});

test('heading present but no issue rows throws ParseError', () => {
  const empty = fx('2022').replace(/<tbody>[\s\S]*?<\/tbody>/, '<tbody></tbody>');
  assert.throws(() => rh.parse([fx('2016'), fx('2019'), empty, fx('2025')], cfg), ParseError);
});

test('resolved issue has fixedBy KB', () => {
  const it = items.find((i) => i.url.includes('2022') && /Remote Desktop Services/.test(i.title));
  assert.equal(it.status, 'resolved');
  assert.equal(it.fixedBy, 'KB5129237');
  assert.equal(it.published, '2026-09-08');
  assert.match(it.url, /status-windows-server-2022#4981msgdesc$/);
});

test('mitigated issue is still open', () => {
  const it = items.find((i) => i.url.includes('2022') && /USB audio/.test(i.title));
  assert.equal(it.status, 'open');
  assert.equal(it.fixedBy, null);
  assert.match(it.summary, /USB Audio Class/);
});

test('issue mentioning an agent gets that agent id', () => {
  const html = fx('2022').replace('Some Windows devices with Remote Desktop enabled', 'Devices running CrowdStrike Falcon sensor');
  const it = rh.parse([fx('2016'), fx('2019'), html, fx('2025')], cfg).find((i) => /Remote Desktop Services/.test(i.title) && i.url.includes('2022'));
  assert.ok(it.products.includes('crowdstrike'));
});

test('page without known issues section throws ParseError', () => {
  assert.throws(() => rh.parse(['<html></html>', fx('2019'), fx('2022'), fx('2025')], cfg), ParseError);
});

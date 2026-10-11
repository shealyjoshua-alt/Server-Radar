const test = require('node:test');
const assert = require('node:assert/strict');
const { matchProducts, loadConfig } = require('../../src/core/match');

const cfg = loadConfig();

test('matches each server version', () => {
  assert.deepEqual(matchProducts('Security update for Windows Server 2022 and Windows Server 2025', cfg), ['ws2022', 'ws2025']);
});

test('excluded look-alikes do not match', () => {
  assert.deepEqual(matchProducts('Windows Server 2012 R2 and Windows 11 23H2', cfg), []);
  assert.deepEqual(matchProducts('VMware Workstation Pro update', cfg), []);
  assert.deepEqual(matchProducts('Splunk Enterprise 9.3 advisory', cfg), []);
});

test('2012 excluded but 2019 in same text still matches', () => {
  assert.deepEqual(matchProducts('Windows Server 2012 R2, Windows Server 2019', cfg), ['ws2019']);
});

test('case-insensitive, agents', () => {
  assert.deepEqual(matchProducts('universal forwarder and falcon sensor crash', cfg), ['crowdstrike', 'splunkuf']);
});

test('keyword with plus sign matches', () => {
  assert.deepEqual(matchProducts('NSClient++ 0.6 vulnerability', cfg), ['nagios']);
});

test('keyword must be a whole word', () => {
  assert.deepEqual(matchProducts('Azurerite mineral', cfg), []);
});

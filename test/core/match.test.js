const test = require('node:test');
const assert = require('node:assert/strict');
const { matchProducts, loadConfig } = require('../../src/core/match');

const cfg = loadConfig();

test('matches each server version', () => {
  assert.deepEqual(matchProducts('Security update for Windows Server 2022 and Windows Server 2025', cfg), ['ws2022', 'ws2025']);
});

test('server 2016 is supported', () => {
  assert.deepEqual(matchProducts('Windows Server 2016 (Server Core installation)', cfg), ['ws2016']);
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

test('domain controller topics tag dc', () => {
  for (const t of ['Windows Kerberos Elevation of Privilege Vulnerability', 'Windows Netlogon spoofing', 'Active Directory Domain Services flaw',
    'Windows LDAP Remote Code Execution', 'Domain controllers might fail to authenticate', 'NTLM hash disclosure', 'Group Policy processing fails', 'Active Directory Certificate Services']) {
    assert.ok(matchProducts(t, cfg).includes('dc'), t);
  }
});

test('Azure Active Directory / Entra is not a domain controller topic', () => {
  assert.ok(!matchProducts('Azure Active Directory B2C update', cfg).includes('dc'));
});

test('chromium and firefox tag the browsers', () => {
  assert.ok(matchProducts('Google Chromium V8 type confusion', cfg).includes('chrome'));
  assert.ok(matchProducts('Mozilla Firefox use-after-free', cfg).includes('firefox'));
  assert.ok(!matchProducts('Stable Channel Update for ChromeOS', cfg).includes('chrome'));
});

test('FileMaker products tag filemaker', () => {
  assert.ok(matchProducts('Claris FileMaker Server 2025 vulnerability', cfg).includes('filemaker'));
});

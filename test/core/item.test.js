const test = require('node:test');
const assert = require('node:assert/strict');
const { makeItem, ParseError } = require('../../src/core/item');

test('fills defaults', () => {
  const it = makeItem({ id: 'a', source: 's', title: 't', kind: 'vuln' });
  assert.deepEqual(it.cves, []);
  assert.deepEqual(it.products, []);
  assert.equal(it.cvss, null);
  assert.equal(it.severity, null);
  assert.equal(it.status, null);
  assert.equal(it.fixedBy, null);
  assert.equal(it.exploited, false);
  assert.equal(it.gov, false);
  assert.equal(it.url, '');
  assert.equal(it.summary, '');
});

test('missing kind throws TypeError', () => {
  assert.throws(() => makeItem({ id: 'a', source: 's', title: 't' }), TypeError);
});

test('ParseError is an Error', () => {
  const e = new ParseError('bad');
  assert.ok(e instanceof Error);
  assert.equal(e.name, 'ParseError');
});

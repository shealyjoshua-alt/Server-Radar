const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { httpGet, HttpError } = require('../../src/sources/http');

// Starts a local server, runs fn(url), and always shuts the server down.
async function withServer(handler, fn) {
  const srv = await new Promise((resolve) => {
    const s = http.createServer(handler).listen(0, '127.0.0.1', () => resolve(s));
  });
  try {
    return await fn(`http://127.0.0.1:${srv.address().port}/`);
  } finally {
    srv.closeAllConnections();
    srv.close();
  }
}

test('returns body and sends user agent and headers', async () => {
  let seen;
  await withServer((req, res) => { seen = req.headers; res.end('hello'); }, async (url) => {
    assert.equal(await httpGet(url, { headers: { Accept: 'application/json' } }), 'hello');
  });
  assert.match(seen['user-agent'], /ServerRadar/);
  assert.equal(seen.accept, 'application/json');
});

test('non-2xx throws HttpError with status', async () => {
  await withServer((req, res) => { res.statusCode = 404; res.end(); }, async (url) => {
    await assert.rejects(httpGet(url), (e) => e instanceof HttpError && e.status === 404);
  });
});

test('times out', async () => {
  await withServer(() => {}, async (url) => {
    await assert.rejects(httpGet(url, { timeoutMs: 100 }));
  });
});

test('sends method and body when given', async () => {
  let got = '';
  let method;
  const handler = (req, res) => { method = req.method; req.on('data', (c) => { got += c; }); req.on('end', () => res.end('ok')); };
  await withServer(handler, (url) => httpGet(url, { method: 'POST', body: '{"a":1}', headers: { 'Content-Type': 'application/json' }, timeoutMs: 2000 }));
  assert.equal(method, 'POST');
  assert.equal(got, '{"a":1}');
});

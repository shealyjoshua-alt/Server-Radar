const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { writeSite } = require('../../scripts/build-web');

test('writes a self-contained static site with the view model', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'site-'));
  writeSite(out, { snapshot: { items: [], sources: [], updatedAt: '2026-10-11T00:00:00Z' }, icon: {}, tiles: {}, patchTuesday: '', safe: [], configNote: {} });
  for (const f of ['index.html', 'view.js', 'app.js', 'bridge.js', 'styles.css', 'viewmodel.json', 'manifest.webmanifest', 'icon.png']) {
    assert.ok(fs.existsSync(path.join(out, f)), f);
  }
  const html = fs.readFileSync(path.join(out, 'index.html'), 'utf8');
  assert.match(html, /bridge\.js[\s\S]*view\.js[\s\S]*app\.js/);
  assert.match(html, /apple-mobile-web-app-capable/);
  assert.ok(!html.includes('unsafe-inline'));
});

test('scripts and styles get a version stamp so phones load the new code', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'site-'));
  writeSite(out, { snapshot: { items: [], sources: [] } }, 'abc123');
  const html = fs.readFileSync(path.join(out, 'index.html'), 'utf8');
  for (const f of ['bridge.js', 'view.js', 'app.js', 'styles.css']) assert.ok(html.includes(`${f}?v=abc123`), f);
});

// Builds the phone/web dashboard as a static site: node scripts/build-web.js <outDir>
// Used by the GitHub Action (hourly) and runnable locally.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const COPY = [
  ['src/renderer/view.js', 'view.js'], ['src/core/patchCycle.js', 'patchCycle.js'], ['src/renderer/app.js', 'app.js'], ['src/renderer/styles.css', 'styles.css'],
  ['web/bridge.js', 'bridge.js'], ['web/index.html', 'index.html'], ['web/manifest.webmanifest', 'manifest.webmanifest'], ['web/icon.png', 'icon.png'],
];

// version: stamps asset URLs so phones (which cache Pages files) pick up new code at once.
function writeSite(outDir, vm, version = String(Date.now())) {
  fs.mkdirSync(outDir, { recursive: true });
  for (const [from, to] of COPY) fs.copyFileSync(path.join(ROOT, from), path.join(outDir, to));
  const index = path.join(outDir, 'index.html');
  fs.writeFileSync(index, fs.readFileSync(index, 'utf8').replace(/(src|href)="(bridge\.js|patchCycle\.js|view\.js|app\.js|styles\.css)"/g, `$1="$2?v=${version}"`));
  fs.writeFileSync(path.join(outDir, 'viewmodel.json'), JSON.stringify(vm));
}

async function main(outDir) {
  const { loadConfig } = require('../src/core/match');
  const { createStore } = require('../src/core/store');
  const { runRefresh } = require('../src/core/refresh');
  const { buildViewModel } = require('../src/core/viewModel');
  const { httpGet } = require('../src/sources/http');
  const config = loadConfig();
  const store = createStore(path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'radar-web-')), 'state.json'), config);
  await runRefresh({ sources: require('../src/sources'), store, config, httpGet });
  const snap = store.snapshot();
  // Read state lives on each phone, so publish everything as unread.
  snap.items.forEach((i) => { i.read = false; });
  writeSite(outDir, buildViewModel(snap, config));
  snap.sources.forEach((s) => console.log(s.consecutiveFailures ? 'FAIL' : 'ok  ', s.id, s.lastError || ''));
}

if (require.main === module) main(process.argv[2] || 'site').catch((e) => { console.error(e); process.exit(1); });

module.exports = { writeSite };

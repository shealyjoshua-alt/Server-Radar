// Builds test/preview/viewmodel.json from a state file for the browser preview:
// node scripts/make-preview-vm.js <state-file>
const fs = require('node:fs');
const path = require('node:path');
const { createStore } = require('../src/core/store');
const { loadConfig } = require('../src/core/match');
const { buildViewModel } = require('../src/core/viewModel');
const config = loadConfig();
const snap = createStore(process.argv[2], config).snapshot();
// Mark the newest few items in each tier unread so the preview shows unread styling.
const seen = {};
for (const it of snap.items) { seen[it.tier] = (seen[it.tier] || 0) + 1; if (seen[it.tier] <= 4) it.read = false; }
fs.writeFileSync(path.join(__dirname, '..', 'test', 'preview', 'viewmodel.json'), JSON.stringify(buildViewModel(snap, config)));

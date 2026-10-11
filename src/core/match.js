const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_CONFIG = path.join(__dirname, '..', '..', 'config', 'radar.config.json');

function loadConfig(file = DEFAULT_CONFIG) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// \b fails next to non-word chars like "+", so use explicit lookarounds.
const wordRe = (kw) => new RegExp(`(?<![A-Za-z0-9_])${escapeRe(kw)}(?![A-Za-z0-9_])`, 'gi');

function matchProducts(text, config) {
  let t = String(text || '');
  for (const ex of config.exclude || []) t = t.replace(wordRe(ex), ' ');
  const found = [];
  for (const [id, keywords] of Object.entries(config.products)) {
    if (keywords.some((kw) => wordRe(kw).test(t))) found.push(id);
  }
  return found.sort();
}

module.exports = { loadConfig, matchProducts };

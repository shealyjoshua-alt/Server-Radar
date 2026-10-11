// Writes the menu bar status dots: assets/tray-<color>.png (16 px) and @2x (32 px).
const fs = require('node:fs');
const path = require('node:path');
const { PNG } = require('pngjs');

const COLORS = { red: '#e5484d', grey: '#8b8d98', amber: '#f5a524', green: '#30a46c' };
const out = path.join(__dirname, '..', 'assets');
fs.mkdirSync(out, { recursive: true });

function dot(size, hex) {
  const png = new PNG({ width: size, height: size });
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
  const c = (size - 1) / 2;
  const radius = size * 0.34;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const d = Math.hypot(x - c, y - c);
      const alpha = Math.max(0, Math.min(1, radius + 0.5 - d)); // anti-aliased edge
      const i = (y * size + x) * 4;
      png.data[i] = r; png.data[i + 1] = g; png.data[i + 2] = b; png.data[i + 3] = Math.round(alpha * 255);
    }
  }
  return PNG.sync.write(png);
}

for (const [name, hex] of Object.entries(COLORS)) {
  fs.writeFileSync(path.join(out, `tray-${name}.png`), dot(16, hex));
  fs.writeFileSync(path.join(out, `tray-${name}@2x.png`), dot(32, hex));
}
console.log('wrote', Object.keys(COLORS).length * 2, 'icons to', out);

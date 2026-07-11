const fs = require('fs');
const path = require('path');

const targetDir = path.resolve(__dirname, '../node_modules/@acme/internal-config');
const sourceDir = path.resolve(__dirname, '../packages/internal-config');
const files = ['package.json', 'index.js'];

if (!fs.existsSync(targetDir)) {
  console.error('Install dependencies first (npm install).');
  process.exit(1);
}

files.forEach((file) => {
  const src = path.join(sourceDir, file);
  const dest = path.join(targetDir, file);
  if (!fs.existsSync(src)) {
    console.warn(`Missing ${src}, skipping.`);
    return;
  }
  fs.copyFileSync(src, dest);
});

console.log('Dependency restored to the original private implementation.');

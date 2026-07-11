const demo = require('./demo-state');

function parseMode(argv) {
  const idx = argv.indexOf('--mode');
  if (idx !== -1 && argv[idx + 1]) {
    return argv[idx + 1].toLowerCase();
  }
  return null;
}

const mode = parseMode(process.argv) || 'defense';
if (mode !== 'attack' && mode !== 'defense') {
  console.error('Usage: node scripts/ci-simulate.js --mode attack|defense');
  process.exit(1);
}

const state = demo.simulateCi(mode);
console.log(`CI simulation complete. Mode: ${state.mode}`);

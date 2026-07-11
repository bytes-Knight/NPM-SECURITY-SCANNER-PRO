const { startServer } = require('../server');
const port = process.env.SANITY_PORT || 4001;
const server = startServer(port);

function shutdown() {
  server.close(() => {
    console.log('Sanity check server closed.');
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

console.log('Sanity check server running. Press Ctrl+C to stop.');

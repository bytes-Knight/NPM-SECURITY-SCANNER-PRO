const express = require('express');
const path = require('path');
const demo = require('./scripts/demo-state');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/status', (req, res) => {
  const state = demo.getState();
  res.json({
    mode: state.mode,
    lastUpdated: state.lastUpdated,
    ecosystems: ['npm', 'pypi', 'maven']
  });
});

app.get('/api/ecosystems', (req, res) => {
  res.json({
    npm: demo.getInstalled('npm'),
    pypi: demo.getInstalled('pypi'),
    maven: demo.getInstalled('maven')
  });
});

app.get('/api/ecosystems/:name', (req, res) => {
  const name = req.params.name.toLowerCase();
  if (!['npm', 'pypi', 'maven'].includes(name)) {
    res.status(404).json({ error: 'Unknown ecosystem' });
    return;
  }
  res.json(demo.getInstalled(name));
});

app.get('/api/configs', (req, res) => {
  res.json(demo.getActiveConfigs());
});

app.get('/api/logs', (req, res) => {
  const limit = parseInt(req.query.lines || '100', 10);
  res.json({ lines: demo.getLogs(limit) });
});

app.post('/api/toggle', (req, res) => {
  const mode = (req.body && req.body.mode) ? String(req.body.mode).toLowerCase() : '';
  if (mode !== 'attack' && mode !== 'defense') {
    res.status(400).json({ error: 'mode must be attack or defense' });
    return;
  }
  const state = demo.simulateCi(mode);
  res.json(state);
});

app.get('/api/toggle', (req, res) => {
  const mode = (req.query.mode || '').toLowerCase();
  if (mode !== 'attack' && mode !== 'defense') {
    res.status(400).json({ error: 'mode must be attack or defense' });
    return;
  }
  const state = demo.simulateCi(mode);
  res.json(state);
});

app.get('/api/run-ci', (req, res) => {
  const mode = (req.query.mode || '').toLowerCase() || demo.getState().mode;
  const state = demo.simulateCi(mode);
  res.json(state);
});

app.get('/status', (req, res) => {
  res.json({
    mode: demo.getState().mode,
    npm: demo.getInstalled('npm'),
    pypi: demo.getInstalled('pypi'),
    maven: demo.getInstalled('maven')
  });
});

function startServer(port = process.env.PORT || 3000) {
  return app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

if (require.main === module) {
  demo.simulateCi(demo.getState().mode || 'defense');
  startServer();
}

module.exports = { app, startServer };

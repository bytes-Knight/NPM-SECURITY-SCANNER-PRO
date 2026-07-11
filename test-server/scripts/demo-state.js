const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', 'demo-state');
const STATE_FILE = path.join(ROOT, 'state.json');
const LOG_FILE = path.join(ROOT, 'ci.log');

function ensureDir(target) {
  fs.mkdirSync(target, { recursive: true });
}

function readJson(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    return fallback;
  }
}

function writeJson(filePath, data) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function readText(filePath, fallback) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    return fallback;
  }
}

function writeText(filePath, content) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, content);
}

function timestamp() {
  return new Date().toISOString();
}

function log(message) {
  const line = `[${timestamp()}] ${message}\n`;
  ensureDir(path.dirname(LOG_FILE));
  fs.appendFileSync(LOG_FILE, line);
}

function getState() {
  return readJson(STATE_FILE, { mode: 'defense', lastUpdated: null });
}

function setState(mode) {
  const state = { mode, lastUpdated: timestamp() };
  writeJson(STATE_FILE, state);
  return state;
}

function sourcePath(ecosystem, variant) {
  return path.join(ROOT, 'sources', ecosystem, `${variant}.json`);
}

function installedPath(ecosystem) {
  return path.join(ROOT, 'installed', ecosystem, 'installed.json');
}

function installFromSource(ecosystem, variant) {
  const src = sourcePath(ecosystem, variant);
  const dest = installedPath(ecosystem);
  const payload = readJson(src, null);
  if (!payload) {
    throw new Error(`Missing source for ${ecosystem}:${variant}`);
  }
  writeJson(dest, payload);
}

function getInstalled(ecosystem) {
  return readJson(installedPath(ecosystem), null);
}

function writeConfig(mode) {
  const npmConfig = readText(path.join(ROOT, 'configs', 'npm', mode === 'attack' ? '.npmrc.public' : '.npmrc'), '');
  const pipConfig = readText(path.join(ROOT, 'configs', 'pip', mode === 'attack' ? 'pip.conf.public' : 'pip.conf'), '');
  const mavenConfig = readText(path.join(ROOT, 'configs', 'maven', mode === 'attack' ? 'settings.xml.public' : 'settings.xml'), '');

  writeText(path.join(ROOT, 'configs', 'npm', '.npmrc.active'), npmConfig);
  writeText(path.join(ROOT, 'configs', 'pip', 'pip.conf.active'), pipConfig);
  writeText(path.join(ROOT, 'configs', 'maven', 'settings.xml.active'), mavenConfig);
}

function simulateCi(mode) {
  const activeMode = mode || getState().mode || 'defense';
  log(`CI start: mode=${activeMode}`);
  log('Step 1/4: Load lockfiles');
  log('Step 2/4: Apply registry configuration');
  writeConfig(activeMode);
  log('Step 3/4: Resolve dependencies');
  installFromSource('npm', activeMode === 'attack' ? 'attacker' : 'internal');
  installFromSource('pypi', activeMode === 'attack' ? 'attacker' : 'internal');
  installFromSource('maven', activeMode === 'attack' ? 'attacker' : 'internal');
  log('Step 4/4: Build artifacts');
  const state = setState(activeMode);
  log(`CI complete: mode=${state.mode}`);
  return state;
}

function getActiveConfigs() {
  return {
    npm: readText(path.join(ROOT, 'configs', 'npm', '.npmrc.active'), ''),
    pypi: readText(path.join(ROOT, 'configs', 'pip', 'pip.conf.active'), ''),
    maven: readText(path.join(ROOT, 'configs', 'maven', 'settings.xml.active'), '')
  };
}

function getLogs(limit) {
  const data = readText(LOG_FILE, '').trim().split('\n');
  if (!data[0]) {
    return [];
  }
  if (limit && data.length > limit) {
    return data.slice(data.length - limit);
  }
  return data;
}

module.exports = {
  ROOT,
  getState,
  setState,
  getInstalled,
  simulateCi,
  getActiveConfigs,
  getLogs,
  log
};

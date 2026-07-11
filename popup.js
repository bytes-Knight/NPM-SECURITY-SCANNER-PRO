/**
 * NPM Security Scanner Pro v3.1.0 — Popup Script
 * Compact 380px UI: theme toggle, settings sub-panel, stage progress,
 * risk meter, expandable findings, copy-bad / copy-all / save.
 */

const elements = {
  themeBtn: document.getElementById('themeBtn'),
  themeIcon: document.getElementById('themeIcon'),
  settingsBtn: document.getElementById('settingsBtn'),
  settingsPanel: document.getElementById('settingsPanel'),
  settingsBackBtn: document.getElementById('settingsBackBtn'),
  settingOsv: document.getElementById('settingOsv'),
  settingDeepCrawl: document.getElementById('settingDeepCrawl'),
  settingAutoScan: document.getElementById('settingAutoScan'),
  settingTheme: document.getElementById('settingTheme'),
  extensionToggle: document.getElementById('extensionToggle'),
  targetUrl: document.getElementById('targetUrl'),
  progressWrap: document.getElementById('progressWrap'),
  progressFill: document.getElementById('progressFill'),
  progressText: document.getElementById('progressText'),
  riskMeter: document.getElementById('riskMeter'),
  riskScore: document.getElementById('riskScore'),
  riskFill: document.getElementById('riskFill'),
  riskCrit: document.getElementById('riskCrit'),
  riskHigh: document.getElementById('riskHigh'),
  riskMed: document.getElementById('riskMed'),
  riskLow: document.getElementById('riskLow'),
  riskVulns: document.getElementById('riskVulns'),
  vulnsStat: document.getElementById('vulnsStat'),
  ecoStrip: document.getElementById('ecoStrip'),
  controls: document.getElementById('controls'),
  searchInput: document.getElementById('searchInput'),
  severityFilter: document.getElementById('severityFilter'),
  rescanBtn: document.getElementById('rescanBtn'),
  copyBadBtn: document.getElementById('copyBadBtn'),
  copyAllBtn: document.getElementById('copyAllBtn'),
  saveBtn: document.getElementById('saveBtn'),
  results: document.getElementById('results'),
  emptyState: document.getElementById('emptyState'),
  emptyTitle: document.getElementById('emptyTitle'),
  emptyText: document.getElementById('emptyText'),
  toast: document.getElementById('toast')
};

const SECTION_META = {
  critical: { title: 'Dependency Confusion (missing on npm)', color: '#ff4d5f' },
  low: { title: 'Safe Packages', color: '#4be288' },
  error: { title: 'Analysis Errors', color: '#ff4d5f' }
};

const SECTION_ORDER = ['critical', 'low', 'error'];
const MAX_POLL_ATTEMPTS_WITHOUT_RESPONSE = 12;
const DEFAULT_EXPANDED_SECTIONS = new Set(['critical']);
const SETTINGS_KEYS = ['osvLookup', 'deepCrawl', 'autoScan', 'theme'];

const state = {
  rawResults: null,
  visibleSections: { critical: [], low: [], error: [] },
  filters: { search: '', severity: 'ALL' },
  pollTimer: null,
  pollAttempts: 0,
  activeTabId: null,
  extensionEnabled: true,
  lastRenderedScanning: false,
  lastUiSignature: '',
  lastStageSignature: '',
  lastRiskSignature: '',
  settings: { osvLookup: true, deepCrawl: true, autoScan: true, theme: 'dark' },
  settingsPanelOpen: false,
  collapsedSections: new Set(),
  // Tracks which finding cards are expanded inline for details view.
  expandedFindings: new Set()
};

// ============================================================================
// UTILITIES
// ============================================================================

const utils = {
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text == null ? '' : String(text);
    return div.innerHTML;
  },

  formatNumber(num) {
    const value = Number(num || 0);
    if (value >= 1000000) return `${(value / 1000000).toFixed(1)}M`;
    if (value >= 1000) return `${(value / 1000).toFixed(1)}K`;
    return `${value}`;
  },

  summarizeUrl(url) {
    if (!url) return '—';
    try {
      const parsed = new URL(url);
      return `${parsed.hostname}${parsed.pathname !== '/' ? parsed.pathname : ''}`;
    } catch {
      return url;
    }
  },

  /**
   * Compute a 0–100 risk score. Critical (unregistered) packages are the dominant
   * signal; OSV advisories add incrementally. Safe packages don't add score.
   */
  calculateRiskScore(stats) {
    if (!stats) return 0;
    const score = (stats.critical * 25) + (stats.advisories * 3);
    return Math.max(0, Math.min(100, score));
  }
};

// ============================================================================
// TOAST
// ============================================================================

const toast = {
  timer: null,
  show(message, type = 'success') {
    if (!elements.toast) return;
    if (this.timer) clearTimeout(this.timer);
    elements.toast.textContent = message;
    elements.toast.className = `toast ${type === 'error' ? 'error' : ''} show`;
    this.timer = setTimeout(() => {
      elements.toast.className = 'toast';
    }, 1800);
  }
};

// ============================================================================
// CLIPBOARD
// ============================================================================

const clipboard = {
  async copyText(text) {
    if (!text) return false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch { /* fall through */ }
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.top = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    let copied = false;
    try { copied = document.execCommand('copy'); } catch { copied = false; }
    document.body.removeChild(textarea);
    return copied;
  }
};

// ============================================================================
// THEME + SETTINGS
// ============================================================================

const theme = {
  apply(themeName) {
    const safe = themeName === 'light' ? 'light' : 'dark';
    document.body.classList.remove('theme-dark', 'theme-light');
    document.body.classList.add(`theme-${safe}`);
    if (elements.themeIcon) elements.themeIcon.textContent = safe === 'light' ? '☀' : '☾';
    if (elements.settingTheme) elements.settingTheme.value = safe;
    state.settings.theme = safe;
  },
  toggle() {
    const next = state.settings.theme === 'dark' ? 'light' : 'dark';
    this.apply(next);
    settings.saveDebounced();
  }
};

const settings = {
  saveTimer: null,
  async load() {
    try {
      const stored = await chrome.storage.sync.get({
        osvLookup: true,
        deepCrawl: true,
        autoScan: true,
        theme: 'dark'
      });
      Object.assign(state.settings, stored);
    } catch (e) { /* storage unavailable; use defaults */ }
    theme.apply(state.settings.theme);
    if (elements.settingOsv) elements.settingOsv.checked = state.settings.osvLookup !== false;
    if (elements.settingDeepCrawl) elements.settingDeepCrawl.checked = state.settings.deepCrawl !== false;
    if (elements.settingAutoScan) elements.settingAutoScan.checked = state.settings.autoScan !== false;
  },
  saveDebounced() {
    if (this.saveTimer) clearTimeout(this.saveTimer);
    this.saveTimer = setTimeout(() => this.save(), 200);
  },
  async save() {
    try {
      await chrome.storage.sync.set(state.settings);
    } catch (e) { /* ignore */ }
  }
};

// ============================================================================
// SCAN DATA MODEL
// ============================================================================

class ScanDataModel {
  static hasValidPayload(results) {
    return Boolean(results && Array.isArray(results.packages) && Array.isArray(results.exposedFiles));
  }

  static hasAnyData(results) {
    if (!this.hasValidPayload(results)) return false;
    return results.packages.length > 0 || results.exposedFiles.length > 0;
  }

  static calculateStats(results) {
    const packages = Array.isArray(results?.packages) ? results.packages : [];
    const exposedFiles = Array.isArray(results?.exposedFiles) ? results.exposedFiles : [];
    const ecosystems = { npm: 0, pypi: 0, gems: 0, go: 0, cargo: 0, php: 0 };

    // Binary model: critical (unregistered/dependency confusion) vs low (everything else).
    let critical = 0, low = 0, error = 0, advisories = 0;

    packages.forEach((pkg) => {
      if (!pkg) return;
      const ecosystem = String(pkg.ecosystem || 'npm').toLowerCase();
      if (ecosystem === 'npm') ecosystems.npm += 1;
      else if (ecosystem === 'pypi') ecosystems.pypi += 1;
      else if (ecosystem === 'rubygems') ecosystems.gems += 1;
      else if (ecosystem === 'golang') ecosystems.go += 1;
      else if (ecosystem === 'crates') ecosystems.cargo += 1;
      else if (ecosystem === 'composer') ecosystems.php += 1;

      advisories += Number(pkg.advisoriesCount) || 0;

      if (pkg.error) { error += 1; return; }
      if (pkg.isUnregistered) { critical += 1; return; }
      // Everything else (registered, with or without CVEs/heuristic flags) is "safe" in the UI.
      low += 1;
    });

    exposedFiles.forEach((_file) => {
      // Exposed files are informational; surface in the safe section so users can audit them.
      if (!_file) return;
      low += 1;
    });

    return {
      totalPackages: packages.length,
      exposedFileCount: exposedFiles.length,
      criticalRisks: critical,
      critical, low, error, advisories,
      totalFindings: critical + low + error,
      ecosystems
    };
  }

  static buildSections(results) {
    // Binary model: critical = unregistered (dependency confusion), low = everything else (safe).
    const sections = { critical: [], low: [], error: [] };
    const packages = Array.isArray(results?.packages) ? results.packages : [];
    const exposedFiles = Array.isArray(results?.exposedFiles) ? results.exposedFiles : [];

    packages.forEach((pkg) => {
      if (!pkg) return;
      if (pkg.error) { sections.error.push(this.mapPackage(pkg, 'error')); return; }
      if (pkg.isUnregistered) { sections.critical.push(this.mapPackage(pkg, 'critical')); return; }
      sections.low.push(this.mapPackage(pkg, 'low'));
    });

    exposedFiles.forEach((file) => {
      if (!file) return;
      // Surface exposed files in the safe section so users can audit them without a separate bucket.
      sections.low.push(this.mapFile(file, 'low'));
    });

    return sections;
  }

  static mapPackage(pkg, severity) {
    const riskLevel = String(pkg.riskLevel || '').toUpperCase() || 'LOW';
    let badgeText = 'OK';
    if (severity === 'critical') badgeText = 'UNREG';
    else if (severity === 'error') badgeText = 'ERR';
    else if (riskLevel === 'HIGH' || riskLevel === 'MEDIUM') badgeText = riskLevel;

    return {
      type: 'package',
      severity,
      name: String(pkg.name || 'unknown'),
      version: pkg.version ? String(pkg.version) : '',
      ecosystem: pkg.ecosystem ? String(pkg.ecosystem) : '',
      badgeText,
      riskLevel,
      riskReasons: Array.isArray(pkg.riskReasons) ? pkg.riskReasons.map(String) : [],
      sources: Array.isArray(pkg.sources) ? pkg.sources.map(String) : [],
      weeklyDownloads: pkg.weeklyDownloads || 0,
      advisories: Array.isArray(pkg.advisories) ? pkg.advisories.map((a) => ({
        id: String(a.id || ''),
        severity: String(a.severity || 'MEDIUM').toUpperCase(),
        summary: String(a.summary || '').slice(0, 200)
      })) : [],
      advisoriesCount: Number(pkg.advisoriesCount) || 0,
      osvError: pkg.osvError ? String(pkg.osvError) : '',
      error: pkg.error ? String(pkg.error) : ''
    };
  }

  static mapFile(file, severity) {
    return {
      type: 'file',
      severity,
      path: String(file.path || 'unknown'),
      risk: String(file.risk || 'LOW').toUpperCase(),
      status: String(file.status ?? ''),
      contentType: String(file.contentType || 'unknown')
    };
  }

  static filterSections(sections, filters) {
    const output = { critical: [], high: [], medium: [], low: [], error: [] };
    const severity = String(filters?.severity || 'ALL').toUpperCase();
    const term = String(filters?.search || '').trim().toLowerCase();

    SECTION_ORDER.forEach((key) => {
      const items = Array.isArray(sections[key]) ? sections[key] : [];
      if (severity !== 'ALL' && severity.toLowerCase() !== key) {
        output[key] = [];
        return;
      }
      output[key] = items.filter((item) => {
        if (!term) return true;
        return this.itemMatches(item, term);
      });
    });
    return output;
  }

  static itemMatches(item, term) {
    const haystack = [];
    if (item.type === 'package') {
      haystack.push(item.name, item.version, item.ecosystem, item.badgeText, item.riskLevel);
      haystack.push(...item.riskReasons);
      haystack.push(...item.sources);
      if (item.error) haystack.push(item.error);
      item.advisories.forEach((a) => { haystack.push(a.id, a.summary); });
    } else {
      haystack.push(item.path, item.risk, item.status, item.contentType);
    }
    return haystack.join(' ').toLowerCase().includes(term);
  }

  static getTotalItems(sections) {
    return SECTION_ORDER.reduce((total, key) => total + (sections[key]?.length || 0), 0);
  }

  static itemToCopyText(item) {
    if (item.type === 'file') {
      return [`[${item.risk}] Exposed File: ${item.path}`, `Status: ${item.status}`, `Content-Type: ${item.contentType}`].join('\n');
    }
    const lines = [`[${item.badgeText}] Package: ${item.name}${item.version ? `@${item.version}` : ''}`];
    if (item.ecosystem) lines.push(`Ecosystem: ${item.ecosystem}`);
    if (item.weeklyDownloads) lines.push(`Downloads/week: ${item.weeklyDownloads}`);
    if (item.error) lines.push(`Error: ${item.error}`);
    if (item.riskReasons.length > 0) {
      lines.push('Reasons:');
      item.riskReasons.forEach((r) => lines.push(`- ${r}`));
    }
    if (item.advisories.length > 0) {
      lines.push('Advisories:');
      item.advisories.forEach((a) => lines.push(`- [${a.severity}] ${a.id}: ${a.summary}`));
    }
    if (item.sources.length > 0) {
      lines.push('Sources:');
      item.sources.forEach((s) => lines.push(`- ${s}`));
    }
    return lines.join('\n');
  }

  static sectionToCopyText(sectionKey, items) {
    const meta = SECTION_META[sectionKey] || { title: sectionKey };
    const lines = [`${meta.title} (${items.length})`, `Generated: ${new Date().toISOString()}`, ''];
    items.forEach((item, index) => {
      lines.push(`#${index + 1}`);
      lines.push(this.itemToCopyText(item));
      lines.push('');
    });
    return lines.join('\n').trim();
  }

  static badItemsToCopyText(results) {
    const sections = this.buildSections(results);
    const critical = sections.critical || [];
    const lines = ['Missing / unregistered packages (dependency-confusion candidates):', ''];
    if (critical.length === 0) {
      lines.push('(none)');
    } else {
      critical.forEach((item, i) => {
        if (item.type === 'file') lines.push(`#${i + 1} [${item.risk}] ${item.path}`);
        else lines.push(`#${i + 1} [${item.badgeText}] ${item.name}${item.version ? `@${item.version}` : ''}`);
        const reasons = item.riskReasons.join('; ');
        if (reasons) lines.push(`  Reason: ${reasons}`);
        if (item.advisories.length > 0) {
          lines.push(`  Advisories: ${item.advisories.map((a) => a.id).join(', ')}`);
        }
        lines.push('');
      });
    }
    return lines.join('\n').trim();
  }

  static summaryToCopyText(results) {
    const stats = this.calculateStats(results);
    const lines = [
      'NPM Security Scanner Summary',
      `Generated: ${new Date().toISOString()}`,
      `Target: ${results?.url || 'unknown'}`,
      `Total Packages: ${stats.totalPackages}`,
      `Critical Risks: ${stats.criticalRisks}`,
      `Exposed Files: ${stats.exposedFileCount}`,
      `OSV Advisories: ${stats.advisories}`,
      ''
    ];
    return lines.join('\n');
  }
}

// ============================================================================
// UI RENDERER
// ============================================================================

class UIRenderer {
  static setTargetUrl(url) {
    if (!elements.targetUrl) return;
    elements.targetUrl.textContent = utils.summarizeUrl(url);
    elements.targetUrl.title = String(url || '');
  }

  static setStage(progress, text) {
    const signature = `${progress}|${text || ''}`;
    if (state.lastStageSignature === signature) return;
    state.lastStageSignature = signature;
    if (!elements.progressWrap) return;
    if (progress == null) {
      elements.progressWrap.hidden = true;
      return;
    }
    elements.progressWrap.hidden = false;
    if (elements.progressFill) elements.progressFill.style.width = `${Math.max(0, Math.min(100, progress))}%`;
    if (elements.progressText) elements.progressText.textContent = text || '';
  }

  static setRiskMeter(stats) {
    const signature = stats
      ? `${stats.critical}|${stats.low}|${stats.advisories}|${stats.totalFindings}`
      : 'empty';
    if (state.lastRiskSignature === signature) return;
    state.lastRiskSignature = signature;

    if (!stats || stats.totalFindings === 0) {
      if (elements.riskMeter) elements.riskMeter.hidden = true;
      return;
    }
    if (elements.riskMeter) elements.riskMeter.hidden = false;

    const score = utils.calculateRiskScore(stats);
    if (elements.riskScore) elements.riskScore.textContent = score.toString();
    if (elements.riskFill) elements.riskFill.style.width = `${score}%`;
    if (elements.riskCrit) elements.riskCrit.textContent = stats.critical.toString();
    if (elements.riskLow) elements.riskLow.textContent = stats.low.toString();
    if (elements.riskVulns) elements.riskVulns.textContent = stats.advisories.toString();
    if (elements.vulnsStat) elements.vulnsStat.hidden = stats.advisories === 0;

    // Ecosystem strip — only show ecosystems with at least one package
    if (elements.ecoStrip) {
      const chips = [];
      const ecoLabels = { npm: 'NPM', pypi: 'PyPI', gems: 'GEMS', go: 'GO', cargo: 'CARGO', php: 'PHP' };
      Object.keys(stats.ecosystems).forEach((key) => {
        if (stats.ecosystems[key] > 0) chips.push(`<span class="eco-chip"><b>${stats.ecosystems[key]}</b>${ecoLabels[key]}</span>`);
      });
      if (chips.length > 0) {
        elements.ecoStrip.innerHTML = chips.join('');
        elements.ecoStrip.hidden = false;
      } else {
        elements.ecoStrip.hidden = true;
      }
    }
  }

  static renderLoading(message) {
    state.lastUiSignature = 'loading';
    state.lastStageSignature = '';
    state.lastRiskSignature = '';
    this.setStage(5, message || 'Initializing…');
    if (elements.controls) elements.controls.hidden = true;
    elements.results.innerHTML = `
      <div class="loading-state">
        <div class="loader"></div>
        <span>${utils.escapeHtml(message || 'Scanning…')}</span>
      </div>
    `;
    if (elements.copyBadBtn) elements.copyBadBtn.disabled = true;
    if (elements.copyAllBtn) elements.copyAllBtn.disabled = true;
    if (elements.saveBtn) elements.saveBtn.disabled = true;
  }

  static renderError(message, details = '') {
    state.lastUiSignature = 'error';
    this.setStage(null);
    this.setRiskMeter(null);
    if (elements.controls) elements.controls.hidden = true;
    elements.results.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">!</div>
        <div class="empty-title">${utils.escapeHtml(message)}</div>
        ${details ? `<div class="empty-text">${utils.escapeHtml(details)}</div>` : ''}
      </div>
    `;
  }

  static renderDisabled() {
    state.lastUiSignature = 'disabled';
    this.setStage(null);
    this.setRiskMeter(null);
    if (elements.controls) elements.controls.hidden = true;
    elements.results.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">II</div>
        <div class="empty-title">Extension Disabled</div>
        <div class="empty-text">Turn the extension on to resume scanning and analysis.</div>
      </div>
    `;
  }

  static renderEmpty(title, description) {
    state.lastUiSignature = `empty:${title}`;
    this.setStage(null);
    this.setRiskMeter(null);
    if (elements.controls) elements.controls.hidden = true;
    elements.results.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">_</div>
        <div class="empty-title">${utils.escapeHtml(title)}</div>
        <div class="empty-text">${utils.escapeHtml(description)}</div>
      </div>
    `;
  }

  static renderNoFilterMatches() {
    state.lastUiSignature = 'no-filter-matches';
    elements.results.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">?</div>
        <div class="empty-title">No matches</div>
        <div class="empty-text">Adjust search keywords or severity filter to view findings.</div>
      </div>
    `;
  }

  static renderResults(results, options = {}) {
    if (!ScanDataModel.hasValidPayload(results)) {
      this.renderEmpty('No scan data', 'Open a page and wait for the content script to provide results.');
      return;
    }

    const scanning = Boolean(options.scanning);
    state.lastRenderedScanning = scanning;
    state.rawResults = results;

    if (results.url) this.setTargetUrl(results.url);

    const stats = ScanDataModel.calculateStats(results);
    this.setRiskMeter(stats);

    if (!scanning) this.setStage(null);
    else if (results.stage) this.setStage(results.stage.progress, results.stage.text);

    if (elements.controls) elements.controls.hidden = false;
    const hasAny = ScanDataModel.hasAnyData(results);
    if (elements.copyBadBtn) elements.copyBadBtn.disabled = !hasAny;
    if (elements.copyAllBtn) elements.copyAllBtn.disabled = !hasAny;
    if (elements.saveBtn) elements.saveBtn.disabled = !hasAny;

    const allSections = ScanDataModel.buildSections(results);
    const filteredSections = ScanDataModel.filterSections(allSections, state.filters);
    state.visibleSections = filteredSections;

    // Build signature to skip redundant renders
    const signatureParts = [
      scanning ? '1' : '0',
      String(results.url || ''),
      String(state.filters.severity || 'ALL'),
      String(state.filters.search || '').trim().toLowerCase()
    ];
    SECTION_ORDER.forEach((key) => {
      const items = filteredSections[key] || [];
      signatureParts.push(`${key}:${items.length}`);
      items.forEach((item) => {
        if (item.type === 'file') signatureParts.push(`f:${item.path}:${item.risk}`);
        else signatureParts.push(`p:${item.name}:${item.version}:${item.badgeText}:${item.error || ''}:${item.advisoriesCount || 0}`);
      });
    });
    const signature = signatureParts.join('|');
    if (state.lastUiSignature === signature) return;
    state.lastUiSignature = signature;

    const totalVisible = ScanDataModel.getTotalItems(filteredSections);
    if (totalVisible === 0) {
      const totalAll = ScanDataModel.getTotalItems(allSections);
      if (totalAll === 0) {
        this.renderEmpty('No findings detected', 'No suspicious packages or exposed files were identified.');
      } else {
        this.renderNoFilterMatches();
      }
      return;
    }

    // Default-collapse sections other than critical+high on first render
    if (state.collapsedSections instanceof Set && state.collapsedSections.size === 0) {
      SECTION_ORDER.forEach((key) => {
        if (!DEFAULT_EXPANDED_SECTIONS.has(key)) state.collapsedSections.add(key);
      });
    }

    let html = '';
    SECTION_ORDER.forEach((sectionKey) => {
      const items = filteredSections[sectionKey] || [];
      if (items.length === 0) return;
      html += this.renderSection(sectionKey, items);
    });
    elements.results.innerHTML = html;
  }

  static renderSection(sectionKey, items) {
    const meta = SECTION_META[sectionKey] || { title: sectionKey, color: '#85a2cc' };
    const collapsed = (state.collapsedSections instanceof Set) && state.collapsedSections.has(sectionKey) ? ' collapsed' : '';
    return `
      <section class="section ${sectionKey}${collapsed}" data-section="${sectionKey}">
        <div class="section-header" data-action="toggle-section" data-section="${sectionKey}">
          <div class="section-title-wrap">
            <span class="section-caret">▼</span>
            <span>${meta.title}</span>
            <span class="section-count">${items.length}</span>
          </div>
          <button class="section-copy" type="button" data-action="copy-section" data-section="${sectionKey}">Copy</button>
        </div>
        <div class="item-list">
          ${items.map((item, index) => this.renderFinding(item, index, sectionKey)).join('')}
        </div>
      </section>
    `;
  }

  static renderFinding(item, index, sectionKey) {
    if (item.type === 'file') return this.renderFileItem(item, index, sectionKey);
    return this.renderPackageItem(item, index, sectionKey);
  }

  static renderPackageItem(item, index, sectionKey) {
    const findingId = `${sectionKey}:${index}:${item.name}`;
    const expanded = (state.expandedFindings instanceof Set) && state.expandedFindings.has(findingId);
    const expandedClass = expanded ? ' expanded' : '';
    const advisories = item.advisories || [];
    const advTag = advisories.length > 0
      ? `<span class="finding-tag vuln" title="${advisories.length} OSV advisory/advisories">⬢ ${advisories.length}</span>`
      : '';
    const ecoTag = item.ecosystem ? `<span class="finding-tag eco">${utils.escapeHtml(item.ecosystem)}</span>` : '';

    const reasons = item.riskReasons.length > 0
      ? item.riskReasons.map((r) => `<div class="detail-line">- ${utils.escapeHtml(r)}</div>`).join('')
      : '<div class="detail-line">- no explicit risk reason</div>';

    const shownSources = item.sources.slice(0, 3);
    const sources = shownSources.length > 0
      ? shownSources.map((s) => `<div class="detail-line mono">${utils.escapeHtml(s)}</div>`).join('')
      : '<div class="detail-line mono">- source not provided</div>';
    const hiddenCount = Math.max(item.sources.length - shownSources.length, 0);
    const remaining = hiddenCount > 0 ? `<div class="detail-line mono">...and ${hiddenCount} more</div>` : '';

    const advisoriesList = advisories.slice(0, 3).map((a) => {
      const sev = String(a.severity || 'MEDIUM').toLowerCase();
      return `
        <div class="advisory-line">
          <span class="advisory-id sev-${sev}">${utils.escapeHtml(a.id)}</span>
          <span class="advisory-summary">${utils.escapeHtml(a.severity)} — ${utils.escapeHtml(a.summary || '')}</span>
        </div>
      `;
    }).join('');
    const advisoriesMore = (item.advisoriesCount - advisories.length) > 0
      ? `<div class="detail-line mono">+ ${item.advisoriesCount - advisories.length} more advisories (top 3 shown)</div>`
      : '';
    const osvErrorLine = item.osvError
      ? `<div class="osv-error">⚠ OSV: ${utils.escapeHtml(item.osvError)}</div>`
      : '';

    return `
      <article class="finding${expandedClass}" data-sev="${item.severity}" data-finding-id="${utils.escapeHtml(findingId)}">
        <div class="finding-row" data-action="toggle-finding" data-finding-id="${utils.escapeHtml(findingId)}">
          <div class="finding-name">${utils.escapeHtml(item.name)}</div>
          <div class="finding-meta">
            ${advTag}${ecoTag}
            <span class="finding-tag ${item.severity}">${utils.escapeHtml(item.badgeText)}</span>
            <button class="finding-copy" type="button" data-action="copy-item" data-finding-id="${utils.escapeHtml(findingId)}" title="Copy name">⧉</button>
          </div>
        </div>
        <div class="finding-details">
          ${item.error ? `<div class="detail-line">Error: ${utils.escapeHtml(item.error)}</div>` : reasons}
          ${osvErrorLine}
          ${advisories.length > 0 ? `<div class="detail-section-title">OSV Advisories</div>${advisoriesList}${advisoriesMore}` : ''}
          <div class="detail-section-title">Sources</div>
          ${sources}${remaining}
        </div>
      </article>
    `;
  }

  static renderFileItem(item, index, sectionKey) {
    const findingId = `${sectionKey}:${index}:${item.path}`;
    const expanded = (state.expandedFindings instanceof Set) && state.expandedFindings.has(findingId);
    const expandedClass = expanded ? ' expanded' : '';
    return `
      <article class="finding${expandedClass}" data-sev="${item.severity}" data-finding-id="${utils.escapeHtml(findingId)}">
        <div class="finding-row" data-action="toggle-finding" data-finding-id="${utils.escapeHtml(findingId)}">
          <div class="finding-name">${utils.escapeHtml(item.path)}</div>
          <div class="finding-meta">
            <span class="finding-tag ${item.severity}">${utils.escapeHtml(item.risk)}</span>
            <button class="finding-copy" type="button" data-action="copy-item" data-finding-id="${utils.escapeHtml(findingId)}" title="Copy path">⧉</button>
          </div>
        </div>
        <div class="finding-details">
          <div class="detail-line">Status: ${utils.escapeHtml(item.status)}</div>
          <div class="detail-line">Content-Type: ${utils.escapeHtml(item.contentType)}</div>
        </div>
      </article>
    `;
  }
}

// ============================================================================
// SCAN MANAGER (popup ↔ content script)
// ============================================================================

const PopupScanManager = {
  isRestrictedUrl(url) {
    if (!url) return true;
    return /^(chrome|edge|about|brave|moz-extension):/i.test(url);
  },

  clearPolling() {
    if (state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  },

  async getActiveTab() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs[0] || null;
  },

  async sendMessage(tabId, payload) {
    return chrome.tabs.sendMessage(tabId, payload);
  },

  async pollStatus(tabId, options = {}) {
    this.clearPolling();
    state.pollAttempts = 0;
    UIRenderer.renderLoading(options.initialLoadingMessage || 'Loading scan status…');

    const renderResponse = (response, scanning) => {
      // Guard every render against thrown errors so a single bad item can't
      // blank the whole popup. The previous design swallowed errors silently
      // in the catch above, which made "Cannot read properties of undefined
      // (reading 'has')" hard to diagnose.
      try {
        UIRenderer.renderResults(response, { scanning });
      } catch (innerError) {
        console.error('[NS Pro] renderResults failed:', innerError);
        const detail = String(innerError && innerError.message ? innerError.message : 'Unknown error');
        const stackLine = String((innerError && innerError.stack) || '').split('\n').slice(0, 2).join(' | ');
        UIRenderer.renderError('Render failed', `${detail}${stackLine ? ` — ${stackLine}` : ''}`);
        return true; // Stop polling on render failure.
      }
      return false;
    };

    const checkStatus = async () => {
      try {
        const response = await this.sendMessage(tabId, { action: 'getScanStatus' });
        if (!response) {
          state.pollAttempts += 1;
          if (state.pollAttempts >= MAX_POLL_ATTEMPTS_WITHOUT_RESPONSE) {
            UIRenderer.renderError('Scanner not responding', 'Try refreshing the page or opening another website.');
            return true;
          }
          UIRenderer.renderLoading('Waiting for content script. Refresh the target page.');
          return false;
        }
        state.pollAttempts = 0;
        if (response.enabled === false) {
          updateToggleState(false);
          UIRenderer.renderDisabled();
          return true;
        }
        if (response.error) {
          UIRenderer.renderError(response.error);
          return true;
        }
        if (response.complete) {
          return renderResponse(response, false) || true;
        }
        if (response.scanning) {
          return renderResponse(response, true) ? true : false;
        }
        if (ScanDataModel.hasValidPayload(response)) {
          return renderResponse(response, false) || true;
        }
        UIRenderer.renderLoading('Initializing scan…');
        return false;
      } catch (error) {
        const message = String(error && error.message ? error.message : 'Unknown error');
        console.error('[NS Pro] checkStatus failed:', error);
        if (message.includes('Could not establish connection') || message.includes('Receiving end does not exist')) {
          state.pollAttempts += 1;
          if (state.pollAttempts >= MAX_POLL_ATTEMPTS_WITHOUT_RESPONSE) {
            UIRenderer.renderError('Scanner did not initialize', 'Refresh the target page, then reopen the extension.');
            return true;
          }
          UIRenderer.renderLoading('Content script not ready. Refresh the page.');
          return false;
        }
        const stackLine = String((error && error.stack) || '').split('\n').slice(0, 2).join(' | ');
        UIRenderer.renderError('Unable to read scan status', `${message}${stackLine ? ` — ${stackLine}` : ''}`);
        return true;
      }
    };

    const complete = await checkStatus();
    if (complete) return;
    state.pollTimer = setInterval(async () => {
      const done = await checkStatus();
      if (done) this.clearPolling();
    }, 1000);
  },

  async refresh(forceRescan = false) {
    try {
      const tab = await this.getActiveTab();
      if (!tab) {
        this.clearPolling();
        UIRenderer.renderError('No active tab', 'Open a web page and try again.');
        return;
      }
      state.activeTabId = tab.id;
      UIRenderer.setTargetUrl(tab.url || 'unknown');

      if (this.isRestrictedUrl(tab.url || '')) {
        this.clearPolling();
        UIRenderer.renderError('Unsupported page', 'System pages cannot be scanned. Open a regular website.');
        return;
      }

      if (forceRescan) {
        try {
          await this.sendMessage(tab.id, { action: 'forceRescan' });
          toast.show('Manual rescan started.');
        } catch (error) {
          const message = String(error && error.message ? error.message : 'Unknown error');
          UIRenderer.renderError('Failed to start rescan', message);
          return;
        }
      }
      await this.pollStatus(tab.id, {
        initialLoadingMessage: forceRescan ? 'Manual rescan started…' : 'Checking scan status…'
      });
    } catch (error) {
      const message = String(error && error.message ? error.message : 'Unknown error');
      UIRenderer.renderError('Popup refresh failed', message);
    }
  }
};

// ============================================================================
// SETTINGS PANEL
// ============================================================================

function openSettings() {
  state.settingsPanelOpen = true;
  if (elements.settingsPanel) elements.settingsPanel.hidden = false;
}

function closeSettings() {
  state.settingsPanelOpen = false;
  if (elements.settingsPanel) elements.settingsPanel.hidden = true;
}

function updateToggleState(isEnabled) {
  state.extensionEnabled = isEnabled;
  if (elements.extensionToggle) elements.extensionToggle.checked = isEnabled;
  if (!isEnabled) {
    PopupScanManager.clearPolling();
    state.rawResults = null;
    state.visibleSections = { critical: [], low: [], error: [] };
    state.lastUiSignature = '';
    state.lastStageSignature = '';
    state.lastRiskSignature = '';
    UIRenderer.renderDisabled();
  }
}

function rerenderFilteredResults() {
  if (!state.rawResults || !ScanDataModel.hasValidPayload(state.rawResults)) return;
  state.lastUiSignature = '';
  UIRenderer.renderResults(state.rawResults, { scanning: state.lastRenderedScanning });
}

// ============================================================================
// COPY HANDLERS
// ============================================================================

async function copyToClipboard(text, successMessage) {
  const copied = await clipboard.copyText(text);
  if (copied) toast.show(successMessage);
  else toast.show('Copy failed', 'error');
}

async function handleCopyItem(findingId) {
  // Lookup via data-finding-id attribute is more reliable than index.
  let item = null;
  const el = document.querySelector(`[data-finding-id="${CSS.escape(findingId)}"]`);
  // We need to find the corresponding item in state.visibleSections.
  for (const sectionKey of SECTION_ORDER) {
    const items = state.visibleSections[sectionKey] || [];
    for (let i = 0; i < items.length; i++) {
      const candidate = items[i];
      const id = `${sectionKey}:${i}:${candidate.name || candidate.path}`;
      if (id === findingId) { item = candidate; break; }
    }
    if (item) break;
  }
  if (!item) { toast.show('Nothing to copy', 'error'); return; }
  const text = item.type === 'file' ? item.path : item.name;
  await copyToClipboard(text, item.type === 'file' ? 'Path copied' : 'Package name copied');
}

async function handleCopySection(sectionKey) {
  const items = state.visibleSections[sectionKey] || [];
  if (items.length === 0) { toast.show('No items in this section', 'error'); return; }
  await copyToClipboard(ScanDataModel.sectionToCopyText(sectionKey, items), `${SECTION_META[sectionKey]?.title || sectionKey} copied`);
}

async function handleCopyBad() {
  if (!state.rawResults) { toast.show('No results', 'error'); return; }
  await copyToClipboard(ScanDataModel.badItemsToCopyText(state.rawResults), 'High-priority findings copied');
}

async function handleCopyAll() {
  if (!state.rawResults) { toast.show('No results', 'error'); return; }
  await copyToClipboard(ScanDataModel.summaryToCopyText(state.rawResults), 'Summary copied');
}

async function handleSaveResults() {
  if (!state.rawResults || !ScanDataModel.hasValidPayload(state.rawResults)) {
    toast.show('No results to save', 'error');
    return;
  }
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `ns-scan-results-${timestamp}.html`;
  const html = generateHtmlReport(state.rawResults);
  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
  toast.show('Report downloaded');
}

function debounce(fn, wait = 150) {
  let timer = null;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), wait);
  };
}

function bindEventListeners() {
  if (elements.themeBtn) {
    elements.themeBtn.addEventListener('click', () => theme.toggle());
  }
  if (elements.settingsBtn) {
    elements.settingsBtn.addEventListener('click', openSettings);
  }
  if (elements.settingsBackBtn) {
    elements.settingsBackBtn.addEventListener('click', closeSettings);
  }
  const settingHandlers = [
    [elements.settingOsv, 'osvLookup'],
    [elements.settingDeepCrawl, 'deepCrawl'],
    [elements.settingAutoScan, 'autoScan']
  ];
  settingHandlers.forEach(([el, key]) => {
    if (!el) return;
    el.addEventListener('change', (e) => {
      state.settings[key] = Boolean(e.target.checked);
      settings.saveDebounced();
    });
  });
  if (elements.settingTheme) {
    elements.settingTheme.addEventListener('change', (e) => {
      theme.apply(e.target.value);
      settings.saveDebounced();
    });
  }

  if (elements.extensionToggle) {
    elements.extensionToggle.addEventListener('change', async (event) => {
      const isEnabled = Boolean(event.target.checked);
      await chrome.storage.local.set({ extensionEnabled: isEnabled });
      updateToggleState(isEnabled);
      try {
        const tab = await PopupScanManager.getActiveTab();
        if (tab?.id) {
          await chrome.tabs.sendMessage(tab.id, { action: 'toggleExtension', enabled: isEnabled });
        }
      } catch { /* content script may not be available */ }
      if (isEnabled) await PopupScanManager.refresh(false);
    });
  }

  if (elements.rescanBtn) elements.rescanBtn.addEventListener('click', () => PopupScanManager.refresh(true));
  if (elements.copyBadBtn) elements.copyBadBtn.addEventListener('click', handleCopyBad);
  if (elements.copyAllBtn) elements.copyAllBtn.addEventListener('click', handleCopyAll);
  if (elements.saveBtn) elements.saveBtn.addEventListener('click', handleSaveResults);

  const debouncedSearch = debounce((value) => {
    state.filters.search = value;
    state.lastUiSignature = '';
    rerenderFilteredResults();
  }, 120);
  if (elements.searchInput) {
    elements.searchInput.addEventListener('input', (e) => debouncedSearch(String(e.target.value || '')));
  }
  if (elements.severityFilter) {
    elements.severityFilter.addEventListener('change', (e) => {
      state.filters.severity = String(e.target.value || 'ALL').toUpperCase();
      state.lastUiSignature = '';
      rerenderFilteredResults();
    });
  }

  // Click delegation for section header, finding expand, copy buttons
  if (elements.results) {
    elements.results.addEventListener('click', async (event) => {
      const copyBtn = event.target.closest('button[data-action]');
      if (copyBtn) {
        event.stopPropagation();
        const action = copyBtn.getAttribute('data-action');
        if (action === 'copy-item') {
          const findingId = copyBtn.getAttribute('data-finding-id');
          await handleCopyItem(findingId);
        } else if (action === 'copy-section') {
          await handleCopySection(copyBtn.getAttribute('data-section'));
        }
        return;
      }
      const sectionHeader = event.target.closest('[data-action="toggle-section"]');
      if (sectionHeader) {
        const key = sectionHeader.getAttribute('data-section');
        if (state.collapsedSections instanceof Set) {
          if (state.collapsedSections.has(key)) state.collapsedSections.delete(key);
          else state.collapsedSections.add(key);
        }
        const sectionEl = sectionHeader.parentElement;
        if (sectionEl) sectionEl.classList.toggle('collapsed');
        return;
      }
      const findingRow = event.target.closest('[data-action="toggle-finding"]');
      if (findingRow) {
        const findingId = findingRow.getAttribute('data-finding-id');
        if (state.expandedFindings instanceof Set) {
          if (state.expandedFindings.has(findingId)) state.expandedFindings.delete(findingId);
          else state.expandedFindings.add(findingId);
        }
        const findingEl = findingRow.parentElement;
        if (findingEl) findingEl.classList.toggle('expanded');
      }
    });
  }
}

function generateHtmlReport(data) {
  const stats = ScanDataModel.calculateStats(data);
  const sections = ScanDataModel.buildSections(data);
  const generatedAt = new Date().toLocaleString();
  const escape = (v) => { const d = document.createElement('div'); d.textContent = v == null ? '' : String(v); return d.innerHTML; };

  const sectionMarkup = SECTION_ORDER.map((key) => {
    const items = sections[key] || [];
    if (items.length === 0) return '';
    const meta = SECTION_META[key];
    const listItems = items.map((item) => {
      if (item.type === 'file') return `<li><strong>${escape(item.path)}</strong> | ${escape(item.risk)} | ${escape(item.status)} | ${escape(item.contentType)}</li>`;
      return `<li><strong>${escape(item.name)}${item.version ? `@${escape(item.version)}` : ''}</strong> [${escape(item.badgeText)}]${item.advisoriesCount > 0 ? ` — ${item.advisoriesCount} OSV advisories` : ''}</li>`;
    }).join('');
    return `<section style="margin-top:16px;"><h3 style="margin:0 0 8px;color:${meta.color};">${meta.title} (${items.length})</h3><ul style="margin:0;padding-left:20px;line-height:1.6;">${listItems}</ul></section>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Scanner Report</title>
  <style>
    body { margin: 0; padding: 24px; font-family: -apple-system, "Segoe UI", system-ui, sans-serif; color: #14202e; background: #f6f8fb; }
    .container { max-width: 980px; margin: 0 auto; border: 1px solid #dde3ec; border-radius: 12px; padding: 24px; background: #fff; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
    .meta { color: #5a6b80; font-size: 13px; }
    .stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin: 16px 0; }
    .card { border: 1px solid #dde3ec; border-radius: 10px; padding: 10px; background: #eef2f7; }
    .value { margin: 0; font-size: 26px; font-weight: 700; }
    .label { margin: 4px 0 0; font-size: 11px; text-transform: uppercase; color: #5a6b80; }
  </style>
</head>
<body>
  <div class="container">
    <h1 style="margin:0;">Security Scanner Report</h1>
    <p class="meta">Generated: ${escape(generatedAt)}</p>
    <p class="meta">Target: ${escape(data.url || 'unknown')}</p>
    <div class="stats">
      <div class="card"><p class="value">${stats.totalPackages}</p><p class="label">Packages</p></div>
      <div class="card"><p class="value">${stats.criticalRisks}</p><p class="label">Critical</p></div>
      <div class="card"><p class="value">${stats.exposedFileCount}</p><p class="label">Exposed</p></div>
      <div class="card"><p class="value">${stats.advisories}</p><p class="label">OSV</p></div>
    </div>
    ${sectionMarkup || '<p>No findings detected.</p>'}
  </div>
</body>
</html>`;
}

document.addEventListener('DOMContentLoaded', async () => {
  bindEventListeners();
  await settings.load();

  chrome.storage.local.get(['extensionEnabled'], async (storage) => {
    const isEnabled = storage.extensionEnabled !== false;
    updateToggleState(isEnabled);
    if (!isEnabled) {
      UIRenderer.renderDisabled();
      return;
    }
    await PopupScanManager.refresh(false);
  });
});

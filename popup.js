/**
 * NPM Security Scanner Pro - Popup Script
 * Neo Security UI with copy toolkit, filtering, and manual rescan.
 */

const elements = {
  scanStatusText: document.getElementById('scanStatusText'),
  targetUrl: document.getElementById('targetUrl'),
  scanResults: document.getElementById('scanResults'),
  statsGrid: document.getElementById('statsGrid'),
  statCritical: document.getElementById('statCritical'),
  statHigh: document.getElementById('statHigh'),
  statMedium: document.getElementById('statMedium'),
  statTotal: document.getElementById('statTotal'),
  ecoNpm: document.getElementById('ecoNpm'),
  ecoPypi: document.getElementById('ecoPypi'),
  ecoGems: document.getElementById('ecoGems'),
  ecoGo: document.getElementById('ecoGo'),
  ecoCargo: document.getElementById('ecoCargo'),
  ecoPhp: document.getElementById('ecoPhp'),
  actionControls: document.getElementById('actionControls'),
  filterControls: document.getElementById('filterControls'),
  rescanBtn: document.getElementById('rescanBtn'),
  copySummaryBtn: document.getElementById('copySummaryBtn'),
  saveResultsBtn: document.getElementById('saveResultsBtn'),
  searchInput: document.getElementById('searchInput'),
  severityFilter: document.getElementById('severityFilter'),
  extensionToggle: document.getElementById('extensionToggle'),
  toggleLabel: document.getElementById('toggleLabel'),
  statusIndicator: document.getElementById('statusIndicator'),
  toast: document.getElementById('toast')
};

const SECTION_META = {
  critical: { title: 'Critical Threats', color: '#ff4d5f' },
  high: { title: 'High Risks', color: '#ff9f43' },
  medium: { title: 'Medium Risks', color: '#ffd166' },
  low: { title: 'Low Risks', color: '#4be288' },
  error: { title: 'Analysis Errors', color: '#ff4d5f' }
};

const SECTION_ORDER = ['critical', 'high', 'medium', 'low', 'error'];
const MAX_POLL_ATTEMPTS_WITHOUT_RESPONSE = 12;

const state = {
  rawResults: null,
  visibleSections: {
    critical: [], high: [], medium: [], low: [], error: []
  },
  filters: { search: '', severity: 'ALL' },
  pollTimer: null,
  pollAttempts: 0,
  activeTabId: null,
  extensionEnabled: true,
  lastRenderedScanning: false,
  lastUiSignature: ''
};

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
    if (!url) return 'unknown';
    try {
      const parsed = new URL(url);
      return `${parsed.hostname}${parsed.pathname !== '/' ? parsed.pathname : ''}`;
    } catch {
      return url;
    }
  }
};

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

const clipboard = {
  async copyText(text) {
    if (!text) return false;

    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch {
      // fallback below
    }

    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.top = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();

    let copied = false;
    try {
      copied = document.execCommand('copy');
    } catch {
      copied = false;
    }

    document.body.removeChild(textarea);
    return copied;
  }
};

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
    const ecosystems = {
      npm: 0,
      pypi: 0,
      gems: 0,
      go: 0,
      cargo: 0,
      php: 0
    };

    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let error = 0;

    packages.forEach((pkg) => {
      if (!pkg) return;

      const ecosystem = String(pkg.ecosystem || 'npm').toLowerCase();
      if (ecosystem === 'npm') ecosystems.npm += 1;
      else if (ecosystem === 'pypi') ecosystems.pypi += 1;
      else if (ecosystem === 'rubygems') ecosystems.gems += 1;
      else if (ecosystem === 'golang') ecosystems.go += 1;
      else if (ecosystem === 'crates') ecosystems.cargo += 1;
      else if (ecosystem === 'composer') ecosystems.php += 1;

      if (pkg.error) {
        error += 1;
        return;
      }

      if (pkg.isUnregistered) {
        critical += 1;
        return;
      }

      const level = String(pkg.riskLevel || '').toUpperCase();
      if (level === 'HIGH') {
        high += 1;
      } else if (level === 'MEDIUM') {
        medium += 1;
      } else {
        low += 1;
      }
    });

    exposedFiles.forEach((file) => {
      if (!file) return;
      const risk = String(file.risk || '').toUpperCase();
      if (risk === 'HIGH') {
        high += 1;
      } else if (risk === 'MEDIUM') {
        medium += 1;
      } else {
        low += 1;
      }
    });

    const totalFindings = critical + high + medium + low + error;

    return {
      totalPackages: packages.length,
      exposedFileCount: exposedFiles.length,
      criticalRisks: critical,
      critical,
      high,
      medium,
      low,
      error,
      totalFindings,
      ecosystems
    };
  }

  static buildSections(results) {
    const sections = { critical: [], high: [], medium: [], low: [], error: [] };
    const packages = Array.isArray(results?.packages) ? results.packages : [];
    const exposedFiles = Array.isArray(results?.exposedFiles) ? results.exposedFiles : [];

    packages.forEach((pkg) => {
      if (!pkg) return;

      if (pkg.error) {
        sections.error.push(this.mapPackage(pkg, 'error'));
        return;
      }

      if (pkg.isUnregistered) {
        sections.critical.push(this.mapPackage(pkg, 'critical'));
        return;
      }

      const level = String(pkg.riskLevel || '').toUpperCase();
      if (level === 'HIGH') {
        sections.high.push(this.mapPackage(pkg, 'high'));
        return;
      }

      if (level === 'MEDIUM') {
        sections.medium.push(this.mapPackage(pkg, 'medium'));
        return;
      }

      sections.low.push(this.mapPackage(pkg, 'low'));
    });

    exposedFiles.forEach((file) => {
      if (!file) return;
      const risk = String(file.risk || '').toUpperCase();
      if (risk === 'HIGH') {
        sections.high.push(this.mapFile(file, 'high'));
      } else if (risk === 'MEDIUM') {
        sections.medium.push(this.mapFile(file, 'medium'));
      } else {
        sections.low.push(this.mapFile(file, 'low'));
      }
    });

    return sections;
  }

  static mapPackage(pkg, severity) {
    const riskLevel = String(pkg.riskLevel || '').toUpperCase() || 'LOW';
    let badgeText = 'OK';

    if (severity === 'critical') {
      badgeText = 'UNREGISTERED';
    } else if (severity === 'error') {
      badgeText = 'ERROR';
    } else if (riskLevel === 'HIGH' || riskLevel === 'MEDIUM') {
      badgeText = riskLevel;
    }

    return {
      type: 'package',
      severity,
      name: String(pkg.name || 'unknown-package'),
      version: pkg.version ? String(pkg.version) : '',
      ecosystem: pkg.ecosystem ? String(pkg.ecosystem) : '',
      badgeText,
      riskLevel,
      riskReasons: Array.isArray(pkg.riskReasons) ? pkg.riskReasons.map(String) : [],
      sources: Array.isArray(pkg.sources) ? pkg.sources.map(String) : [],
      weeklyDownloads: pkg.weeklyDownloads || 0,
      maintainers: pkg.maintainers || 0,
      error: pkg.error ? String(pkg.error) : ''
    };
  }

  static mapFile(file, severity) {
    return {
      type: 'file',
      severity,
      path: String(file.path || 'unknown-path'),
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
      return [
        `[${item.risk}] Exposed File: ${item.path}`,
        `Status: ${item.status}`,
        `Content-Type: ${item.contentType}`
      ].join('\n');
    }

    const lines = [`[${item.badgeText}] Package: ${item.name}${item.version ? `@${item.version}` : ''}`];
    if (item.ecosystem) lines.push(`Ecosystem: ${item.ecosystem}`);
    if (item.weeklyDownloads) lines.push(`Downloads/week: ${item.weeklyDownloads}`);
    if (item.maintainers) lines.push(`Maintainers: ${item.maintainers}`);
    if (item.error) lines.push(`Error: ${item.error}`);

    if (item.riskReasons.length > 0) {
      lines.push('Reasons:');
      item.riskReasons.forEach((reason) => lines.push(`- ${reason}`));
    }

    if (item.sources.length > 0) {
      lines.push('Sources:');
      item.sources.forEach((source) => lines.push(`- ${source}`));
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

  static summaryToCopyText(results) {
    const stats = this.calculateStats(results);
    const sections = this.buildSections(results);

    const lines = [
      'NPM Security Scanner Summary',
      `Generated: ${new Date().toISOString()}`,
      `Target: ${results?.url || 'unknown'}`,
      `Total Packages: ${stats.totalPackages}`,
      `Critical Risks: ${stats.criticalRisks}`,
      `Exposed Files: ${stats.exposedFileCount}`,
      ''
    ];

    const highPriority = [...sections.critical, ...sections.high];
    if (highPriority.length > 0) {
      lines.push('High Priority Findings:');
      highPriority.slice(0, 20).forEach((item) => {
        if (item.type === 'file') {
          lines.push(`- [${item.risk}] ${item.path}`);
          return;
        }
        lines.push(`- [${item.badgeText}] ${item.name}${item.version ? `@${item.version}` : ''}`);
      });
    } else {
      lines.push('High Priority Findings: none');
    }

    return lines.join('\n');
  }
}

class UIRenderer {
  static setStatus(text) {
    elements.scanStatusText.textContent = text;
  }

  static setTargetUrl(url) {
    elements.targetUrl.textContent = `Target: ${utils.summarizeUrl(url)}`;
  }

  static toggleDataControls(show) {
    elements.statsGrid.style.display = show ? 'grid' : 'none';
    elements.actionControls.style.display = show ? 'flex' : 'none';
    elements.filterControls.style.display = show ? 'grid' : 'none';
  }

  static renderLoading(message = 'Scanning in progress...') {
    const signature = `loading:${message}`;
    if (state.lastUiSignature === signature) return;
    state.lastUiSignature = signature;

    this.toggleDataControls(false);
    this.setStatus('SCANNING...');
    elements.scanResults.innerHTML = `
      <div class="loading-state">
        <div class="loader"></div>
        <p>${utils.escapeHtml(message)}</p>
      </div>
    `;
    elements.copySummaryBtn.disabled = true;
    elements.saveResultsBtn.disabled = true;
  }

  static renderError(message, details = '') {
    const signature = `error:${message}:${details}`;
    if (state.lastUiSignature === signature) return;
    state.lastUiSignature = signature;

    this.toggleDataControls(false);
    this.setStatus('ERROR');
    const detailsHtml = details ? `<p>${utils.escapeHtml(details)}</p>` : '';
    elements.scanResults.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">!</div>
        <h2>Error while scanning</h2>
        <p>${utils.escapeHtml(message)}</p>
        ${detailsHtml}
      </div>
    `;
  }

  static renderDisabled() {
    if (state.lastUiSignature === 'disabled') return;
    state.lastUiSignature = 'disabled';

    this.toggleDataControls(false);
    this.setStatus('DISABLED');
    elements.scanResults.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">II</div>
        <h2>Extension Disabled</h2>
        <p>Turn the extension on to resume scanning and analysis.</p>
      </div>
    `;
  }

  static renderEmptyState(title, description) {
    const signature = `empty:${title}:${description}`;
    if (state.lastUiSignature === signature) return;
    state.lastUiSignature = signature;

    elements.scanResults.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">_</div>
        <h2>${utils.escapeHtml(title)}</h2>
        <p>${utils.escapeHtml(description)}</p>
      </div>
    `;
  }

  static renderNoFilterMatches() {
    if (state.lastUiSignature === 'no-filter-matches') return;
    state.lastUiSignature = 'no-filter-matches';

    elements.scanResults.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">?</div>
        <h2>No matches</h2>
        <p>Adjust search keywords or severity filter to view findings.</p>
      </div>
    `;
  }

  static renderResults(results, options = {}) {
    if (!ScanDataModel.hasValidPayload(results)) {
      this.renderEmptyState('No scan data', 'Open a page and wait for the content script to provide results.');
      return;
    }

    const scanning = Boolean(options.scanning);
    state.lastRenderedScanning = scanning;
    state.rawResults = results;

    if (results.url) {
      this.setTargetUrl(results.url);
    }

    const stats = ScanDataModel.calculateStats(results);
    elements.statCritical.textContent = stats.critical.toString();
    elements.statHigh.textContent = stats.high.toString();
    elements.statMedium.textContent = stats.medium.toString();
    elements.statTotal.textContent = stats.totalFindings.toString();
    elements.ecoNpm.textContent = stats.ecosystems.npm.toString();
    elements.ecoPypi.textContent = stats.ecosystems.pypi.toString();
    elements.ecoGems.textContent = stats.ecosystems.gems.toString();
    elements.ecoGo.textContent = stats.ecosystems.go.toString();
    elements.ecoCargo.textContent = stats.ecosystems.cargo.toString();
    elements.ecoPhp.textContent = stats.ecosystems.php.toString();

    this.toggleDataControls(true);
    elements.copySummaryBtn.disabled = !ScanDataModel.hasAnyData(results);
    elements.saveResultsBtn.disabled = !ScanDataModel.hasAnyData(results);
    this.setStatus(scanning ? 'SCANNING...' : (results.partial ? 'PARTIAL RESULTS' : 'SCAN COMPLETE'));

    const allSections = ScanDataModel.buildSections(results);
    const filteredSections = ScanDataModel.filterSections(allSections, state.filters);
    state.visibleSections = filteredSections;

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
        if (item.type === 'file') {
          signatureParts.push(`f:${item.path}:${item.risk}:${item.status}:${item.contentType}`);
          return;
        }
        signatureParts.push(`p:${item.name}:${item.version}:${item.badgeText}:${item.riskLevel}:${item.error || ''}:${item.weeklyDownloads || 0}:${item.maintainers || 0}`);
      });
    });

    const signature = signatureParts.join('|');
    if (state.lastUiSignature === signature) {
      return;
    }
    state.lastUiSignature = signature;

    const totalVisible = ScanDataModel.getTotalItems(filteredSections);
    if (totalVisible === 0) {
      const totalAll = ScanDataModel.getTotalItems(allSections);
      if (totalAll === 0) {
        this.renderEmptyState('No findings detected', 'No suspicious packages or exposed files were identified.');
      } else {
        this.renderNoFilterMatches();
      }
      return;
    }

    let html = '';
    SECTION_ORDER.forEach((sectionKey) => {
      const items = filteredSections[sectionKey] || [];
      if (items.length === 0) return;
      html += this.renderSection(sectionKey, items);
    });

    elements.scanResults.innerHTML = html;
  }

  static renderSection(sectionKey, items) {
    const meta = SECTION_META[sectionKey] || { title: sectionKey, color: '#85a2cc' };

    return `
      <section class="section" data-section="${sectionKey}">
        <div class="section-header">
          <div class="section-title-wrap">
            <h3 class="section-title" style="color:${meta.color}">${meta.title}</h3>
            <span class="section-count" style="color:${meta.color}">${items.length}</span>
          </div>
          <button class="mini-btn" type="button" data-action="copy-section" data-section="${sectionKey}">Copy Section</button>
        </div>
        <div class="item-list">
          ${items.map((item, index) => this.renderItem(sectionKey, item, index)).join('')}
        </div>
      </section>
    `;
  }

  static renderItem(sectionKey, item, index) {
    if (item.type === 'file') {
      return this.renderFileItem(sectionKey, item, index);
    }
    return this.renderPackageItem(sectionKey, item, index);
  }

  static renderPackageItem(sectionKey, item, index) {
    const reasons = item.riskReasons.length > 0
      ? item.riskReasons.map((reason) => `<div class="detail-line">- ${utils.escapeHtml(reason)}</div>`).join('')
      : '<div class="detail-line">- no explicit risk reason provided</div>';

    const shownSources = item.sources.slice(0, 4);
    const sources = shownSources.length > 0
      ? shownSources.map((source) => `<div class="detail-line mono">${utils.escapeHtml(source)}</div>`).join('')
      : '<div class="detail-line mono">source not provided</div>';

    const hiddenCount = Math.max(item.sources.length - shownSources.length, 0);
    const remaining = hiddenCount > 0 ? `<div class="detail-line mono">...and ${hiddenCount} more source locations</div>` : '';

    const versionMeta = item.version ? `v${utils.escapeHtml(item.version)}` : 'version unknown';
    const ecosystemTag = item.ecosystem ? `<span class="tag ecosystem">${utils.escapeHtml(item.ecosystem)}</span>` : '';

    const extraMeta = [];
    if (item.weeklyDownloads) extraMeta.push(`${utils.formatNumber(item.weeklyDownloads)} weekly downloads`);
    if (item.maintainers) extraMeta.push(`${item.maintainers} maintainers`);

    return `
      <article class="finding-card" data-severity="${item.severity}">
        <div class="finding-head">
          <div>
            <h4 class="finding-name">${utils.escapeHtml(item.name)}</h4>
            <p class="finding-meta">${versionMeta}${extraMeta.length > 0 ? ` | ${extraMeta.join(' | ')}` : ''}</p>
          </div>
          <div class="actions-inline">
            ${ecosystemTag}
            <span class="tag ${item.severity}">${utils.escapeHtml(item.badgeText)}</span>
            <button class="mini-btn" type="button" data-action="copy-item" data-section="${sectionKey}" data-index="${index}">Copy</button>
          </div>
        </div>
        <div class="finding-body">
          ${item.error ? `<div class="detail-line">Error: ${utils.escapeHtml(item.error)}</div>` : reasons}
          <div class="detail-line">Sources:</div>
          ${sources}
          ${remaining}
        </div>
      </article>
    `;
  }

  static renderFileItem(sectionKey, item, index) {
    return `
      <article class="finding-card" data-severity="${item.severity}">
        <div class="finding-head">
          <div>
            <h4 class="finding-name">${utils.escapeHtml(item.path)}</h4>
            <p class="finding-meta">Status ${utils.escapeHtml(item.status)} | ${utils.escapeHtml(item.contentType)}</p>
          </div>
          <div class="actions-inline">
            <span class="tag ${item.severity}">${utils.escapeHtml(item.risk)}</span>
            <button class="mini-btn" type="button" data-action="copy-item" data-section="${sectionKey}" data-index="${index}">Copy</button>
          </div>
        </div>
      </article>
    `;
  }
}

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

    const initialLoadingMessage = options.initialLoadingMessage || 'Loading scan status...';
    UIRenderer.renderLoading(initialLoadingMessage);

    const checkStatus = async () => {
      try {
        const response = await this.sendMessage(tabId, { action: 'getScanStatus' });

        if (!response) {
          state.pollAttempts += 1;
          if (state.pollAttempts >= MAX_POLL_ATTEMPTS_WITHOUT_RESPONSE) {
            UIRenderer.renderError('Scanner not responding on this page', 'Try refreshing the page or opening another website.');
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
          UIRenderer.renderResults(response, { scanning: false });
          return true;
        }

        if (response.scanning) {
          if (ScanDataModel.hasAnyData(response)) {
            UIRenderer.renderResults(response, { scanning: true });
          } else {
            UIRenderer.renderLoading('Scan in progress...');
          }
          return false;
        }

        if (ScanDataModel.hasValidPayload(response)) {
          UIRenderer.renderResults(response, { scanning: false });
          return true;
        }

        UIRenderer.renderLoading('Initializing scan...');
        return false;
      } catch (error) {
        const message = String(error && error.message ? error.message : 'Unknown error');
        if (message.includes('Could not establish connection') || message.includes('Receiving end does not exist')) {
          state.pollAttempts += 1;
          if (state.pollAttempts >= MAX_POLL_ATTEMPTS_WITHOUT_RESPONSE) {
            UIRenderer.renderError('Scanner did not initialize in time', 'Refresh the target page, then reopen the extension.');
            return true;
          }
          UIRenderer.renderLoading('Content script not ready. Refresh the page.');
          return false;
        }

        UIRenderer.renderError('Unable to read scan status', message);
        return true;
      }
    };

    const complete = await checkStatus();
    if (complete) return;

    state.pollTimer = setInterval(async () => {
      const done = await checkStatus();
      if (done) {
        this.clearPolling();
      }
    }, 1000);
  },

  async refresh(forceRescan = false) {
    try {
      const tab = await this.getActiveTab();
      if (!tab) {
        this.clearPolling();
        UIRenderer.toggleDataControls(false);
        UIRenderer.setStatus('NO TAB');
        UIRenderer.renderEmptyState('No active tab', 'Open a web page and try again.');
        return;
      }

      state.activeTabId = tab.id;
      UIRenderer.setTargetUrl(tab.url || 'unknown');

      if (this.isRestrictedUrl(tab.url || '')) {
        this.clearPolling();
        UIRenderer.toggleDataControls(false);
        UIRenderer.setStatus('UNSUPPORTED');
        UIRenderer.renderEmptyState('Unsupported page', 'System pages cannot be scanned. Open a regular website.');
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
        initialLoadingMessage: forceRescan ? 'Manual rescan started...' : 'Checking scan status...'
      });
    } catch (error) {
      const message = String(error && error.message ? error.message : 'Unknown error');
      UIRenderer.renderError('Popup refresh failed', message);
    }
  }
};

function updateToggleState(isEnabled) {
  state.extensionEnabled = isEnabled;
  elements.extensionToggle.checked = isEnabled;
  elements.toggleLabel.textContent = isEnabled ? 'ON' : 'OFF';

  if (isEnabled) {
    elements.statusIndicator.classList.add('active');
  } else {
    elements.statusIndicator.classList.remove('active');
    PopupScanManager.clearPolling();
    state.rawResults = null;
    state.visibleSections = { critical: [], high: [], medium: [], low: [], error: [] };
    state.lastUiSignature = '';
    UIRenderer.renderDisabled();
  }
}

function debounce(fn, wait = 150) {
  let timer = null;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), wait);
  };
}

function rerenderFilteredResults() {
  if (!state.rawResults || !ScanDataModel.hasValidPayload(state.rawResults)) return;
  UIRenderer.renderResults(state.rawResults, { scanning: state.lastRenderedScanning });
}

async function copyToClipboard(text, successMessage) {
  const copied = await clipboard.copyText(text);
  if (copied) {
    toast.show(successMessage);
    return;
  }
  toast.show('Copy failed. Try again.', 'error');
}

async function handleCopyItem(sectionKey, index) {
  const items = state.visibleSections[sectionKey] || [];
  const item = items[index];
  if (!item) {
    toast.show('Nothing to copy for this item.', 'error');
    return;
  }

  if (item.type === 'package') {
    await copyToClipboard(item.name, 'Package name copied.');
    return;
  }

  await copyToClipboard(item.path, 'File path copied.');
}

async function handleCopySection(sectionKey) {
  const items = state.visibleSections[sectionKey] || [];
  if (items.length === 0) {
    toast.show('No items in this section.', 'error');
    return;
  }

  await copyToClipboard(ScanDataModel.sectionToCopyText(sectionKey, items), 'Section copied to clipboard.');
}

async function handleCopySummary() {
  if (!state.rawResults || !ScanDataModel.hasValidPayload(state.rawResults)) {
    toast.show('No scan summary available.', 'error');
    return;
  }

  await copyToClipboard(ScanDataModel.summaryToCopyText(state.rawResults), 'Summary copied to clipboard.');
}

async function getLatestResults() {
  if (state.rawResults && ScanDataModel.hasValidPayload(state.rawResults)) {
    return state.rawResults;
  }

  if (!state.activeTabId) return null;

  try {
    const response = await chrome.tabs.sendMessage(state.activeTabId, { action: 'getScanStatus' });
    if (ScanDataModel.hasValidPayload(response)) {
      return response;
    }
  } catch {
    return null;
  }

  return null;
}

async function handleSaveResults() {
  const data = await getLatestResults();
  if (!data || !ScanDataModel.hasValidPayload(data)) {
    toast.show('No results available to save.', 'error');
    return;
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `npm-scan-results-${timestamp}.html`;
  const htmlContent = generateHtmlReport(data);

  const blob = new Blob([htmlContent], { type: 'text/html' });
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);

  toast.show('Report downloaded.');
}

function bindEventListeners() {
  elements.extensionToggle.addEventListener('change', async (event) => {
    const isEnabled = Boolean(event.target.checked);

    await chrome.storage.local.set({ extensionEnabled: isEnabled });
    updateToggleState(isEnabled);

    try {
      const tab = await PopupScanManager.getActiveTab();
      if (tab?.id) {
        await chrome.tabs.sendMessage(tab.id, {
          action: 'toggleExtension',
          enabled: isEnabled
        });
      }
    } catch {
      // content script may not be available on current tab
    }

    if (isEnabled) {
      await PopupScanManager.refresh(false);
    }
  });

  elements.rescanBtn.addEventListener('click', async () => {
    if (!state.extensionEnabled) {
      toast.show('Turn extension ON before rescanning.', 'error');
      return;
    }

    await PopupScanManager.refresh(true);
  });

  elements.copySummaryBtn.addEventListener('click', handleCopySummary);
  elements.saveResultsBtn.addEventListener('click', handleSaveResults);

  const debouncedSearch = debounce((value) => {
    state.filters.search = value;
    rerenderFilteredResults();
  }, 120);

  elements.searchInput.addEventListener('input', (event) => {
    debouncedSearch(String(event.target.value || ''));
  });

  elements.severityFilter.addEventListener('change', (event) => {
    state.filters.severity = String(event.target.value || 'ALL').toUpperCase();
    rerenderFilteredResults();
  });

  elements.scanResults.addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button) return;

    const action = button.getAttribute('data-action');
    const section = button.getAttribute('data-section') || '';

    if (action === 'copy-item') {
      const index = Number(button.getAttribute('data-index') || '-1');
      if (Number.isInteger(index) && index >= 0) {
        await handleCopyItem(section, index);
      }
      return;
    }

    if (action === 'copy-section') {
      await handleCopySection(section);
    }
  });
}

function generateHtmlReport(data) {
  const stats = ScanDataModel.calculateStats(data);
  const sections = ScanDataModel.buildSections(data);
  const generatedAt = new Date().toLocaleString();

  const escape = (value) => {
    const div = document.createElement('div');
    div.textContent = value == null ? '' : String(value);
    return div.innerHTML;
  };

  const sectionMarkup = SECTION_ORDER.map((key) => {
    const items = sections[key] || [];
    if (items.length === 0) return '';

    const meta = SECTION_META[key];
    const listItems = items.map((item) => {
      if (item.type === 'file') {
        return `<li><strong>${escape(item.path)}</strong> | ${escape(item.risk)} | ${escape(item.status)} | ${escape(item.contentType)}</li>`;
      }

      return `<li><strong>${escape(item.name)}${item.version ? `@${escape(item.version)}` : ''}</strong> [${escape(item.badgeText)}]</li>`;
    }).join('');

    return `
      <section style="margin-top:16px;">
        <h3 style="margin:0 0 8px;color:${meta.color};">${meta.title} (${items.length})</h3>
        <ul style="margin:0;padding-left:20px;line-height:1.6;">${listItems}</ul>
      </section>
    `;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NPM Security Scanner Report</title>
  <style>
    body { margin: 0; padding: 24px; font-family: "Space Grotesk", sans-serif; color: #e8f2ff; background: #08111d; }
    .container { max-width: 980px; margin: 0 auto; border: 1px solid #35517a; border-radius: 12px; padding: 24px; background: #0c1729; }
    .meta { color: #9db6d8; font-size: 13px; }
    .stats { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin: 16px 0; }
    .card { border: 1px solid #35517a; border-radius: 10px; padding: 10px; background: #13243d; }
    .value { margin: 0; font-size: 26px; font-weight: 700; }
    .label { margin: 4px 0 0; font-size: 11px; text-transform: uppercase; color: #9db6d8; }
  </style>
</head>
<body>
  <div class="container">
    <h1 style="margin:0;">NPM Security Scanner Report</h1>
    <p class="meta">Generated: ${escape(generatedAt)}</p>
    <p class="meta">Target: ${escape(data.url || 'unknown')}</p>

    <div class="stats">
      <div class="card"><p class="value">${stats.totalPackages}</p><p class="label">Packages</p></div>
      <div class="card"><p class="value">${stats.criticalRisks}</p><p class="label">Critical Risks</p></div>
      <div class="card"><p class="value">${stats.exposedFileCount}</p><p class="label">Exposed Files</p></div>
    </div>

    ${sectionMarkup || '<p>No findings detected in this scan.</p>'}
  </div>
</body>
</html>`;
}

document.addEventListener('DOMContentLoaded', async () => {
  document.documentElement.style.width = '560px';
  document.documentElement.style.minWidth = '560px';
  document.body.style.width = '560px';
  document.body.style.minWidth = '560px';

  bindEventListeners();

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

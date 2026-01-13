/**
 * NPM Security Scanner Pro - Popup Script
 * Simplified version - focuses on dependency confusion detection
 */

// ============================================================================
// DOM ELEMENTS
// ============================================================================

const elements = {
  // scanBtn: document.getElementById('scanBtn'), // Removed
  scanStatusText: document.getElementById('scanStatusText'),
  scanResults: document.getElementById('scanResults'),
  statsGrid: document.getElementById('statsGrid'),
  statPackages: document.getElementById('statPackages'),
  statRisks: document.getElementById('statRisks'),
  statRiskCard: document.getElementById('statRiskCard'),
  statusIndicator: document.getElementById('statusIndicator'),
  saveResultsBtn: document.getElementById('saveResultsBtn'),
  actionControls: document.getElementById('actionControls'),
  extensionToggle: document.getElementById('extensionToggle'),
  toggleLabel: document.getElementById('toggleLabel')
};

// ============================================================================
// UTILITIES
// ============================================================================

const utils = {
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
  },

  formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
  },

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
};

// ============================================================================
// UI RENDERER
// ============================================================================

class UIRenderer {
  static renderLoading(message = 'DEEP_CRAWLING_IN_PROGRESS...') {
    elements.statsGrid.style.display = 'none';
    elements.actionControls.style.display = 'none';
    elements.scanResults.innerHTML = `
      <div class="loading-container">
        <div class="terminal-loader">
          > ${message}
        </div>
      </div>
    `;
    elements.scanStatusText.textContent = 'SCANNING...';
    elements.scanStatusText.className = 'scan-status text-high';
  }

  static renderError(message, details = null) {
    elements.statsGrid.style.display = 'none';
    elements.actionControls.style.display = 'none';
    elements.scanResults.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon text-critical">!</div>
        <div class="text-critical">ERROR: ${utils.escapeHtml(message)}</div>
        ${details ? `<div class="text-muted mt-2">${utils.escapeHtml(details)}</div>` : ''}
      </div>
    `;
    elements.scanStatusText.textContent = 'ERROR';
    elements.scanStatusText.className = 'scan-status text-critical';
  }

  static renderEmptyState() {
    elements.statsGrid.style.display = 'none';
    elements.actionControls.style.display = 'none';
    elements.scanResults.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">_</div>
        <div>NO_PACKAGES_DETECTED</div>
        <div class="text-muted mt-2">Target appears clean or obfuscated</div>
      </div>
    `;
    elements.scanStatusText.textContent = 'NO_RESULTS';
    elements.scanStatusText.className = 'scan-status text-muted';
  }

  static updateStats(stats) {
    elements.statsGrid.style.display = 'grid';
    elements.actionControls.style.display = 'block';

    // Animate numbers
    this.animateValue(elements.statPackages, 0, stats.totalPackages, 1000);
    this.animateValue(elements.statRisks, 0, stats.criticalRisks, 1000);

    // Update risk card style
    elements.statRiskCard.className = `stat-card ${stats.criticalRisks > 0 ? 'critical' : 'safe'}`;

    elements.scanStatusText.textContent = 'SCAN_COMPLETE';
    elements.scanStatusText.className = 'scan-status text-safe';
  }

  static animateValue(obj, start, end, duration) {
    let startTimestamp = null;
    const step = (timestamp) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / duration, 1);
      obj.innerHTML = Math.floor(progress * (end - start) + start);
      if (progress < 1) {
        window.requestAnimationFrame(step);
      }
    };
    window.requestAnimationFrame(step);
  }

  static renderResults(results) {
    // Defensive check: ensure results and packages exist
    if (!results || !results.packages || !Array.isArray(results.packages)) {
      this.renderEmptyState();
      return;
    }

    const stats = this.calculateStats(results);
    this.updateStats(stats);

    let html = '';

    // Show Critical Packages (Dependency Confusion) first
    const criticalPackages = results.packages.filter(p => p.isUnregistered);

    if (criticalPackages.length > 0) {
      html += this.renderSection(
        'CRITICAL_THREATS',
        criticalPackages.length,
        criticalPackages.map(pkg => this.renderPackageItem(pkg, 'critical'))
      );
    }

    // Show ALL other packages (safe/registered)
    const safePackages = results.packages.filter(p => !p.isUnregistered && !p.error);

    if (safePackages.length > 0) {
      html += this.renderSection(
        'VERIFIED_PACKAGES',
        safePackages.length,
        safePackages.map(pkg => this.renderPackageItem(pkg, 'safe'))
      );
    }

    // Show packages with errors
    const errorPackages = results.packages.filter(p => p.error);

    if (errorPackages.length > 0) {
      html += this.renderSection(
        'ANALYSIS_ERRORS',
        errorPackages.length,
        errorPackages.map(pkg => this.renderPackageItem(pkg, 'error'))
      );
    }

    // Show Exposed Files
    const exposedFiles = results.exposedFiles || [];
    if (exposedFiles.length > 0) {
      html += this.renderSection(
        'EXPOSED_FILES',
        exposedFiles.length,
        exposedFiles.map(file => this.renderFileItem(file))
      );
    }

    if (!html) {
      html = `
        <div class="empty-state">
          <div class="empty-icon">_</div>
          <div>NO_PACKAGES_DETECTED</div>
        </div>
      `;
    }

    elements.scanResults.innerHTML = html;
  }

  static calculateStats(results) {
    // Defensive check
    const packages = results?.packages || [];
    const exposedFiles = results?.exposedFiles || [];
    const criticalRisks = packages.filter(p => p.isUnregistered).length + exposedFiles.length;

    return {
      totalPackages: packages.length,
      criticalRisks
    };
  }

  static renderSection(title, count, items) {
    return `
      <div class="section">
        <div class="section-header">
          <span class="section-title">${title}</span>
          <span class="badge">${count}</span>
        </div>
        <div class="items">
          ${items.join('')}
        </div>
      </div>
    `;
  }

  static renderPackageItem(pkg, severity) {
    const badge = this.getBadge(pkg);
    const sources = pkg.sources || [];

    return `
      <div class="package-item ${severity}">
        <div class="package-header">
          <div>
            <span class="package-name">${utils.escapeHtml(pkg.name)}</span>
            ${pkg.version ? `<span class="package-version">v${utils.escapeHtml(pkg.version)}</span>` : ''}
          </div>
          ${badge}
        </div>
        <div class="package-details">
          ${pkg.riskReasons ? pkg.riskReasons.map(r => `<div class="text-muted">> ${utils.escapeHtml(r)}</div>`).join('') : ''}
          ${pkg.error ? `<div class="text-critical">> Error: ${utils.escapeHtml(pkg.error)}</div>` : ''}
          <div class="text-secondary mt-1">
            <strong>Found in:</strong>
          </div>
          ${sources.slice(0, 3).map(src => `<div class="text-muted source-path">> ${utils.escapeHtml(src)}</div>`).join('')}
          ${sources.length > 3 ? `<div class="text-muted">... and ${sources.length - 3} more locations</div>` : ''}
        </div>
      </div>
    `;
  }

  static getBadge(pkg) {
    if (pkg.isUnregistered) return '<span class="badge critical">UNREGISTERED</span>';
    if (pkg.error) return '<span class="badge critical">ERROR</span>';
    return '<span class="badge safe">OK</span>';
  }

  static getPackageMeta(pkg) {
    const items = [];
    if (pkg.weeklyDownloads) items.push(`${utils.formatNumber(pkg.weeklyDownloads)} dl/wk`);
    if (pkg.maintainers) items.push(`${pkg.maintainers} maintainers`);
    return items.length ? `<div class="mb-1">${items.join(' | ')}</div>` : '';
  }
  static renderFileItem(file) {
    const severity = file.risk === 'HIGH' ? 'critical' : 'warning';
    return `
      <div class="package-item ${severity}">
        <div class="package-header">
          <div>
            <span class="package-name">${utils.escapeHtml(file.path)}</span>
            <span class="package-version">${utils.escapeHtml(file.status)}</span>
          </div>
          <span class="badge ${severity}">${utils.escapeHtml(file.risk)}</span>
        </div>
        <div class="package-details">
          <div class="text-muted">Content-Type: ${utils.escapeHtml(file.contentType)}</div>
        </div>
      </div>
    `;
  }
}

// ============================================================================
// SCAN MANAGER
// ============================================================================

class PopupScanManager {
  static async performScan(forceRescan = false) {
    elements.scanBtn.disabled = true;

    // Don't show loading if we're checking for cached results
    if (forceRescan) {
      UIRenderer.renderLoading();
    }

    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tabs[0]) throw new Error('No active tab found');

      const tab = tabs[0];
      if (tab.url.startsWith('chrome://')) throw new Error('Cannot scan system pages');

      // First, try to get cached results
      // If forceRescan is false (default), we ALWAYS try to show cached data first
      if (!forceRescan) {
        try {
          const cachedResponse = await chrome.tabs.sendMessage(tab.id, { action: 'getLastResults' });

          // If we have valid results, show them and STOP
          if (cachedResponse && cachedResponse.packages && cachedResponse.packages.length > 0) {
            UIRenderer.renderResults(cachedResponse);
            elements.scanBtn.disabled = false;
            return;
          }

          // If a scan is currently running, show loading and STOP
          if (cachedResponse && cachedResponse.scanning) {
            UIRenderer.renderLoading('SCAN_IN_PROGRESS...');
            elements.scanBtn.disabled = false;
            return;
          }
        } catch (e) {
          // No cached results or content script not ready
        }
      }

      // Show loading for new scan
      UIRenderer.renderLoading();

      // Add artificial delay for "hacking" effect
      await utils.delay(800);

      const response = await chrome.tabs.sendMessage(tab.id, { action: 'scan' });

      if (!response) {
        throw new Error('Content script not loaded. Try refreshing the page.');
      }

      if (response.error) {
        throw new Error(response.error);
      }

      // Check if scan is still in progress (backward compatibility)
      if (response.scanning) {
        UIRenderer.renderLoading('SCAN_IN_PROGRESS...');
        return;
      }

      // Ensure response has valid structure
      if (!response.packages) {
        throw new Error('Invalid response from content script');
      }

      UIRenderer.renderResults(response);
    } catch (error) {
      console.error('Scan error:', error);

      // Provide more helpful error messages
      let errorMessage = error.message;
      if (error.message.includes('Could not establish connection')) {
        errorMessage = 'Content script not loaded. Please refresh the page and try again.';
      } else if (error.message.includes('Receiving end does not exist')) {
        errorMessage = 'Extension not ready. Please refresh the page.';
      }

      UIRenderer.renderError(errorMessage);
    } finally {
      elements.scanBtn.disabled = false;
    }
  }
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================

// Scan Button - force a new scan (Removed)
// elements.scanBtn.addEventListener('click', () => {
//   PopupScanManager.performScan(true);
// });

// Save Results Button
if (elements.saveResultsBtn) {
  elements.saveResultsBtn.addEventListener('click', async () => {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tabs[0]) return;

      const response = await chrome.tabs.sendMessage(tabs[0].id, { action: 'getScanStatus' });

      if (response && response.packages) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `npm-scan-results-${timestamp}.html`;

        const htmlContent = generateHtmlReport(response);

        const blob = new Blob([htmlContent], { type: 'text/html' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error('Failed to save results:', error);
    }
  });
}

// Toggle Switch
if (elements.extensionToggle) {
  // Load saved state
  chrome.storage.local.get(['extensionEnabled'], (result) => {
    const isEnabled = result.extensionEnabled !== false; // default to true
    elements.extensionToggle.checked = isEnabled;
    elements.toggleLabel.textContent = isEnabled ? 'ON' : 'OFF';
    updateToggleState(isEnabled);
  });

  elements.extensionToggle.addEventListener('change', async (e) => {
    const isEnabled = e.target.checked;
    elements.toggleLabel.textContent = isEnabled ? 'ON' : 'OFF';

    // Save state
    await chrome.storage.local.set({ extensionEnabled: isEnabled });

    // Update visual state
    updateToggleState(isEnabled);

    // Notify content script
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, {
          action: 'toggleExtension',
          enabled: isEnabled
        });
      }
    } catch (error) {
      console.debug('Could not notify content script:', error);
    }
  });
}

function updateToggleState(isEnabled) {
  if (isEnabled) {
    elements.statusIndicator.classList.add('active');
    // Don't clear results when enabling - they'll be loaded/scanned
  } else {
    elements.statusIndicator.classList.remove('active');
    // Show that extension is disabled
    UIRenderer.renderEmptyState();
    elements.statsGrid.style.display = 'none';
    elements.actionControls.style.display = 'none';

    // Update scan results to show disabled state
    elements.scanResults.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon text-muted">⏸</div>
        <div>EXTENSION_DISABLED</div>
        <div class="text-muted mt-2">Toggle ON to start scanning</div>
      </div>
    `;
  }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  // Auto-fetch results on open
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs[0] && !tabs[0].url.startsWith('chrome://')) {

      const checkStatus = async () => {
        try {
          const response = await chrome.tabs.sendMessage(tabs[0].id, { action: 'getScanStatus' });

          if (response) {
            if (response.complete) {
              UIRenderer.renderResults(response);
              return true; // Done
            } else if (response.scanning) {
              UIRenderer.renderLoading('SCAN_IN_PROGRESS...');
              return false; // Keep polling
            } else if (response.error) {
              UIRenderer.renderError(response.error);
              return true; // Done (error)
            }
          } else {
            // Response is undefined - likely old content script
            UIRenderer.renderLoading('PLEASE_REFRESH_PAGE...');
            return false;
          }
        } catch (e) {
          // Content script might not be ready yet
          UIRenderer.renderLoading('INITIALIZING...');
          return false;
        }
        return false;
      };

      // Initial check
      if (!await checkStatus()) {
        // Poll every 1s
        const interval = setInterval(async () => {
          if (await checkStatus()) {
            clearInterval(interval);
          }
        }, 1000);
      }

    } else {
      UIRenderer.renderEmptyState();
    }
  } catch (error) {
    console.debug('Could not load results:', error);
    UIRenderer.renderEmptyState();
  }
});

function generateHtmlReport(data) {
  const stats = UIRenderer.calculateStats(data);
  const date = new Date().toLocaleString();

  const criticalPackages = data.packages.filter(p => p.isUnregistered);
  const safePackages = data.packages.filter(p => !p.isUnregistered && !p.error);
  const errorPackages = data.packages.filter(p => p.error);
  const exposedFiles = data.exposedFiles || [];

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NPM Security Scan Report</title>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-primary: #0d1117;
      --bg-secondary: #000000;
      --text-primary: #00ff41;
      --text-secondary: #00cc33;
      --text-muted: #005511;
      --accent-primary: #00ff41;
      --critical: #ff0033;
      --high: #ff6600;
      --medium: #ffcc00;
      --safe: #00ff41;
      --border-color: #004411;
    }

    body {
      background-color: var(--bg-primary);
      color: var(--text-primary);
      font-family: 'JetBrains Mono', monospace;
      margin: 0;
      padding: 40px;
      line-height: 1.6;
    }

    .container {
      max-width: 1000px;
      margin: 0 auto;
      border: 1px solid var(--border-color);
      padding: 40px;
      background: var(--bg-secondary);
      box-shadow: 0 0 20px rgba(0, 255, 65, 0.1);
    }

    header {
      border-bottom: 2px solid var(--border-color);
      padding-bottom: 20px;
      margin-bottom: 40px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }

    h1 {
      margin: 0;
      font-size: 24px;
      text-transform: uppercase;
      letter-spacing: 2px;
      text-shadow: 0 0 10px rgba(0, 255, 65, 0.4);
    }

    .meta {
      color: var(--text-secondary);
      font-size: 14px;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 40px;
    }

    .stat-card {
      background: rgba(0, 20, 0, 0.3);
      border: 1px solid var(--border-color);
      padding: 20px;
      text-align: center;
    }

    .stat-value {
      font-size: 36px;
      font-weight: bold;
      margin-bottom: 5px;
    }

    .stat-label {
      font-size: 12px;
      text-transform: uppercase;
      color: var(--text-secondary);
      letter-spacing: 1px;
    }

    .section {
      margin-bottom: 40px;
    }

    .section-title {
      font-size: 18px;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 10px;
      margin-bottom: 20px;
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .badge {
      font-size: 12px;
      padding: 2px 8px;
      border: 1px solid currentColor;
      border-radius: 4px;
    }

    .item {
      border: 1px solid var(--border-color);
      margin-bottom: 15px;
      background: rgba(0, 20, 0, 0.2);
      transition: transform 0.2s;
    }

    .item:hover {
      transform: translateX(5px);
      border-color: var(--accent-primary);
    }

    .item-header {
      padding: 15px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(0, 0, 0, 0.2);
    }

    .item-name {
      font-weight: bold;
      font-size: 16px;
    }

    .item-details {
      padding: 15px;
      border-top: 1px solid var(--border-color);
      font-size: 14px;
      color: var(--text-secondary);
    }

    .text-critical { color: var(--critical); }
    .text-high { color: var(--high); }
    .text-safe { color: var(--safe); }
    .text-muted { color: var(--text-muted); }

    .critical-border { border-left: 4px solid var(--critical); }
    .safe-border { border-left: 4px solid var(--safe); }
    .warning-border { border-left: 4px solid var(--medium); }

    .source-path {
      font-family: monospace;
      margin-top: 5px;
      color: var(--text-muted);
      word-break: break-all;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>NPM Security Scan Report</h1>
        <div style="margin-top: 10px; color: var(--text-secondary);">Target: ${data.url || 'Unknown'}</div>
      </div>
      <div class="meta">Generated: ${date}</div>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value">${stats.totalPackages}</div>
        <div class="stat-label">Total Packages</div>
      </div>
      <div class="stat-card" style="${stats.criticalRisks > 0 ? 'border-color: var(--critical); box-shadow: 0 0 10px rgba(255, 0, 51, 0.2);' : ''}">
        <div class="stat-value" style="color: ${stats.criticalRisks > 0 ? 'var(--critical)' : 'var(--safe)'}">${stats.criticalRisks}</div>
        <div class="stat-label">Critical Risks</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${exposedFiles.length}</div>
        <div class="stat-label">Exposed Files</div>
      </div>
    </div>

    ${criticalPackages.length > 0 ? `
      <div class="section">
        <div class="section-title">
          <span class="text-critical">⚠️ CRITICAL THREATS</span>
          <span class="badge" style="color: var(--critical); border-color: var(--critical)">${criticalPackages.length}</span>
        </div>
        ${criticalPackages.map(pkg => `
          <div class="item critical-border">
            <div class="item-header">
              <div>
                <span class="item-name text-critical">${utils.escapeHtml(pkg.name)}</span>
                <span style="color: var(--text-muted)">v${utils.escapeHtml(pkg.version || '?')}</span>
              </div>
              <span class="badge" style="color: var(--critical); border-color: var(--critical)">UNREGISTERED</span>
            </div>
            <div class="item-details">
              ${pkg.riskReasons ? pkg.riskReasons.map(r => `<div class="text-critical">> ${utils.escapeHtml(r)}</div>`).join('') : ''}
              <div style="margin-top: 10px; font-weight: bold; color: var(--text-secondary)">Found in:</div>
              ${(pkg.sources || []).map(src => `<div class="source-path">> ${utils.escapeHtml(src)}</div>`).join('')}
            </div>
          </div>
        `).join('')}
      </div>
    ` : ''}

    ${exposedFiles.length > 0 ? `
      <div class="section">
        <div class="section-title">
          <span class="text-high">🔓 EXPOSED FILES</span>
          <span class="badge" style="color: var(--high); border-color: var(--high)">${exposedFiles.length}</span>
        </div>
        ${exposedFiles.map(file => `
          <div class="item warning-border">
            <div class="item-header">
              <span class="item-name text-high">${utils.escapeHtml(file.path)}</span>
              <span class="badge" style="color: var(--high); border-color: var(--high)">${utils.escapeHtml(file.risk)}</span>
            </div>
            <div class="item-details">
              <div>Status: ${utils.escapeHtml(file.status)}</div>
              <div>Type: ${utils.escapeHtml(file.contentType)}</div>
            </div>
          </div>
        `).join('')}
      </div>
    ` : ''}

    ${safePackages.length > 0 ? `
      <div class="section">
        <div class="section-title">
          <span class="text-safe">✓ VERIFIED PACKAGES</span>
          <span class="badge" style="color: var(--safe); border-color: var(--safe)">${safePackages.length}</span>
        </div>
        ${safePackages.map(pkg => `
          <div class="item safe-border">
            <div class="item-header">
              <div>
                <span class="item-name text-safe">${utils.escapeHtml(pkg.name)}</span>
                <span style="color: var(--text-muted)">v${utils.escapeHtml(pkg.version || '?')}</span>
              </div>
              <span class="badge" style="color: var(--safe); border-color: var(--safe)">OK</span>
            </div>
            <div class="item-details">
              ${pkg.weeklyDownloads ? `<div>Downloads: ${utils.formatNumber(pkg.weeklyDownloads)}/wk</div>` : ''}
              <div style="margin-top: 5px; color: var(--text-muted)">Found in:</div>
              ${(pkg.sources || []).map(src => `<div class="source-path">> ${utils.escapeHtml(src)}</div>`).join('')}
            </div>
          </div>
        `).join('')}
      </div>
    ` : ''}
    
    <div style="text-align: center; margin-top: 60px; color: var(--text-muted); font-size: 12px;">
      Generated by NPM Security Scanner Pro<br>
      Made by <a href="https://bugcrowd.com/h/Bytes_Knight" target="_blank" style="color: var(--accent-primary); text-decoration: none;">@Bytes_Knight</a>
      | <a href="https://github.com/bytes-Knight" target="_blank" style="color: var(--accent-primary); text-decoration: none;" title="GitHub">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" style="vertical-align: middle;">
          <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
        </svg>
      </a>
    </div>
  </div>
</body>
</html>`;
}
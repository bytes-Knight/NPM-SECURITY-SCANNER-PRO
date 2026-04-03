/**
 * NPM Security Scanner Pro - Background Service Worker
 * Handles notifications, badge management, and cross-tab communication
 */

// ============================================================================
// STATE MANAGEMENT
// ============================================================================

class BackgroundState {
  constructor() {
    this.tabResults = new Map();
    this.scanTimestamps = new Map();
    this.notificationIds = new Map();
  }

  setTabResult(tabId, result) {
    this.tabResults.set(tabId, {
      ...result,
      timestamp: Date.now()
    });
  }

  getTabResult(tabId) {
    return this.tabResults.get(tabId);
  }

  removeTab(tabId) {
    this.tabResults.delete(tabId);
    this.scanTimestamps.delete(tabId);
    this.notificationIds.delete(tabId);
  }

  canScan(tabId) {
    const lastScan = this.scanTimestamps.get(tabId);
    if (!lastScan) return true;
    return Date.now() - lastScan > 5000; // 5 second cooldown
  }

  recordScan(tabId) {
    this.scanTimestamps.set(tabId, Date.now());
  }

  cleanup() {
    const now = Date.now();
    const maxAge = 10 * 60 * 1000; // 10 minutes

    for (const [tabId, data] of this.tabResults.entries()) {
      if (now - data.timestamp > maxAge) {
        this.removeTab(tabId);
      }
    }
  }
}

const state = new BackgroundState();
const NETWORK_TIMEOUT_MS = 8000;

// ============================================================================
// BADGE MANAGEMENT
// ============================================================================

class BadgeManager {
  static async updateBadge(tabId, riskCount) {
    try {
      if (riskCount > 0) {
        const color = this.getRiskColor(riskCount);
        const text = riskCount > 99 ? '99+' : riskCount.toString();

        await chrome.action.setBadgeText({ text, tabId });
        await chrome.action.setBadgeBackgroundColor({ color, tabId });
      } else {
        await chrome.action.setBadgeText({ text: '', tabId });
      }
    } catch (error) {
      console.error('Failed to update badge:', error);
    }
  }

  static getRiskColor(count) {
    if (count >= 5) return '#d32f2f'; // Critical - Dark red
    if (count >= 3) return '#f57c00'; // High - Orange
    if (count >= 1) return '#fbc02d'; // Medium - Yellow
    return '#388e3c'; // Safe - Green
  }

  static async clearBadge(tabId) {
    try {
      await chrome.action.setBadgeText({ text: '', tabId });
    } catch (error) {
      console.error('Failed to clear badge:', error);
    }
  }
}

// ============================================================================
// NOTIFICATION MANAGEMENT
// ============================================================================

class NotificationManager {
  static async create(tabId, riskData) {
    // Notifications disabled - return immediately
    return;

    const { critical, high, medium, exposedFiles } = this.categorizeRisks(riskData);

    if (critical.length === 0 && high.length === 0 && medium.length === 0 && exposedFiles.length === 0) {
      return;
    }

    const notificationId = `npm-security-${tabId}-${Date.now()}`;
    const message = this.buildMessage(critical, high, medium, exposedFiles);
    const priority = critical.length > 0 ? 2 : high.length > 0 ? 1 : 0;

    try {
      await chrome.notifications.create(notificationId, {
        type: 'basic',
        iconUrl: 'icon128.png',
        title: this.getTitle(critical, high),
        message,
        priority,
        requireInteraction: critical.length > 0
      });

      state.notificationIds.set(tabId, notificationId);
    } catch (error) {
      console.error('Failed to create notification:', error);
    }
  }

  static categorizeRisks(riskData) {
    const critical = [];
    const high = [];
    const medium = [];
    const exposedFiles = riskData.exposedFiles || [];

    (riskData.suspiciousPackages || []).forEach(pkg => {
      if (pkg.isUnregistered) {
        critical.push(pkg);
      } else if (pkg.riskLevel === 'HIGH') {
        high.push(pkg);
      } else if (pkg.riskLevel === 'MEDIUM') {
        medium.push(pkg);
      }
    });

    return { critical, high, medium, exposedFiles };
  }

  static getTitle(critical, high) {
    if (critical.length > 0) {
      return '🚨 CRITICAL: Dependency Confusion Detected!';
    }
    if (high.length > 0) {
      return '⚠️ HIGH RISK: Security Threats Found';
    }
    return '⚠️ Security Risks Detected';
  }

  static buildMessage(critical, high, medium, exposedFiles) {
    const parts = [];

    if (critical.length > 0) {
      parts.push(`🚨 ${critical.length} UNREGISTERED package${critical.length > 1 ? 's' : ''} (Dependency Confusion)`);
    }
    if (high.length > 0) {
      parts.push(`⚠️ ${high.length} HIGH RISK package${high.length > 1 ? 's' : ''}`);
    }
    if (medium.length > 0) {
      parts.push(`⚠️ ${medium.length} MEDIUM RISK package${medium.length > 1 ? 's' : ''}`);
    }
    if (exposedFiles.length > 0) {
      const criticalFiles = exposedFiles.filter(f => f.risk === 'HIGH');
      if (criticalFiles.length > 0) {
        parts.push(`🔓 ${exposedFiles.length} sensitive file${exposedFiles.length > 1 ? 's' : ''} exposed (${criticalFiles.length} critical)`);
      } else {
        parts.push(`🔓 ${exposedFiles.length} file${exposedFiles.length > 1 ? 's' : ''} exposed`);
      }
    }

    return parts.join('\n');
  }

  static async clear(tabId) {
    const notificationId = state.notificationIds.get(tabId);
    if (notificationId) {
      try {
        await chrome.notifications.clear(notificationId);
      } catch (error) {
        console.error('Failed to clear notification:', error);
      }
    }
  }
}

// ============================================================================
// MESSAGE HANDLERS
// ============================================================================

class MessageHandler {
  static async fetchWithTimeout(url, options = {}) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), NETWORK_TIMEOUT_MS);

    try {
      return await fetch(url, {
        ...options,
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeoutId);
    }
  }

  static async handleNotifyRisks(request, sender) {
    if (!sender.tab?.id) {
      console.error('No tab ID in sender');
      return { success: false, error: 'No tab ID' };
    }

    const tabId = sender.tab.id;
    const { suspiciousPackages = [], exposedFiles = [] } = request;

    // Store results
    state.setTabResult(tabId, { suspiciousPackages, exposedFiles });

    // Update badge
    const totalRisks = suspiciousPackages.length + exposedFiles.length;
    await BadgeManager.updateBadge(tabId, totalRisks);

    // Create notification
    await NotificationManager.create(tabId, { suspiciousPackages, exposedFiles });

    return { success: true, totalRisks };
  }

  static async handleGetResults(request) {
    const { tabId } = request;
    const result = state.getTabResult(tabId);
    return result || { packages: [], exposedFiles: [] };
  }

  static async handleCanScan(request) {
    const { tabId } = request;
    return { canScan: state.canScan(tabId) };
  }

  static async handleRecordScan(request) {
    const { tabId } = request;
    state.recordScan(tabId);
    return { success: true };
  }

  static async handleGetSettings() {
    try {
      const settings = await chrome.storage.sync.get({
        autoScan: true,
        deepCrawl: true,
        notifications: true,
        showAllRisks: false,
        minDownloads: 100,
        dayThreshold: 90
      });
      return settings;
    } catch (error) {
      console.error('Failed to get settings:', error);
      return {
        autoScan: true,
        deepCrawl: true,
        notifications: true,
        showAllRisks: false,
        minDownloads: 100,
        dayThreshold: 90
      };
    }
  }

  static async handleSaveSettings(request) {
    try {
      const { settings } = request;
      const oldSettings = await chrome.storage.sync.get({ autoScan: true });

      await chrome.storage.sync.set(settings);

      // If auto-scan was disabled, clear all badges
      if (settings.autoScan === false) {
        const tabs = await chrome.tabs.query({});
        for (const tab of tabs) {
          await BadgeManager.clearBadge(tab.id);
        }
      }

      // If auto-scan was enabled (and it was previously off), notify content scripts
      // Broadcast disabled to prevent unwanted auto-scans
      /*
      if (settings.autoScan === true && oldSettings.autoScan === false) {
        const tabs = await chrome.tabs.query({});
        for (const tab of tabs) {
          try {
            await chrome.tabs.sendMessage(tab.id, {
              action: 'settingsChanged',
              settings
            });
          } catch (error) {
            // Content script might not be loaded on this tab
            console.debug('Could not notify tab:', tab.id);
          }
        }
      }
      */

      return { success: true };
    } catch (error) {
      console.error('Failed to save settings:', error);
      return { success: false, error: error.message };
    }
  }

  static async handleAnalyzePackage(request) {
    const { name, sources, ecosystem = 'npm' } = request;

    try {
      if (ecosystem === 'npm') {
        return await MessageHandler.analyzeNpm(name, sources);
      }

      return await MessageHandler.analyzeGeneric(ecosystem, name, sources);

    } catch (e) {
      return { name, error: e.message, sources };
    }
  }

  static registryCache = new Map();
  static registryCacheTtl = 5 * 60 * 1000;

  static getCacheKey(ecosystem, name) {
    return `${ecosystem}:${name}`;
  }

  static getCached(ecosystem, name) {
    const key = this.getCacheKey(ecosystem, name);
    const entry = this.registryCache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.timestamp > this.registryCacheTtl) {
      this.registryCache.delete(key);
      return null;
    }
    return entry.value;
  }

  static setCached(ecosystem, name, value) {
    const key = this.getCacheKey(ecosystem, name);
    this.registryCache.set(key, { value, timestamp: Date.now() });
  }

  static async analyzeNpm(name, sources) {
    const normalized = String(name || '').trim().toLowerCase();
    if (!normalized) return { name, error: 'Invalid package name', sources };

    const cached = this.getCached('npm', normalized);
    if (cached) {
      return { ...cached, sources };
    }

    const res = await this.fetchWithTimeout(`https://registry.npmjs.org/${normalized}`);

    if (res.status === 404) {
      const result = {
        name: normalized,
        suspicious: true,
        isUnregistered: true,
        riskLevel: 'CRITICAL',
        riskReasons: ['Package not found on npmjs.org - potential dependency confusion'],
        sources
      };
      this.setCached('npm', normalized, result);
      return result;
    }

    if (res.status === 429) {
      return { name: normalized, error: 'Rate Limit Exceeded (429)', sources };
    }

    if (!res.ok) {
      return { name: normalized, error: `Registry Error (${res.status})`, sources };
    }

    const info = await res.json();

    // Fetch Downloads
    let downloads = 0;
    try {
      const dlRes = await this.fetchWithTimeout(`https://api.npmjs.org/downloads/point/last-week/${normalized}`);
      if (dlRes.ok) {
        const dlData = await dlRes.json();
        downloads = dlData.downloads;
      }
    } catch (e) { /* ignore download fetch error */ }

    // Assess Risk
    const reasons = [];
    let suspicious = false;
    let level = 'LOW';

    const MIN_DOWNLOADS_SUSPICIOUS = 100;
    const LEVEL_RANK = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
    const bumpLevel = (next) => {
      if (LEVEL_RANK[next] > LEVEL_RANK[level]) level = next;
    };

    if (downloads < MIN_DOWNLOADS_SUSPICIOUS && !info.repository) {
      suspicious = true;
      bumpLevel('HIGH');
      reasons.push('Low downloads + No Repo');
    }

    // Typosquatting-ish patterns. Keep this conservative to reduce false positives.
    const nameForHeuristics = String(info.name || normalized);
    const hasLongNumber = /[0-9]{3,}/.test(nameForHeuristics);
    // Confusable digit patterns like l0/10/i0/1o, not normal "io" or "lo" sequences.
    const hasDigitConfusable = /(?:l0|10|i0|1o|0l|0i|o0|0o)/.test(nameForHeuristics);
    if (hasLongNumber || hasDigitConfusable) {
      suspicious = true;
      bumpLevel('MEDIUM');
      reasons.push('Suspicious name pattern');
    }

    const result = {
      name: normalized,
      version: info['dist-tags']?.latest || '?',
      weeklyDownloads: downloads,
      suspicious,
      riskLevel: suspicious ? level : 'LOW',
      riskReasons: reasons,
      sources
    };
    this.setCached('npm', normalized, result);
    return result;
  }

  static async analyzeGeneric(ecosystem, name, sources) {
    const cached = this.getCached(ecosystem, name);
    if (cached) {
      return { ...cached, sources };
    }

    const exists = await this.checkRegistryExists(ecosystem, name);
    if (!exists) {
      const result = {
        name,
        suspicious: true,
        isUnregistered: true,
        riskLevel: 'CRITICAL',
        riskReasons: [`Package not found on public ${ecosystem} registry - potential dependency confusion`],
        sources
      };
      this.setCached(ecosystem, name, result);
      return result;
    }

    const result = {
      name,
      suspicious: false,
      isUnregistered: false,
      riskLevel: 'LOW',
      riskReasons: [],
      sources
    };
    this.setCached(ecosystem, name, result);
    return result;
  }

  static async checkRegistryExists(ecosystem, name) {
    try {
      switch (ecosystem) {
        case 'pypi': {
          const res = await this.fetchWithTimeout(`https://pypi.org/pypi/${name}/json`);
          return res.ok;
        }
        case 'rubygems': {
          const res = await this.fetchWithTimeout(`https://rubygems.org/api/v1/gems/${name}.json`);
          return res.ok;
        }
        case 'nuget': {
          const normalized = name.toLowerCase();
          const res = await this.fetchWithTimeout(`https://api.nuget.org/v3-flatcontainer/${normalized}/index.json`);
          return res.ok;
        }
        case 'maven': {
          if (!name.includes(':')) return false;
          const [groupId, artifactId] = name.split(':', 2);
          const query = `g:"${groupId}" AND a:"${artifactId}"`;
          const url = `https://search.maven.org/solrsearch/select?q=${encodeURIComponent(query)}&rows=1&wt=json`;
          const res = await this.fetchWithTimeout(url);
          if (!res.ok) return false;
          const data = await res.json();
          return (data.response && data.response.numFound > 0);
        }
        case 'composer': {
          const res = await this.fetchWithTimeout(`https://repo.packagist.org/p2/${name}.json`);
          return res.ok;
        }
        case 'golang': {
          const encoded = encodeURIComponent(name).replace(/%2F/g, '/');
          const res = await this.fetchWithTimeout(`https://proxy.golang.org/${encoded}/@v/list`);
          return res.ok;
        }
        case 'crates': {
          const res = await this.fetchWithTimeout(`https://crates.io/api/v1/crates/${name}`);
          return res.ok;
        }
        default:
          return false;
      }
    } catch (e) {
      return true;
    }
  }
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const handlers = {
    notifyRisks: MessageHandler.handleNotifyRisks,
    getResults: MessageHandler.handleGetResults,
    canScan: MessageHandler.handleCanScan,
    recordScan: MessageHandler.handleRecordScan,
    getSettings: MessageHandler.handleGetSettings,
    saveSettings: MessageHandler.handleSaveSettings,
    analyzePackage: MessageHandler.handleAnalyzePackage
  };

  const handler = handlers[request.action];
  if (handler) {
    handler(request, sender)
      .then(response => sendResponse(response))
      .catch(error => {
        console.error(`Error in ${request.action}:`, error);
        sendResponse({ success: false, error: error.message });
      });
    return true; // Keep channel open
  }

  return false;
});

// Notification click handler
chrome.notifications.onClicked.addListener(async (notificationId) => {
  const match = notificationId.match(/npm-security-(\d+)/);
  if (match) {
    const tabId = parseInt(match[1]);
    try {
      const tab = await chrome.tabs.get(tabId);
      await chrome.tabs.update(tabId, { active: true });
      await chrome.windows.update(tab.windowId, { focused: true });
    } catch (error) {
      console.warn('Tab no longer exists:', error);
    }
  }
});

// Tab removed handler
chrome.tabs.onRemoved.addListener(async (tabId) => {
  await BadgeManager.clearBadge(tabId);
  await NotificationManager.clear(tabId);
  state.removeTab(tabId);
});

// Tab updated handler
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    await BadgeManager.clearBadge(tabId);
    await NotificationManager.clear(tabId);
    state.removeTab(tabId);
  }
});

// Periodic cleanup
setInterval(() => {
  state.cleanup();
}, 60000); // Run every minute

// ============================================================================
// INITIALIZATION
// ============================================================================

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    console.log('NPM Security Scanner Pro installed');

    // Set default settings
    await chrome.storage.sync.set({
      autoScan: true,
      deepCrawl: true,
      notifications: true,
      showAllRisks: false,
      minDownloads: 100,
      dayThreshold: 90
    });
  }
});

console.log('NPM Security Scanner Pro - Background service worker initialized');

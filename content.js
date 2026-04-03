/**
 * NPM Security Scanner Pro - Content Script (Full Crawler Edition)
 * Performs comprehensive security analysis with deep crawling
 */

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
  API_RATE_LIMIT: 50,
  API_WINDOW: 60000,
  SCAN_COOLDOWN: 5000,
  CACHE_DURATION: 300000, // 5 minutes
  MIN_DOWNLOADS_SUSPICIOUS: 100,
  MIN_DOWNLOADS_NEW: 1000,
  NEW_PACKAGE_DAYS: 90,
  ABANDONED_DAYS: 365,

  // Crawler settings
  MAX_CRAWL_DEPTH: 3,
  MAX_FILES_PER_TYPE: 50,
  MAX_CONCURRENT_REQUESTS: 10, // For crawling
  MAX_CONCURRENT_SCANS: 5,     // For directory brute-forcing
  REQUEST_TIMEOUT: 8000,

  // File patterns to search for
  SCRIPT_PATTERNS: [
    '*.js', '*.mjs', '*.jsx', '*.ts', '*.tsx',
    'bundle.*.js', 'vendor.*.js', 'main.*.js', 'app.*.js', 'chunk.*.js'
  ],

  // Common directories to check
  COMMON_DIRS: [
    '/static/js/', '/static/scripts/', '/assets/js/', '/assets/scripts/',
    '/js/', '/scripts/', '/dist/', '/build/', '/out/',
    '/_next/static/', '/_nuxt/', '/webpack/',
    '/.next/', '/public/', '/lib/', '/src/'
  ],

  // Configuration files to check (Expanded)
  CONFIG_FILES: [
    // Node/NPM
    '/package.json',
    '/package-lock.json',
    '/yarn.lock',
    '/pnpm-lock.yaml',
    '/npm-shrinkwrap.json',
    '/.npmrc',
    '/.yarnrc',
    '/.yarnrc.yml',
    '/node_modules/',

    // Python / PyPI
    '/requirements.txt',
    '/Pipfile',
    '/Pipfile.lock',

    // Ruby / RubyGems
    '/Gemfile',
    '/Gemfile.lock',

    // .NET / NuGet
    '/packages.config',

    // Java / Maven / Gradle
    '/pom.xml',
    '/build.gradle',
    '/build.gradle.kts',

    // PHP / Composer
    '/composer.json',

    // Go
    '/go.mod',
    '/go.sum',

    // Rust / Crates
    '/Cargo.toml',
    '/Cargo.lock',

    // Bundlers/Frameworks
    '/webpack.config.js',
    '/vite.config.js',
    '/vite.config.ts',
    '/next.config.js',
    '/nuxt.config.js',
    '/rollup.config.js',
    '/babel.config.js',
    '/tsconfig.json',

    // Environment/Secrets
    '/.env',
    '/.env.local',
    '/.env.development',
    '/.env.production',
    '/.env.test',
    '/docker-compose.yml',
    '/Dockerfile'
  ],

  NODE_BUILTINS: new Set([
    'assert', 'buffer', 'child_process', 'cluster', 'crypto', 'dgram', 'dns',
    'domain', 'events', 'fs', 'http', 'https', 'net', 'os', 'path', 'punycode',
    'querystring', 'readline', 'repl', 'stream', 'string_decoder', 'timers',
    'tls', 'tty', 'url', 'util', 'v8', 'vm', 'zlib', 'constants', 'module',
    'process', 'console', 'http2', 'perf_hooks', 'trace_events', 'worker_threads',
    'require', 'exports'
  ]),

  // Common path aliases used by bundlers/frameworks
  INTERNAL_ALIAS_PREFIXES: ['@/', '~/', '~~/'],
  INTERNAL_ALIAS_ROOTS: [
    'src', 'app', 'apps', 'components', 'component', 'pages', 'layouts', 'views',
    'hooks', 'utils', 'lib', 'libs', 'services', 'service', 'store', 'stores',
    'state', 'modules', 'assets', 'styles', 'css', 'scss', 'sass', 'less',
    'images', 'img', 'fonts', 'locales', 'i18n', 'types', 'constants',
    'config', 'configs', 'public'
  ],

  CONFIG_PATTERNS: {
    'package.json': /^\s*\{/,
    'package-lock.json': /^\s*\{/,
    'yarn.lock': /^#.*yarn|registry/i,
    'pnpm-lock.yaml': /^lockfileVersion/,
    'npm-shrinkwrap.json': /^\s*\{/,
    '.npmrc': /registry=|disturl=|always-auth=|_auth=/,
    '.yarnrc': /--install|yarn-path/,
    '.yarnrc.yml': /nodeLinker:|yarnPath:/,
    'node_modules': /Index of|Parent Directory/i,
    'requirements.txt': /^[a-zA-Z0-9_.-]+/m,
    'Pipfile': /^\[(packages|dev-packages)\]/m,
    'Pipfile.lock': /^\s*\{/,
    'Gemfile': /^\s*source\s+['"]|^\s*gem\s+['"]/m,
    'Gemfile.lock': /^GEM\b/m,
    'packages.config': /<packages>|<package\s+id=/i,
    'pom.xml': /<project[\s>]/i,
    'build.gradle': /\bdependencies\b|\bplugins\b/i,
    'build.gradle.kts': /\bdependencies\b|\bplugins\b/i,
    'composer.json': /^\s*\{/,
    'go.mod': /^\s*module\s+/m,
    'go.sum': /^[a-zA-Z0-9_.-]+\s+[v0-9]/m,
    'Cargo.toml': /^\s*\[(dependencies|dev-dependencies|build-dependencies)\]/m,
    'Cargo.lock': /^\s*\[\[package\]\]/m,
    'webpack.config.js': /module\.exports|require\(|import /,
    'vite.config.js': /export default|defineConfig/,
    'vite.config.ts': /export default|defineConfig/,
    'next.config.js': /module\.exports|nextConfig/,
    'nuxt.config.js': /export default|defineNuxtConfig/,
    'rollup.config.js': /export default/,
    'babel.config.js': /module\.exports/,
    'tsconfig.json': /^\s*\{/,
    '.env': /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=/m,
    '.env.local': /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=/m,
    '.env.development': /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=/m,
    '.env.production': /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=/m,
    '.env.test': /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=/m,
    'docker-compose.yml': /^version:|services:/,
    'Dockerfile': /^FROM /i
  },

  // Internal module patterns - these are NOT standalone npm packages
  // but internal references within parent packages
  INTERNAL_MODULE_PATTERNS: [
    { parent: 'prismjs', pattern: /^prism-[a-z]+$/ }, // prism-javascript, prism-python, etc.
    { parent: 'highlight.js', pattern: /^highlight\.js\/lib\/languages\// },
    { parent: 'monaco-editor', pattern: /^monaco-editor\/esm\// },
    { parent: 'codemirror', pattern: /^codemirror\/mode\// },
    { parent: 'codemirror', pattern: /^codemirror\/addon\// },
    { parent: 'ace-builds', pattern: /^ace\/mode\// },
    { parent: 'ace-builds', pattern: /^ace\/theme\// },
    // Polymer / Web Components (Common False Positives)
    { parent: null, pattern: /^(dom-module|custom-style|ps-dom-if|ps-dom-repeat)$/ },
    { parent: null, pattern: /^(iron-|paper-|neon-|app-).+$/ }, // Common Polymer prefixes
    // YouTube Internal
    { parent: null, pattern: /^yt-.+$/ },
    { parent: null, pattern: /^ytd-.+$/ }
  ]
};

// ============================================================================
// UTILITIES
// ============================================================================

class Logger {
  static debug(...args) {
    // Always log in development, or check a flag
    console.log('%c[NPM Scanner]', 'color: #00ff41; font-weight: bold;', ...args);
  }

  static error(...args) {
    console.error('%c[NPM Scanner]', 'color: #ff0000; font-weight: bold;', ...args);
  }

  static warn(...args) {
    console.warn('%c[NPM Scanner]', 'color: #ff9900; font-weight: bold;', ...args);
  }
}

class RateLimiter {
  constructor(maxRequests, timeWindow) {
    this.maxRequests = maxRequests;
    this.timeWindow = timeWindow;
    this.requests = [];
  }

  async waitForSlot() {
    const now = Date.now();
    this.requests = this.requests.filter(time => now - time < this.timeWindow);

    if (this.requests.length >= this.maxRequests) {
      const oldestRequest = this.requests[0];
      const waitTime = this.timeWindow - (now - oldestRequest) + 100;
      await new Promise(resolve => setTimeout(resolve, waitTime));
      return this.waitForSlot();
    }

    this.requests.push(now);
  }
}

class PackageNameExtractor {
  /**
   * Check if a package name is likely an internal module (not a real npm package)
   * @param {string} packageName - The package name to check
   * @param {Set} detectedPackages - Set of all detected package names (to check for parent packages)
   * @returns {boolean} - True if this is likely an internal module
   */
  static isInternalModule(packageName, detectedPackages = new Set()) {
    if (!packageName) return false;

    // Check against known internal module patterns
    for (const pattern of CONFIG.INTERNAL_MODULE_PATTERNS) {
      if (pattern.pattern.test(packageName)) {
        // If we've detected the parent package, this is definitely an internal module
        if (detectedPackages.has(pattern.parent)) {
          return true;
        }
        // Even if parent not detected yet, it's likely internal
        // (parent might be detected later in the scan)
        return true;
      }
    }

    return false;
  }

  static stripQueryAndHash(value) {
    return value.split('#')[0].split('?')[0];
  }

  static isAliasPath(importPath) {
    if (!importPath) return false;

    const normalized = importPath.trim();
    const lower = normalized.toLowerCase();

    if (normalized.startsWith('/') && !normalized.startsWith('//')) return true;
    if (/^[a-z]:[\\/]/i.test(normalized) || normalized.startsWith('\\\\')) return true;

    for (const prefix of CONFIG.INTERNAL_ALIAS_PREFIXES) {
      if (lower.startsWith(prefix)) return true;
    }

    if (lower === '~' || lower.startsWith('~/')) return true;

    const parts = normalized.split('/');
    if (parts.length > 1) {
      const root = parts[0].toLowerCase();
      if (CONFIG.INTERNAL_ALIAS_ROOTS.includes(root)) return true;
    }

    return false;
  }

  static normalizePackageName(pkgName) {
    if (!pkgName) return null;

    let normalized = pkgName.trim();
    if (normalized.startsWith('@')) {
      const match = normalized.match(/^(@[^/]+)\/(.+)$/);
      if (!match) return null;
      const scope = match[1];
      let name = match[2];
      name = name.split('@')[0];
      normalized = `${scope}/${name}`;
    } else if (normalized.includes('@')) {
      normalized = normalized.split('@')[0];
    }

    if (CONFIG.NODE_BUILTINS.has(normalized)) return null;

    // npm package names are effectively lowercase; normalize early to reduce false negatives
    normalized = normalized.toLowerCase();

    if (!/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(normalized)) return null;

    return normalized;
  }

  /**
   * Extract an npm package name from a source-map "sources" entry by looking for
   * a node_modules segment. This is much more reliable than treating the entire
   * path as an import specifier.
   */
  static extractFromNodeModulesPath(value) {
    if (!value || typeof value !== 'string') return null;

    let cleaned = value.trim();
    if (!cleaned) return null;

    cleaned = this.stripQueryAndHash(cleaned).replace(/\\/g, '/');
    const lower = cleaned.toLowerCase();

    const markers = ['node_modules/', '/~/'];
    let idx = -1;
    let markerLen = 0;
    let usedMarker = null;
    for (const m of markers) {
      const i = lower.lastIndexOf(m);
      if (i > idx) {
        idx = i;
        markerLen = m.length;
        usedMarker = m;
      }
    }
    if (idx === -1) return null;

    const rest = cleaned.slice(idx + markerLen);
    const parts = rest.split('/').filter(Boolean);
    if (parts.length === 0) return null;

    let pkg = parts[0];
    // In some frameworks, "~/" is an alias to the app root. Filter common app roots to reduce false positives.
    if (usedMarker === '/~/' && CONFIG.INTERNAL_ALIAS_ROOTS.includes(pkg.toLowerCase())) return null;
    if (pkg.startsWith('@')) {
      if (parts.length < 2) return null;
      pkg = `${parts[0]}/${parts[1]}`;
    }

    return this.normalizePackageName(pkg);
  }

  static extract(importPath) {
    if (!importPath || typeof importPath !== 'string') return null;

    let cleaned = importPath.trim();
    if (!cleaned) return null;

    cleaned = this.stripQueryAndHash(cleaned);

    if (this.isAliasPath(cleaned)) return null;

    // 1. Handle CDN URLs
    try {
      const url = new URL(cleaned, 'https://example.com'); // Base for relative URLs
      const hostname = url.hostname;

      if (hostname.includes('unpkg.com') || hostname.includes('jsdelivr.net') || hostname.includes('cdnjs.cloudflare.com')) {
        // unpkg.com/react@18.2.0/index.js -> react
        // cdn.jsdelivr.net/npm/react@18.2.0/index.js -> react
        // cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js -> react

        const pathParts = url.pathname.split('/').filter(p => p);

        // Handle jsdelivr /npm/ prefix
        if (hostname.includes('jsdelivr.net') && pathParts[0] === 'npm') {
          pathParts.shift();
        }
        // Handle cdnjs /ajax/libs/ prefix
        if (hostname.includes('cdnjs.cloudflare.com') && pathParts[0] === 'ajax' && pathParts[1] === 'libs') {
          return this.normalizePackageName(pathParts[2]); // cdnjs structure is usually /ajax/libs/<package>/...
        }

        if (pathParts.length === 0) return null;

        let pkgPart = pathParts[0];

        // Handle scoped packages in URL (e.g. @scope/pkg)
        if (pkgPart.startsWith('@') && pathParts.length > 1) {
          pkgPart = `${pathParts[0]}/${pathParts[1]}`;
        }

        return this.normalizePackageName(pkgPart);
      }
      // If it's an absolute web URL but NOT a known CDN, ignore it
      // This prevents false positives like 'connect.facebook.net' being treated as a package
      if (/^(https?:)?\/\//.test(cleaned)) {
        return null;
      }

    } catch (e) {
      // Not a URL, continue to standard extraction
    }

    // 2. Standard Import Path Cleaning
    cleaned = cleaned
      .replace(/^(https?:\/\/|node:|file:)/, '')
      .replace(/^(\.\.\/)*node_modules\//, '');

    if (cleaned.startsWith('.')) return null;
    if (cleaned.startsWith('/') && !cleaned.startsWith('//')) return null;
    if (this.isAliasPath(cleaned)) return null;

    const parts = cleaned.split('/');

    // Handle scoped packages (@org/package)
    let pkgName = parts[0];
    if (cleaned.startsWith('@')) {
      pkgName = parts.length > 1 ? `${parts[0]}/${parts[1]}` : null;
    }

    return this.normalizePackageName(pkgName);
  }
}

// ============================================================================
// WEB CRAWLER
// ============================================================================

class WebCrawler {
  constructor(baseUrl) {
    this.baseUrl = new URL(baseUrl);
    this.discoveredUrls = new Set();
    this.scannedUrls = new Set();
  }

  async fetchWithTimeout(url, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        cache: 'force-cache'
      });
      clearTimeout(timeout);
      return response;
    } catch (error) {
      clearTimeout(timeout);
      throw error;
    }
  }

  normalizeUrl(url) {
    try {
      return new URL(url, this.baseUrl).href;
    } catch {
      return null;
    }
  }

  async discoverUrlsFromHtml(html) {
    const urls = new Set();
    const patterns = [
      /<script[^>]+src=["']([^"']+)["']/gi,
      /<link[^>]+href=["']([^"']+)["'][^>]*>/gi,
      /["']([^"']*(?:manifest|asset-manifest)\.json)["']/gi
    ];

    for (const regex of patterns) {
      let match;
      while ((match = regex.exec(html)) !== null) {
        const url = this.normalizeUrl(match[1]);
        if (url) {
          // Allow all scripts, including external CDNs
          urls.add(url);
        }
      }
    }
    return Array.from(urls);
  }

  async discoverAllUrls() {
    Logger.debug('Starting URL discovery...');

    // 1. Initial Page
    const pageHtml = document.documentElement.outerHTML;
    (await this.discoverUrlsFromHtml(pageHtml)).forEach(u => this.discoveredUrls.add(u));

    // 2. Performance Entries
    performance.getEntriesByType('resource').forEach(r => {
      if (r.initiatorType === 'script' || r.name.match(/\.(js|mjs|jsx|ts|tsx)$/)) {
        // Allow all script resources
        this.discoveredUrls.add(r.name);
      }
    });

    // 3. Crawl Common Directories (Parallel)
    const dirPromises = CONFIG.COMMON_DIRS.map(async dir => {
      try {
        const response = await this.fetchWithTimeout(dir);
        if (response.ok) {
          const text = await response.text();
          const matches = text.match(/href=["']([^"']+\.(js|json))["']/g);
          if (matches) {
            matches.forEach(m => {
              const u = this.normalizeUrl(dir + m.slice(6, -1));
              if (u) this.discoveredUrls.add(u);
            });
          }
        }
      } catch (e) { /* ignore */ }
    });
    await Promise.all(dirPromises);

    Logger.debug(`Discovered ${this.discoveredUrls.size} URLs`);
    return Array.from(this.discoveredUrls);
  }
}

// ============================================================================
// PACKAGE SCANNER
// ============================================================================

class PackageScanner {
  constructor() {
    this.packages = new Map();
    this.npmPackageNames = new Set();
    this.rateLimiter = new RateLimiter(CONFIG.API_RATE_LIMIT, CONFIG.API_WINDOW);
    this.cache = new Map();
    this.scannedFiles = 0;
    this.totalFiles = 0;
  }

  addPackage(ecosystem, packageName, source) {
    if (!ecosystem || !packageName) return;

    // Normalize npm names to avoid case-sensitive registry lookups causing false results.
    if (ecosystem === 'npm' && typeof packageName === 'string') {
      packageName = packageName.trim().toLowerCase();
    }

    // Filter out internal modules to prevent false positives
    if (ecosystem === 'npm') {
      if (PackageNameExtractor.isInternalModule(packageName, this.npmPackageNames)) {
        Logger.debug(`Skipping internal module: ${packageName}`);
        return;
      }
      this.npmPackageNames.add(packageName);
    }

    const key = `${ecosystem}:${packageName}`;
    if (!this.packages.has(key)) {
      this.packages.set(key, { ecosystem, name: packageName, sources: new Set() });
    }
    this.packages.get(key).sources.add(source);
  }

  async scanPageSource() {
    const scripts = Array.from(document.scripts || []);
    scripts.forEach(script => {
      const type = (script.type || '').trim().toLowerCase();
      const isJsType = !type || type === 'text/javascript' || type === 'application/javascript' || type === 'module' || type === 'text/ecmascript' || type === 'application/ecmascript';
      if (!isJsType) return;
      if (script.src) return; // External scripts are handled by the crawler

      const content = script.textContent || '';
      if (content.trim()) {
        this.scanContent(content, 'Inline Script');
      }
    });
  }

  scanContent(content, source) {
    const patterns = [
      /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
      /import\s+.*?\s+from\s+['"]([^'"]+)['"]/g,
      /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
      /export\s+.*?\s+from\s+['"]([^'"]+)['"]/g,
      // AMD / RequireJS
      /define\s*\(\s*\[\s*['"]([^'"]+)['"]/g,
      // Webpack / Bundlers
      /__webpack_require__\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
      /require\.ensure\s*\(\s*\[\s*['"]([^'"]+)['"]/g,
      // SystemJS
      /System\.import\s*\(\s*['"]([^'"]+)['"]\s*\)/g
    ];

    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        // For AMD array syntax, we might want to capture more than just the first one
        // But for now, let's ensure we at least get the first one.
        // Also, check if the match is valid.
        if (match[1]) {
          const pkg = PackageNameExtractor.extract(match[1]);
          this.addPackage('npm', pkg, source);
        }
      }
    }
  }

  async scanAllDiscoveredFiles(urls) {
    this.totalFiles = urls.length;
    this.scannedFiles = 0;

    // 1. Check if the URLs themselves are packages (CDNs)
    this.scanUrls(urls);

    // 2. Process in chunks to avoid overwhelming the browser
    const chunkSize = 5;
    for (let i = 0; i < urls.length; i += chunkSize) {
      const chunk = urls.slice(i, i + chunkSize);
      await Promise.all(chunk.map(url => this.scanJsFile(url)));
    }
  }

  scanUrls(urls) {
    urls.forEach(url => {
      const pkg = PackageNameExtractor.extract(url);
      if (pkg) {
        this.addPackage('npm', pkg, `CDN/URL: ${url}`);
      }
    });
  }

  async scanJsFile(url) {
    try {
      const response = await fetch(url, { cache: 'force-cache' });
      if (!response.ok) return;
      const content = await response.text();
      this.scanContent(content, url);

      // Check for source map
      const mapMatch = content.match(/\/\/[#@]\s*sourceMappingURL=(.+\.map)/);
      if (mapMatch) {
        const mapUrl = new URL(mapMatch[1].trim(), url).href;
        await this.scanSourceMap(mapUrl);
      }
    } catch (e) {
      // ignore
    } finally {
      this.scannedFiles++;
    }
  }

  async scanSourceMap(url) {
    try {
      const response = await fetch(url);
      if (!response.ok) return;
      const map = await response.json();
      if (map.sources) {
        map.sources.forEach(s => {
          const pkg = PackageNameExtractor.extractFromNodeModulesPath(s);
          this.addPackage('npm', pkg, `Source Map: ${url}`);
        });
      }
    } catch (e) { /* ignore */ }
  }

  // Optimized Directory Brute-Force
  async checkExposedFiles() {
    Logger.debug('Checking for exposed files (Concurrent Mode)...');
    const exposedFiles = [];

    const basePaths = new Set(['/']);
    const currentPath = window.location.pathname || '/';
    const baseDir = currentPath.endsWith('/') ? currentPath : currentPath.slice(0, currentPath.lastIndexOf('/') + 1);
    if (baseDir && baseDir !== '/') {
      basePaths.add(baseDir);
    }

    const baselineContent = new Map();
    for (const basePath of basePaths) {
      try {
        const res = await fetch(basePath, { cache: 'force-cache' });
        baselineContent.set(basePath, res.ok ? await res.text() : '');
      } catch (e) {
        baselineContent.set(basePath, '');
      }
    }

    // Helper to check a single file
    const checkFile = async (path, basePath) => {
      try {
        // 1. Fast HEAD check
        let headRes = null;
        try {
          headRes = await fetch(path, { method: 'HEAD', cache: 'no-cache' });
        } catch (e) {
          headRes = null;
        }

        const allowGet = !headRes || headRes.ok || headRes.status === 405 || headRes.status === 501;
        if (!allowGet) return;

        // 2. Validation GET (prevent false positives from custom 404s)
        // Fetch first 512 bytes to verify content
        const getRes = await fetch(path, {
          method: 'GET',
          headers: { 'Range': 'bytes=0-512' }
        });

        if (getRes.ok) {
          const text = await getRes.text();

          // Soft 404 Check: Compare with base content
          // If the content is identical or extremely similar to the base, it's likely a SPA fallback
          const baseContent = baselineContent.get(basePath) || '';
          if (baseContent && (text === baseContent.slice(0, text.length) || text.includes('<!DOCTYPE html>'))) {
            // Double check if it's NOT an expected HTML file
            if (!path.endsWith('.html')) {
              return; // False positive: Soft 404
            }
          }

          const filename = path.split('/').pop() || 'node_modules';
          const pattern = CONFIG.CONFIG_PATTERNS[filename];

          // If we have a pattern, enforce it
          if (pattern) {
            if (!pattern.test(text)) {
              return; // False positive: Content doesn't match expected format
            }
          } else {
            // Fallback for files without specific patterns
            const contentType = (getRes.headers.get('content-type') || '').toLowerCase();

            // STRICT CHECK: Reject if Content-Type is HTML
            if (contentType.includes('text/html')) {
              return; // False positive
            }

            // STRICT CHECK: Reject if content looks like HTML
            if (text.trim().startsWith('<!DOCTYPE') || text.trim().startsWith('<html')) {
              return; // False positive
            }

            const isHtml = contentType.includes('text/html') || text.includes('<!DOCTYPE html>');
            const expectedJson = path.endsWith('.json') || path.endsWith('rc');

            if (expectedJson && isHtml) {
              return; // False positive
            }
          }

          let risk = 'LOW';
          if (filename.startsWith('.env') || filename === '.npmrc') risk = 'HIGH';
          else if (filename.includes('lock') || filename === 'package.json' || filename === 'npm-shrinkwrap.json') risk = 'MEDIUM';

          exposedFiles.push({
            path,
            risk,
            status: getRes.status,
            contentType: getRes.headers.get('content-type')
          });

          await this.parseDependencyFile(path);
        }
      } catch (e) {
        // Ignore network errors (file not found)
      }
    };

    // Run checks in parallel with concurrency limit
    const pool = [];
    const limit = CONFIG.MAX_CONCURRENT_SCANS;

    const candidatePaths = [];
    for (const basePath of basePaths) {
      const prefix = basePath === '/' ? '' : basePath.replace(/\/$/, '');
      for (const path of CONFIG.CONFIG_FILES) {
        candidatePaths.push({ path: `${prefix}${path}`, basePath });
      }
    }

    for (const { path, basePath } of candidatePaths) {
      const p = checkFile(path, basePath).then(() => {
        pool.splice(pool.indexOf(p), 1);
      });
      pool.push(p);
      if (pool.length >= limit) await Promise.race(pool);
    }
    await Promise.all(pool);

    return exposedFiles;
  }

  async parsePackageJson(packagePath = '/package.json') {
    try {
      const res = await fetch(packagePath);
      const text = await res.text();
      this.parsePackageJsonContent(text, packagePath);
    } catch (e) { /* ignore */ }
  }

  parsePackageJsonContent(content, source) {
    try {
      const json = JSON.parse(content);
      ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'].forEach(t => {
        if (json[t]) Object.keys(json[t]).forEach(d => this.addPackage('npm', d, source));
      });
    } catch (e) { /* ignore */ }
  }

  parseRequirementsTxt(content, source) {
    const lines = (content || '').split(/\r?\n/);
    lines.forEach(line => {
      const stripped = line.trim();
      if (!stripped || stripped.startsWith('#')) return;
      if (stripped.startsWith('-')) return;
      if (stripped.includes('://') || stripped.startsWith('git+')) return;
      if (stripped.startsWith('-e ') || stripped.startsWith('--') || stripped.startsWith('-r ') || stripped.startsWith('-c ')) return;
      let name = stripped.split(/[\s<=>~!]/)[0];
      name = name.split('[')[0];
      if (stripped.includes('egg=')) {
        const egg = stripped.split('egg=')[1];
        if (egg) name = egg;
      }
      if (name) this.addPackage('pypi', name, source);
    });
  }

  parsePipfile(content, source) {
    let inPackages = false;
    let inDevPackages = false;
    const lines = (content || '').split(/\r?\n/);
    for (const line of lines) {
      const stripped = line.trim();
      if (!stripped || stripped.startsWith('#')) continue;
      if (stripped.startsWith('[') && stripped.endsWith(']')) {
        const section = stripped.slice(1, -1).toLowerCase();
        inPackages = section === 'packages';
        inDevPackages = section === 'dev-packages';
        continue;
      }
      if ((inPackages || inDevPackages) && stripped.includes('=')) {
        const name = stripped.split('=')[0].trim().replace(/^["']|["']$/g, '');
        const value = stripped.split('=')[1].trim();
        if (!this.isPypiValueAllowed(value)) continue;
        if (name) this.addPackage('pypi', name, source);
      }
    }
  }

  parsePipfileLock(content, source) {
    try {
      const json = JSON.parse(content);
      ['default', 'develop'].forEach(section => {
        const deps = json[section] || {};
        Object.keys(deps).forEach(name => {
          const meta = deps[name];
          if (this.isPypiValueAllowed(meta)) {
            this.addPackage('pypi', name, source);
          }
        });
      });
    } catch (e) { /* ignore */ }
  }

  isPypiValueAllowed(value) {
    if (value == null) return true;
    if (typeof value === 'object') {
      const keys = Object.keys(value);
      for (const key of ['path', 'file', 'git', 'editable', 'url']) {
        if (keys.includes(key)) return false;
      }
      return true;
    }
    const text = String(value).toLowerCase();
    if (text.startsWith('http://') || text.startsWith('https://') || text.startsWith('git+') || text.startsWith('git://')) return false;
    if (text.startsWith('file:') || text.startsWith('link:') || text.startsWith('workspace:')) return false;
    return true;
  }

  parseGemfile(content, source) {
    const regex = /^\s*gem\s+['"]([^'"]+)['"]/gm;
    let match;
    while ((match = regex.exec(content || '')) !== null) {
      const name = match[1];
      if (name) this.addPackage('rubygems', name, source);
    }
  }

  parseComposerJson(content, source) {
    try {
      const json = JSON.parse(content);
      ['require', 'require-dev'].forEach(key => {
        const reqs = json[key] || {};
        Object.keys(reqs).forEach(name => {
          if (!name || name === 'php') return;
          if (name.startsWith('ext-') || name.startsWith('lib-')) return;
          if (name.includes('/')) this.addPackage('composer', name, source);
        });
      });
    } catch (e) { /* ignore */ }
  }

  parsePomXml(content, source) {
    const regex = /<dependency>([\s\S]*?)<\/dependency>/g;
    let match;
    while ((match = regex.exec(content || '')) !== null) {
      const block = match[1];
      const group = /<groupId>(.*?)<\/groupId>/.exec(block);
      const artifact = /<artifactId>(.*?)<\/artifactId>/.exec(block);
      if (group && artifact) {
        const name = `${group[1].trim()}:${artifact[1].trim()}`;
        if (!name.includes('${')) this.addPackage('maven', name, source);
      }
    }
  }

  parseGradle(content, source) {
    const regex = /['"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):[^'"]+['"]/g;
    let match;
    while ((match = regex.exec(content || '')) !== null) {
      const name = `${match[1]}:${match[2]}`;
      if (!name.includes('${')) this.addPackage('maven', name, source);
    }
  }

  parseNuget(content, source) {
    const refs = [];
    const regex1 = /PackageReference\s+Include="([^"]+)"/g;
    const regex2 = /<package\s+id="([^"]+)"/g;
    let match;
    while ((match = regex1.exec(content || '')) !== null) refs.push(match[1]);
    while ((match = regex2.exec(content || '')) !== null) refs.push(match[1]);
    refs.forEach(name => {
      if (name) this.addPackage('nuget', name, source);
    });
  }

  parseGoMod(content, source) {
    const lines = (content || '').split(/\r?\n/);
    let inRequire = false;
    for (const line of lines) {
      const stripped = line.trim();
      if (stripped.startsWith('require (')) {
        inRequire = true;
        continue;
      }
      if (inRequire && stripped === ')') {
        inRequire = false;
        continue;
      }
      if (stripped.startsWith('require ')) {
        const parts = stripped.replace(/^require\s+/, '').trim().split(/\s+/);
        if (parts[0]) this.addPackage('golang', parts[0], source);
      } else if (inRequire) {
        const parts = stripped.split(/\s+/);
        if (parts[0]) this.addPackage('golang', parts[0], source);
      }
    }
  }

  parseCargoToml(content, source) {
    const lines = (content || '').split(/\r?\n/);
    let inDeps = false;
    for (const line of lines) {
      const stripped = line.trim();
      if (stripped.startsWith('[') && stripped.endsWith(']')) {
        const section = stripped.slice(1, -1);
        inDeps = ['dependencies', 'dev-dependencies', 'build-dependencies'].includes(section);
        continue;
      }
      if (inDeps && stripped.includes('=') && !stripped.startsWith('#')) {
        const name = stripped.split('=')[0].trim();
        const value = stripped.split('=')[1].trim();
        if (value.includes('path =') || value.includes('git =')) continue;
        if (name) this.addPackage('crates', name, source);
      }
    }
  }

  async parseDependencyFile(path) {
    const lower = path.toLowerCase();
    try {
      const res = await fetch(path);
      if (!res.ok) return;
      const content = await res.text();
      if (lower.endsWith('package.json')) this.parsePackageJsonContent(content, path);
      else if (lower.endsWith('requirements.txt')) this.parseRequirementsTxt(content, path);
      else if (lower.endsWith('pipfile')) this.parsePipfile(content, path);
      else if (lower.endsWith('pipfile.lock')) this.parsePipfileLock(content, path);
      else if (lower.endsWith('gemfile')) this.parseGemfile(content, path);
      else if (lower.endsWith('composer.json')) this.parseComposerJson(content, path);
      else if (lower.endsWith('pom.xml')) this.parsePomXml(content, path);
      else if (lower.endsWith('build.gradle') || lower.endsWith('build.gradle.kts')) this.parseGradle(content, path);
      else if (lower.endsWith('packages.config') || lower.endsWith('.csproj')) this.parseNuget(content, path);
      else if (lower.endsWith('go.mod')) this.parseGoMod(content, path);
      else if (lower.endsWith('cargo.toml')) this.parseCargoToml(content, path);
    } catch (e) { /* ignore */ }
  }

  async analyzePackages(onUpdate) {
    Logger.debug(`Analyzing ${this.packages.size} packages...`);
    const results = [];

    for (const pkg of this.packages.values()) {
      results.push(await this.analyzePackage(pkg.ecosystem, pkg.name, Array.from(pkg.sources)));
      if (onUpdate) onUpdate(results);
    }
    return results;
  }

  async analyzePackage(ecosystem, name, sources) {
    // Check cache
    const cacheKey = `${ecosystem}:${name}`;
    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CONFIG.CACHE_DURATION) {
      return { ...cached.data, sources, ecosystem };
    }

    await this.rateLimiter.waitForSlot();

    try {
      // Delegate to background script to bypass CSP/CORS
      const result = await chrome.runtime.sendMessage({
        action: 'analyzePackage',
        ecosystem,
        name,
        sources
      });

      if (result.error) {
        return { name, ecosystem, error: result.error, sources };
      }

      this.cacheResult(cacheKey, result);
      return { ...result, ecosystem };

    } catch (e) {
      return { name, ecosystem, error: e.message, sources };
    }
  }

  async fetchDownloads(name) {
    try {
      await this.rateLimiter.waitForSlot();
      const res = await fetch(`https://api.npmjs.org/downloads/point/last-week/${name}`);
      if (res.ok) {
        const data = await res.json();
        return data.downloads;
      }
    } catch (e) { return 0; }
    return 0;
  }

  assessRisk(info, downloads) {
    const reasons = [];
    let suspicious = false;
    let level = 'LOW';

    if (downloads < CONFIG.MIN_DOWNLOADS_SUSPICIOUS && !info.repository) {
      suspicious = true;
      level = 'HIGH';
      reasons.push('Low downloads + No Repo');
    }

    // Typosquatting check
    if (/[0-9]{3,}|[il1][o0]/.test(info.name)) {
      suspicious = true;
      level = 'MEDIUM';
      reasons.push('Suspicious name pattern');
    }

    return { suspicious, riskLevel: suspicious ? level : 'LOW', riskReasons: reasons };
  }

  cacheResult(name, data) {
    this.cache.set(name, { data, timestamp: Date.now() });
  }
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================

let scanner = new PackageScanner();
let crawler = new WebCrawler(window.location.href);
let scanSessionId = 0;

// State Management
let scanState = {
  scanning: false,
  complete: false,
  packages: [],
  exposedFiles: [],
  error: null,
  url: window.location.href,
  enabled: true // Extension enabled by default
};

// Auto-start scan
async function runAutoScan() {
  const sessionId = ++scanSessionId;

  // Check if extension is enabled
  const storage = await chrome.storage.local.get(['extensionEnabled']);
  const isEnabled = storage.extensionEnabled !== false; // default to true
  scanState.enabled = isEnabled;

  if (!isEnabled) {
    Logger.debug('Extension is disabled. Scan aborted.');
    return;
  }

  if (scanState.scanning || scanState.complete) return;

  scanState.scanning = true;
  scanState.complete = false;
  scanState.error = null;
  scanState.url = window.location.href;
  Logger.debug('Auto-scan initiated...');

  try {
    // 1. Scan Page Source
    await scanner.scanPageSource();
    if (sessionId !== scanSessionId) return;

    // 2. Crawl & Scan Scripts
    const urls = await crawler.discoverAllUrls();
    await scanner.scanAllDiscoveredFiles(urls);
    if (sessionId !== scanSessionId) return;

    // 3. Check Exposed Files
    const exposedFiles = await scanner.checkExposedFiles();
    if (sessionId !== scanSessionId) return;
    scanState.exposedFiles = exposedFiles;

    // 4. Analyze Packages (incremental)
    const packageResults = await scanner.analyzePackages((partial) => {
      if (sessionId !== scanSessionId) return;
      scanState.packages = partial.slice();
      const suspiciousPackages = scanState.packages.filter(p => p.suspicious);
      if (suspiciousPackages.length > 0 || scanState.exposedFiles.length > 0) {
        chrome.runtime.sendMessage({
          action: 'notifyRisks',
          suspiciousPackages,
          exposedFiles: scanState.exposedFiles
        });
      }
    });
    if (sessionId !== scanSessionId) return;
    const suspiciousPackages = packageResults.filter(p => p.suspicious);

    // Update State
    scanState.packages = packageResults;
    scanState.exposedFiles = exposedFiles;
    scanState.complete = true;
    scanState.scanning = false;

    // 5. Report Results (Optional: Badge/Notification)
    // 5. Report Results (Optional: Badge/Notification)
    if (suspiciousPackages.length > 0 || exposedFiles.length > 0) {
      chrome.runtime.sendMessage({
        action: 'notifyRisks',
        suspiciousPackages,
        exposedFiles
      });
    }

  } catch (e) {
    if (sessionId !== scanSessionId) return;
    scanState.error = e.message;
    scanState.scanning = false;
    Logger.error('Scan failed:', e);
  }
}

function resetForRescan() {
  scanSessionId += 1;
  scanner = new PackageScanner();
  crawler = new WebCrawler(window.location.href);

  scanState.scanning = false;
  scanState.complete = false;
  scanState.packages = [];
  scanState.exposedFiles = [];
  scanState.error = null;
  scanState.url = window.location.href;
}

// Start immediately (with slight delay for DOM)
setTimeout(runAutoScan, 1000);

// Listen for messages from Popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getScanStatus' || request.action === 'startScan') {
    // Return current state immediately
    sendResponse(scanState);
    return true;
  }

  if (request.action === 'forceRescan') {
    resetForRescan();
    runAutoScan().catch((error) => {
      Logger.error('Force rescan failed:', error);
    });
    sendResponse({ success: true, started: true });
    return true;
  }

  if (request.action === 'toggleExtension') {
    const isEnabled = request.enabled;
    scanState.enabled = isEnabled;

    Logger.debug(`Extension ${isEnabled ? 'ENABLED' : 'DISABLED'}`);

    // If enabled and not yet scanned, start scan
    if (isEnabled && !scanState.complete && !scanState.scanning) {
      runAutoScan();
    }

    // If disabled, clear results
    if (!isEnabled) {
      scanSessionId += 1;
      scanState.packages = [];
      scanState.exposedFiles = [];
      scanState.complete = false;
      scanState.scanning = false;
      scanState.error = null;
    }

    sendResponse({ success: true, enabled: isEnabled });
    return true;
  }
});

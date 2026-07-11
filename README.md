# 🧪 NPM-SECURITY-SCANNER-PRO

**NPM-SECURITY-SCANNER-PRO** is a browser extension built for **security researchers**, **developers**, and **DevSecOps pros** who demand speed, accuracy, and deep visibility.
It helps detect **dependency confusion**, **unregistered packages**, **known CVEs (OSV.dev)**, **typosquatting**, and **exposed secrets** directly from web applications in real time.

Whether you're auditing a target, securing your own app, or hunting supply-chain vulnerabilities, **NPM-SECURITY-SCANNER-PRO** makes risk detection fast, practical, and actionable.

---

## ✨ Features

### 🕵️ Advanced Scanning Modes
*Fully compatible with modern bundlers and frameworks.*

- 🔍 **Deep Crawl**: Recursively crawls linked JavaScript files and source maps to uncover hidden dependencies.
- 🧾 **Page Source Scan**: Extracts npm packages defined in initial HTML and inline scripts.
- 🧩 **Bundler Analysis**: Deconstructs Webpack, Vite, Parcel, and SystemJS bundles.
- 📄 **Exposed Files**: Checks for sensitive files like `.env`, `package.json`, registry configs, and lockfiles.

### 🧠 Intelligent Threat Detection

- ⚠️ **Dependency Confusion**: Flags internal package names not registered on public registries.
- 🧬 **Typosquatting**: Detects suspicious package names that mimic common libraries.
- 🕰️ **Abandoned Packages**: Warns about stale packages with weak maintenance signals.

### 🖥️ Hacker-Grade Workflow

- 🧑‍💻 **Terminal-Style UX**: High-contrast popup tuned for quick triage.
- 📊 **Risk Matrix Dashboard**: Compact severity cards plus ecosystem counters.
- 🧷 **Live Badge Counts**: Extension icon badge reflects current risk count.
- 📄 **One-Click Export**: Download a complete HTML report.
- ✂️ **Fast Copy**: Copy per-item findings quickly for reporting.
- 🧹 **Soft 404 Filtering**: Reduces false positives on SPA fallback routes.

---

## 🧭 How to Use

1. 🌐 **Navigate to a target** website.
2. ⚡ **Auto-scan starts** in the background.
3. 🏷️ **Check the badge color**:
   - 🟢 Green: clean
   - 🟡 Yellow: warnings
   - 🔴 Red: critical risks
4. 🧩 **Open the extension popup** to inspect full results.
5. 📤 **Export report** with `Save Results`.

---
## 🧪 Local Test Server

This repo includes a demo server under `test-server/` that exposes registry configs and lockfiles for multiple ecosystems:
- npm, PyPI, Maven, RubyGems, NuGet, Composer, Go, Crates

Quick start:

```bash
cd test-server
npm install
npm start
```

Then open `http://localhost:3000/` and run the extension on that page.

---

## 🖼️ Screenshot

### Terminal Dashboard
*View critical risks and package details in a high-contrast interface.*

<div align="center">
  <img src="icon128.png" alt="Extension Icon" width="128" height="128" />
</div>

---

## 🧾 Changelog

### v3.1.0 (Latest)
- **OSV.dev advisory lookups** (`api.osv.dev`). Every detected package is cross-referenced against the Open Source Vulnerabilities database; up to 3 top-severity advisories (CVE/GHSA) are surfaced per package and visible inline on each finding card.
- **Deeper page scanning**:
  - `<script type="importmap">` blocks: extract declared bare specifiers and validate them as packages.
  - `navigator.serviceWorker.register(...)` calls: queue the registered script for secondary crawling.
  - Webpack runtime chunk URL patterns (`__webpack_require__.p + "<chunk>.js"`) are surfaced for follow-up crawling.
  - Inline `<script type="application/ld+json">` and `<script type="application/json">` blocks contribute any http(s) URLs to the crawl queue.
- **Stronger NPM heuristics**: now flags packages that have no public downloads AND no linked repository, single-maintainer packages without a repo, packages not updated in 2+ years, and brand-new packages (<90 days) with low adoption. Typosquat patterns unchanged.
- **Bug fixes**:
  - Replaced every `cache: 'force-cache'` (which *throws* on responses the browser can't store) with the safe default cache mode so crawler / source-map / directory-brute-force fetches no longer abort mid-scan.
  - Replaced `cache: 'no-cache'` (per-call revalidation, often returning 304) with `cache: 'reload'` for HEAD/GET on potentially exposed files, then for source-map and discovered-file fetches keep default cache for in-session reuse.
  - Removed dead `NotificationManager` stub from the service worker.
  - Bounded `tabResults` Map with a true LRU (max 32 tabs) so the worker can't leak under heavy tab churn.
- **Manifest**: added `content_security_policy` so the popup's Google Fonts stylesheet loads reliably, plus an `https://api.osv.dev/*` host permission.
- **UI**: new `VULNS` matrix card and per-finding CVE/CWE advisory lines with severity colour swatches.

### v3.0.3

### v3.0.1
- Neo Security popup redesign.
- Added copy toolkit (`Copy Summary`, per-section copy, per-item copy).
- Added manual popup rescan via `forceRescan` message flow.
- Added client-side search and severity filters.
### v3.0.0
- Complete UI overhaul to terminal aesthetic.
- Added deep crawling.
- Implemented dependency confusion detection logic.
- Improved soft-404 filtering.
- Migrated to Manifest V3.

### v2.0.0
- Added support for Webpack and Vite bundle analysis.
- Introduced HTML report export.

### v1.0.0
- Initial release.
- Basic package extraction from page source.

---

## 🧩 Installation Guide

1. 📥 Download the extension source.
2. Open `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked** and select this directory.
5. Pin the extension in your browser toolbar.

---

## 👤 Contributor

- **Bytes_Knight** — Creator and Maintainer  
  Bugcrowd: [@Bytes_Knight](https://bugcrowd.com/h/Bytes_Knight) | GitHub: [bytes-Knight](https://github.com/bytes-Knight)

---

## 🤝 Contributing

Contributions are welcome:

1. Fork the repository.
2. Create a branch (`git checkout -b feature/your-feature-name`).
3. Commit your changes.
4. Push your branch.
5. Open a pull request.

---

## 📜 License

MIT License.

---

## 🔒 Privacy Note

- Scanning is performed locally in the browser.
- Registry checks use public package registries.
- No intentional collection of private project data.

---

> 🧪 *Built by a hunter, for hunters.*


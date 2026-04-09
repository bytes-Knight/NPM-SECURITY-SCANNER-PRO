# 🧪 NPM-SECURITY-SCANNER-PRO

**NPM-SECURITY-SCANNER-PRO** is a browser extension built for **security researchers**, **developers**, and **DevSecOps pros** who demand speed, accuracy, and deep visibility.
It helps detect **dependency confusion**, **unregistered packages**, and **exposed secrets** directly from web applications in real time.

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

### v3.0.3 (Latest)
- Added compact popup dashboard matrix with severity cards and ecosystem counters.
- Updated per-item `Copy` behavior for faster reporting.
- Added scan timeout guards and URL discovery limits.
- Reduced flicker and redundant popup render loops.

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


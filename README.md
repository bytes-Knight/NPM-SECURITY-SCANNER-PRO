# ðŸ§ª NPM-SECURITY-SCANNER-PRO

**NPM-SECURITY-SCANNER-PRO** is a browser extension built for **security researchers**, **developers**, and **DevSecOps pros** who demand speed, accuracy, and deep visibility.
It's your go-to tool for detecting **dependency confusion**, **unregistered packages**, and **exposed secrets** directly from any web application in real-time.

Whether you're auditing a target, securing your own app, or hunting for supply chain vulnerabilities, **NPM-SECURITY-SCANNER-PRO** makes risk detection fast, smart, and deadly efficient. ðŸ§¨

---
## âœ¨ Features

### ðŸ•µï¸ Advanced Scanning Modes
*Fully compatible with modern bundlers and frameworks.*

- ðŸ” **Deep Crawl**: Recursively crawls linked JavaScript files and source maps to uncover hidden dependencies that aren't immediately visible.
- ðŸ§¾ **Page Source Scan**: Instantly extracts npm packages defined in the initial HTML and inline scripts.
- ðŸ§© **Bundler Analysis**: Deconstructs Webpack, Vite, Parcel, and SystemJS bundles to find every single included library.
- ðŸ”“ **Exposed Files**: Automatically checks for sensitive files like `.env`, `package.json`, registry configs, and lockfiles that shouldn't be public.

### ðŸ§  Intelligent Threat Detection
- âš ï¸ **Dependency Confusion**: Identifies internal package names that are NOT registered on the public npm registry - a critical supply chain vector.
- ðŸ§¬ **Typosquatting**: Flags packages with suspicious names that mimic popular libraries (for example, `react-dom-binding` vs `react-dom`).
- ðŸ•°ï¸ **Abandoned Packages**: Warns you about packages that haven't been updated in years or have dangerously low download counts.

### ðŸ–¥ï¸ Hacker-Grade Workflow
- ðŸ§‘â€ðŸ’» **Terminal UI**: A retro, hacker-style interface that makes viewing results feel like you're in the matrix.
- 📊 **Risk Matrix Dashboard**: The popup now includes a compact 4-card severity block (**Critical / High / Medium / Total**) plus 6 ecosystem counters (**NPM / PYPI / GEMS / GO / CARGO / PHP**).
- ðŸ§· **Live Badges**: Get immediate visual feedback on the extension icon with risk counts (Red for Critical, Yellow for Warning).
- ðŸ“„ **One-Click Export**: Download a comprehensive **HTML Report** of your findings, styled and ready for client presentation.
- ✂️ **Fast Copy**: Per-item Copy now copies only the package name (or file path for exposed-file rows), making triage and reporting faster.
- ðŸ§¹ **Soft 404 Filtering**: Smart logic to ignore false positives from Single Page Applications (SPAs).

---

## ðŸ§­ How to Use

1. ðŸŒ **Navigate to a Target**: Go to any website you want to audit.
2. âš¡ **Auto-Scan Initiates**: The extension automatically starts scanning in the background.
3. ðŸ·ï¸ **Check the Badge**:
   - ðŸŸ¢ **Green**: Clean.
   - ðŸŸ¡ **Yellow**: Warnings found.
   - ðŸ”´ **Red**: Critical risks detected.
4. ðŸ§© **Open the Terminal**: Click the **NPM-SECURITY-SCANNER-PRO** icon to view the detailed "Hacker Terminal" dashboard.
5. ðŸ“¤ **Analyze and Export**: Review findings as they stream in and click **`SAVE RESULTS`** to generate a full HTML report.

---

## ðŸ§ª Local Test Server
This repo includes a demo server under `test-server/` that exposes registry configs and lockfiles for multiple ecosystems to validate the scanner:
- npm, PyPI, Maven, RubyGems, NuGet, Composer, Go, Crates

Quick start:
```
cd test-server
npm install
npm start
```
Then open `http://localhost:3000/` and run the extension on that page.

---

## ðŸ–¼ï¸ Screenshots

### Terminal Dashboard
*View critical risks and package details in a high-contrast terminal interface.*

<!-- Placeholder for screenshot -->
<div align="center">
  <img src="icon128.png" alt="Extension Icon" width="128" height="128" />
</div>

---

## ðŸ§¾ Changelog

### v3.0.3 (Latest)
- **UI**: Added the compact popup dashboard matrix with 4 severity cards and 6 ecosystem counters.
- **Improvement**: Updated per-item `Copy` behavior to copy package name only (file path for exposed-file items).
- **Improvement**: Added scan timeout guards and URL discovery limits to reduce stuck scans on heavy sites.
- **Fix**: Removed popup pulse/entry flicker and avoided redundant render loops.

### v3.0.2
- **UI**: Redesigned popup to a modern "Neo Security" dashboard with improved information hierarchy.
- **Feature**: Added copy toolkit (`Copy Summary`, per-section copy, per-item copy) for faster reporting workflows.
- **Feature**: Added manual `Rescan` action in popup with new content-script `forceRescan` message handling.
- **Feature**: Added client-side search and severity filters for large result sets.
- **Improvement**: Updated popup interactions with toast feedback for copy/download actions.

### v3.0.0
- **Feature**: Complete UI overhaul to "Hacker Terminal" aesthetic.
- **Feature**: Added **Deep Crawling** for recursive script analysis.
- **Feature**: Implemented **Dependency Confusion** detection logic.
- **Improvement**: Enhanced "Soft 404" detection to reduce false positives on SPAs.
- **Refactor**: Migrated to Manifest V3 for better performance and security.

### v2.0.0
- Added support for Webpack and Vite bundle analysis.
- Introduced HTML report export.

### v1.0.0
- Initial release.
- Basic package extraction from page source.

---

## ðŸ§© Installation Guide

1. ðŸ“¥ **Download the Extension**:
   - Click the green **Code** button on this repository page.
   - Select **Download ZIP** and save the file.
   - Unzip the downloaded file.

2. ðŸ§­ **Load the Extension in Your Browser**:
   - Open Chrome and navigate to `chrome://extensions`.
   - Enable **Developer mode** using the toggle in the top-right corner.
   - Click **Load unpacked**.
   - Select the directory containing the extension files.

3. ðŸ“Œ **Pin the Extension**:
   - Click the puzzle piece icon (Extensions) in your toolbar.
   - Find **NPM-SECURITY-SCANNER-PRO** and click the pin icon next to it.
   - Now you're ready to hunt! ðŸ•¶ï¸

---

## ðŸ‘¤ Contributors

- **Bytes_Knight** - ðŸ›¡ï¸ Creator and Maintainer  
  Bugcrowd: [@Bytes_Knight](https://bugcrowd.com/h/Bytes_Knight) | [![GitHub](https://img.shields.io/badge/GitHub-bytes--Knight-181717?style=flat&logo=github)](https://github.com/bytes-Knight)

---

## ðŸ¤ Contributing

Contributions are welcome! If you have ideas for improvements, new features, or bug fixes, please follow these steps:

1. **Fork the repository.**
2. **Create a new branch** (`git checkout -b feature/your-feature-name`).
3. **Make your changes.**
4. **Commit your changes** (`git commit -m 'Add some feature'`).
5. **Push to the branch** (`git push origin feature/your-feature-name`).
6. **Open a pull request.**

Alternatively, you can open an issue to discuss your ideas or report a bug.

---

## ðŸ“œ License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## ðŸ—‚ï¸ Potential TODOs

- [ ] Add support for scanning `pnpm-lock.yaml` files directly
- [ ] Implement dark/light mode toggle (currently Dark Mode only)
- [ ] Add integration with Snyk or Socket.dev APIs
- [ ] Expand support for Firefox and Edge

---

## ðŸ”’ Privacy Note

- **NPM-SECURITY-SCANNER-PRO** performs all scanning **locally** within your browser.
- It only communicates with the public npm registry (`registry.npmjs.org`) to verify package details.
- No private data is collected, stored, or transmitted to any third-party servers.
- 100% open source for transparency and auditing.

---

> ðŸ§ª *NPM-SECURITY-SCANNER-PRO - built by a hunter, for hunters.*
> Because supply chain security shouldn't be a black box.


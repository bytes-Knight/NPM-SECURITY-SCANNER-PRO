# 🧪 NPM-SECURITY-SCANNER-PRO

**NPM-SECURITY-SCANNER-PRO** is a browser extension built for **security researchers**, **developers**, and **DevSecOps pros** who demand speed, accuracy, and deep visibility.
It's your go-to tool for detecting **dependency confusion**, **unregistered packages**, and **exposed secrets** directly from any web application in real-time.

Whether you're auditing a target, securing your own app, or hunting for supply chain vulnerabilities, **NPM-SECURITY-SCANNER-PRO** makes risk detection fast, smart, and deadly efficient. 🧨

---
## ✨ Features

### 🕵️ Advanced Scanning Modes
*Fully compatible with modern bundlers and frameworks.*

- 🔍 **Deep Crawl**: Recursively crawls linked JavaScript files and source maps to uncover hidden dependencies that aren't immediately visible.
- 🧾 **Page Source Scan**: Instantly extracts npm packages defined in the initial HTML and inline scripts.
- 🧩 **Bundler Analysis**: Deconstructs Webpack, Vite, Parcel, and SystemJS bundles to find every single included library.
- 🔓 **Exposed Files**: Automatically checks for sensitive files like `.env`, `package.json`, and `Dockerfile` that shouldn't be public.

### 🧠 Intelligent Threat Detection
- ⚠️ **Dependency Confusion**: Identifies internal package names that are NOT registered on the public npm registry - a critical supply chain vector.
- 🧬 **Typosquatting**: Flags packages with suspicious names that mimic popular libraries (for example, `react-dom-binding` vs `react-dom`).
- 🕰️ **Abandoned Packages**: Warns you about packages that haven't been updated in years or have dangerously low download counts.

### 🖥️ Hacker-Grade Workflow
- 🧑‍💻 **Terminal UI**: A retro, hacker-style interface that makes viewing results feel like you're in the matrix.
- 🧷 **Live Badges**: Get immediate visual feedback on the extension icon with risk counts (Red for Critical, Yellow for Warning).
- 📄 **One-Click Export**: Download a comprehensive **HTML Report** of your findings, styled and ready for client presentation.
- 🧹 **Soft 404 Filtering**: Smart logic to ignore false positives from Single Page Applications (SPAs).

---

## 🧭 How to Use

1. 🌐 **Navigate to a Target**: Go to any website you want to audit.
2. ⚡ **Auto-Scan Initiates**: The extension automatically starts scanning in the background.
3. 🏷️ **Check the Badge**:
   - 🟢 **Green**: Clean.
   - 🟡 **Yellow**: Warnings found.
   - 🔴 **Red**: Critical risks detected.
4. 🧩 **Open the Terminal**: Click the **NPM-SECURITY-SCANNER-PRO** icon to view the detailed "Hacker Terminal" dashboard.
5. 📤 **Analyze and Export**: Review the findings and click **`SAVE RESULTS`** to generate a full HTML report.

---

## 🖼️ Screenshots

### Terminal Dashboard
*View critical risks and package details in a high-contrast terminal interface.*

<!-- Placeholder for screenshot -->
<div align="center">
  <img src="icon128.png" alt="Extension Icon" width="128" height="128" />
</div>

---

## 🧾 Changelog

### v3.0.0 (Latest)
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

## 🧩 Installation Guide

1. 📥 **Download the Extension**:
   - Click the green **Code** button on this repository page.
   - Select **Download ZIP** and save the file.
   - Unzip the downloaded file.

2. 🧭 **Load the Extension in Your Browser**:
   - Open Chrome and navigate to `chrome://extensions`.
   - Enable **Developer mode** using the toggle in the top-right corner.
   - Click **Load unpacked**.
   - Select the directory containing the extension files.

3. 📌 **Pin the Extension**:
   - Click the puzzle piece icon (Extensions) in your toolbar.
   - Find **NPM-SECURITY-SCANNER-PRO** and click the pin icon next to it.
   - Now you're ready to hunt! 🕶️

---

## 👤 Contributors

- **Bytes_Knight** - 🛡️ Creator and Maintainer  
  Bugcrowd: [@Bytes_Knight](https://bugcrowd.com/h/Bytes_Knight) | [![GitHub](https://img.shields.io/badge/GitHub-bytes--Knight-181717?style=flat&logo=github)](https://github.com/bytes-Knight)

---

## 🤝 Contributing

Contributions are welcome! If you have ideas for improvements, new features, or bug fixes, please follow these steps:

1. **Fork the repository.**
2. **Create a new branch** (`git checkout -b feature/your-feature-name`).
3. **Make your changes.**
4. **Commit your changes** (`git commit -m 'Add some feature'`).
5. **Push to the branch** (`git push origin feature/your-feature-name`).
6. **Open a pull request.**

Alternatively, you can open an issue to discuss your ideas or report a bug.

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 🗂️ Potential TODOs

- [ ] Add support for scanning `pnpm-lock.yaml` files directly
- [ ] Implement dark/light mode toggle (currently Dark Mode only)
- [ ] Add integration with Snyk or Socket.dev APIs
- [ ] Expand support for Firefox and Edge

---

## 🔒 Privacy Note

- **NPM-SECURITY-SCANNER-PRO** performs all scanning **locally** within your browser.
- It only communicates with the public npm registry (`registry.npmjs.org`) to verify package details.
- No private data is collected, stored, or transmitted to any third-party servers.
- 100% open source for transparency and auditing.

---

> 🧪 *NPM-SECURITY-SCANNER-PRO - built by a hunter, for hunters.*
> Because supply chain security shouldn't be a black box.

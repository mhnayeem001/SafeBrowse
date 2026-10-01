# SafeBrowse X — Chrome Web Store Submission Checklist

This document details the checklist and permission justifications required for submitting the SafeBrowse X extension to the Google Chrome Web Store.

---

## 📋 Pre-Submission Checklist

- [x] **Manifest V3 Standard**: Verified no deprecated Manifest V2 APIs are used.
- [x] **Zero Remote Code Execution**: No `eval()`, `new Function()`, or dynamically downloaded remote scripts.
- [x] **Assets & Icons**: All required icon sizes included (`icon16.png`, `icon32.png`, `icon48.png`, `icon128.png`).
- [x] **Package Archive**: Created clean ZIP archive containing only runtime extension files (`release/safebrowse-extension.zip`).
- [x] **Privacy Policy**: Comprehensive privacy documentation provided in `docs/PRIVACY.md`.
- [x] **Single Purpose**: Focused strictly on defensive browser threat detection and anti-phishing protection.

---

## 🔑 Manifest V3 Permission Justifications

| Permission | Purpose & Justification |
| :--- | :--- |
| `declarativeNetRequest` | Used to enforce instantaneous, privacy-preserving block rules for confirmed malicious endpoints. |
| `webNavigation` | Required to intercept top-level navigation (`onBeforeNavigate`) and evaluate site reputation before malicious payloads load. |
| `storage` | Required to store user security settings, local whitelists, blacklists, and fast dual-layer reputation cache. |
| `alarms` | Required to schedule periodic cache evictions and background signature updates. |
| `downloads` | Required to inspect incoming filenames for masqueraded double extensions (e.g. `invoice.pdf.exe`) and alert users. |
| `notifications` | Used to display non-intrusive security alerts when dangerous downloads or active exploits are intercepted. |
| `tabs` | Required to query current active tab URL in popup and redirect blocked navigation to the local warning page. |
| `<all_urls>` (host_permissions) | Necessary for universal real-time threat protection across all web destinations visited by the user. |

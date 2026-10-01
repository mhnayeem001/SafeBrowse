# SafeBrowse X — Chrome Extension API Boundaries & Known Limitations

To maintain transparency and adhere to honest engineering principles, this document outlines technical boundaries imposed by the modern Chrome Manifest V3 extension security model and how SafeBrowse X addresses them.

---

## 1. Pre-Navigation Blocking Boundaries in Manifest V3

### Platform Behavior
In Chrome Manifest V3, synchronous blocking via `webRequest` has been deprecated in favor of `declarativeNetRequest` and `webNavigation` asynchronous events.

### SafeBrowse X Implementation & Mitigation
* **Instant Local Matching**: Known blacklisted and brand-spoofed domains are evaluated in $<1\text{ ms}$ synchronously in the service worker and immediately redirected via `chrome.tabs.update()` to `warning/warning.html`.
* **Declarative Rules**: Confirmed static malicious domain signatures are compiled into declarative net request rules.
* **Content Script Guard Fallback**: If an unknown site finishes initial handshake before an asynchronous cloud reputation response arrives, the content script monitors DOM mutations and halts sensitive form interactions immediately upon receiving a `BLOCK` signal.

---

## 2. Antivirus & Binary Malware Scanning Boundaries

### Platform Behavior
Chrome extensions execute in a sandboxed JavaScript runtime and do not possess OS kernel privileges or raw disk access to execute in-depth binary signature / heuristic antivirus scanning.

### SafeBrowse X Implementation & Mitigation
* SafeBrowse X clearly distinguishes **"Suspicious / Dangerous Download Pattern"** (e.g. double extension `.pdf.exe`, MIME mismatch, or hosted on known malware C2 domains) from full OS-level antivirus binary scans.
* SafeBrowse X pauses or cancels high-risk masqueraded downloads and alerts the user without falsely claiming to replace a complete endpoint detection and response (EDR) antivirus suite.

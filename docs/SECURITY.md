# SafeBrowse X — Defensive Security Architecture & Threat Model

## 1. Threat Modeling Overview

SafeBrowse X is designed to defend end-users against modern browser-borne attacks while ensuring defense-in-depth and zero backend exploitation vectors.

### Primary Threat Vectors Addressed
1. **Phishing & Credential Harvesting**: Fake login pages crafted on lookalike domains targeting financial, cloud, and social platforms.
2. **Brand Impersonation & Typosquatting**: Visual homoglyphs (e.g. Cyrillic letters replacing Latin, `paypa1`, `g00gle`) and unauthorized brand compounds.
3. **Malicious Downloads & Masquerading Executables**: Attackers using double extensions (e.g., `invoice.pdf.exe`, `photo.jpg.scr`) to disguise malware payloads.
4. **Suspicious Redirect Chains**: Multi-hop redirection hopping through throwaway domains to bypass basic blocklists.
5. **Notification Permission Spam**: Social engineering lures demanding notification permissions ("Click Allow to verify you're human").

---

## 2. Server-Side Request Forgery (SSRF) Protection

Because threat intelligence backends must inspect URLs and redirect targets, SSRF is a critical risk vector. SafeBrowse X implements strict multi-layer SSRF safeguards in `backend/app/security/ssrf.py`:

* **Subnet & IP Blacklist**: Blocks all private IPv4 addresses (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopbacks (`127.0.0.0/8`), link-local / cloud metadata services (`169.254.169.254`, `100.100.100.200`), carrier-grade NAT (`100.64.0.0/10`), broadcast, and reserved ranges.
* **IPv6 Filtering**: Prohibits IPv6 loopbacks (`::1`), link-local (`fe80::/10`), unique local (`fc00::/7`), and IPv4-mapped IPv6 (`::ffff:0:0/96`).
* **DNS Resolution Verification**: Pre-resolves target hostnames via system DNS and validates every resolved IP against the IP blacklist prior to initiating outbound HTTP connections, neutralizing DNS rebinding attacks.
* **Strict Scheme & Port Restrictions**: Only `http` and `https` schemes on standard ports (80, 443, 8080, 8443) are accepted. Prohibits dangerous schemes like `file://`, `gopher://`, `dict://`, or internal IPC.
* **Safe Redirect Tracing**: Outbound redirect chains are re-validated hop-by-hop up to a maximum limit of 5 hops with a 3.0s timeout and a 1MB response size cap.

---

## 3. Explainable Adaptive Risk Engine

SafeBrowse X avoids "black-box" decisions. Every classification is computed using transparent, explainable deterministic signals:

$$\text{Final Risk} = f(\text{URL Risk}, \text{Domain Entropy}, \text{Typosquatting Score}, \text{DOM Credential Signals}, \text{Threat Feeds})$$

Every `BLOCK` or `WARN` decision includes a structured `reasons` list displayed on the user's Warning Screen and logged in the Security Center.

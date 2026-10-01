# SafeBrowse X — Privacy Policy & Data Handling Guarantees

SafeBrowse X is engineered with a **Privacy-First Defensive Architecture**. Protecting users against browser threats must never compromise personal browsing privacy or credential security.

---

## 🔒 Absolute Privacy Commitments

1. **ZERO Credential Logging**:
   - SafeBrowse X **NEVER captures, logs, or transmits plaintext passwords, OTP tokens, recovery codes, or credit card numbers**.
   - The DOM content script only checks boolean structural metadata (e.g. `has_password: true`, `input_count: 2`, `is_cross_origin: false`).

2. **NO Form Content Exfiltration**:
   - Field values, user keystrokes, personal identity inputs, and private message contents are strictly untouched.

3. **Minimal Telemetry & Hashing**:
   - Known-safe domains are resolved instantly on the client machine via local whitelist and dual-layer cache without making backend network calls.
   - URLs sent to the backend for analysis are stripped of personal userinfo (e.g. `http://user:pass@host` has credentials stripped during normalization).

4. **No Third-Party Data Monetization**:
   - Browsing activity and telemetry logs are solely used for defensive threat mitigation within the user's or organization's deployment. SafeBrowse X does not sell or share telemetry with data brokers.

---

## 📊 Privacy Mode Tiers

Users can configure privacy sensitivity in the extension options:

| Privacy Mode | Behavior & Telemetry |
| :--- | :--- |
| **MINIMAL** | Maximizes local client evaluation; queries backend only for unknown domains flagged with high local structural risk. |
| **BALANCED** (Default) | Uses local whitelist/blacklist/cache first; queries backend asynchronously for unknown domains. |
| **MAXIMUM PROTECTION** | Performs full heuristic and DOM metadata verification on unvetted websites. |

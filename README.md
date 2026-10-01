# SafeBrowse X — Professional Real-Time Browser Threat Protection Platform

SafeBrowse X is a production-grade defensive browser security platform engineered with a **Chrome Manifest V3 Extension**, a **FastAPI Threat Intelligence Backend**, and a **Security Operations Dashboard (React)**.

The product adheres strictly to the primary design principle:
> **MAXIMUM PROTECTION WITH MINIMUM USER INTERRUPTION.**

---

## 🛡️ Key Features

* **Pre-Navigation Interception**: Intercepts malicious links before page loading commences via Chrome Manifest V3 APIs.
* **Local-First Threat Engine**: Sub-5ms deterministic evaluation using local whitelist, blacklist, homoglyph matcher, and dual-layer LRU/TTL cache.
* **Typosquatting & Brand Spoof Defense**: Damerau-Levenshtein edit distance algorithms, visual Unicode confusables normalization, and protected brand database.
* **SSRF Guarded Cloud API**: Hardened FastAPI security backend with comprehensive private IP range filtering, link-local / cloud metadata blocking, DNS rebinding mitigation, and safe redirect validation.
* **Credential Form Shield**: Inspects DOM input metadata to detect credential harvesting forms on untrusted domains **without capturing or transmitting user passwords or OTP values**.
* **Download Masquerade Protection**: Flags double extensions (e.g. `.pdf.exe`, `.jpg.scr`) and executable disguises before disk write.
* **Real-Time Security Dashboard**: WebSocket-driven Live Threat Monitor, URL & Domain Intelligence Scanner, Rule Configurator, and System Health Observability.

---

## 📁 Repository Structure

```
SafeBrowse/
├── backend/                  # FastAPI Python Threat Intelligence Core
│   ├── app/
│   │   ├── main.py           # FastAPI application entrypoint & middleware
│   │   ├── config.py         # Configuration settings & environment variables
│   │   ├── database.py       # SQLAlchemy async database session factory
│   │   ├── security/         # SSRF protection and JWT authentication
│   │   ├── models/           # Database models (Events, Whitelist, Blacklist, Rules)
│   │   ├── schemas/          # Pydantic v2 schemas
│   │   ├── engines/          # URL Normalizer, Domain Intel, Typosquatting, Phishing, Risk
│   │   ├── services/         # Threat Intel aggregator, Cache, and WebSocket broadcaster
│   │   └── api/v1/           # Scan, Reputation, Events, Lists, Rules, and Health endpoints
│   ├── tests/                # Automated pytest test suite (SSRF, Heuristics, API)
│   ├── requirements.txt      # Python dependencies
│   ├── .env.example          # Environment variables template
│   └── Dockerfile            # Container deployment
│
├── extension/                # Chrome Manifest V3 Extension
│   ├── manifest.json         # Extension manifest V3
│   ├── background/           # Background Service Worker
│   ├── content/              # Privacy-safe DOM metadata inspector
│   ├── popup/                # Popup UI (Threat meter, mode toggle, whitelist shortcut)
│   ├── warning/              # Explainable threat blocked warning screen
│   ├── options/              # Settings, backend URL, and local lists manager
│   ├── utils/                # Normalizer, brand matcher, and local dual-layer cache
│   └── assets/               # Standard icons (16, 32, 48, 128px)
│
├── dashboard/                # Security Operations Center (React + Vite)
│   ├── src/
│   │   ├── components/       # LiveFeed, UrlScanner, ListsManager, Rules, SystemHealth
│   │   ├── App.jsx           # Master dashboard view
│   │   └── index.css         # Cybersecurity dark theme design system
│   ├── package.json          # Node dependencies
│   └── Dockerfile            # Multi-stage Nginx container
│
├── docs/                     # Technical, Security & Compliance Documentation
│   ├── SECURITY.md           # Threat modeling, SSRF defense, and AI/heuristics
│   ├── PRIVACY.md            # Privacy policy & zero-password capture guarantee
│   ├── DEPLOYMENT.md         # Docker & production installation guide
│   ├── CHROME_STORE_CHECKLIST.md # Chrome Web Store submission guidelines
│   └── API_LIMITATIONS.md    # Known Chrome Manifest V3 platform boundaries
│
├── release/                  # Production artifacts & Web Store ZIP package
│   └── safebrowse-extension.zip
│
├── scripts/                  # Packaging & asset generation utilities
└── docker-compose.yml        # Multi-service stack (API, PostgreSQL, Redis, Dashboard)
```

---

## 🚀 Quick Start Guide

### 1. Running the FastAPI Backend
```bash
cd backend
python -m venv .venv
# On Windows: .venv\Scripts\activate
# On Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```
API Documentation will be available at `http://localhost:8000/docs`.

### 2. Running the Security Dashboard
```bash
cd dashboard
npm install
npm run dev
```
Dashboard will be available at `http://localhost:5173`.

### 3. Loading the Chrome Extension
1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle in upper right).
3. Click **Load unpacked** and select the `extension/` directory.
4. The SafeBrowse X shield icon will appear in your browser toolbar.

### 4. Running the Multi-Container Production Stack
```bash
docker-compose up --build -d
```

---

## 🧪 Running Automated Tests

SafeBrowse X includes unit and integration tests verifying SSRF protection, brand spoofing algorithms, URL normalization, and API routes:

```bash
python -m pytest backend/tests
```

---

## 📦 Chrome Extension Release Package

To generate an updated release package:
```bash
python scripts/package_extension.py
```
The resulting archive is saved to `release/safebrowse-extension.zip`.

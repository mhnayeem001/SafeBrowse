# Changelog

All notable changes to the SafeBrowse X Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-01

### Added
- **Chrome Manifest V3 Extension**:
  - Declarative & `webNavigation` pre-navigation threat interception.
  - Sub-5ms deterministic local evaluation engine with dual-layer memory + `chrome.storage.local` caching.
  - Non-invasive DOM metadata content script for credential harvesting detection without logging passwords.
  - Download masquerade protection monitoring double extensions (`.pdf.exe`, `.jpg.scr`) and executable disguises.
  - Popup interface with live threat meter, security mode toggle, and quick-whitelist controls.
  - Explainable Warning Screen with granular diagnostic breakdown and return-to-safety actions.
  - Options UI for backend API endpoint configuration and local lists management.
- **FastAPI Threat Intelligence Backend**:
  - URL Normalization Engine handling Unicode, punycode, IP-hosts, and nested redirect parameters.
  - Domain Intelligence Engine analyzing TLD risk tiers, DGA Shannon entropy, and suspicious structural keywords.
  - Typosquatting & Brand Spoof Engine utilizing Damerau-Levenshtein distance and visual homoglyphs normalization.
  - SSRF Security Layer blocking all RFC 1918 private subnets, cloud metadata IPs (`169.254.169.254`), loopbacks, and non-HTTP schemes.
  - Multi-Signal Adaptive Risk and Confidence Scoring Engine.
  - PostgreSQL models and async SQLAlchemy database migrations with SQLite local fallback.
  - Real-time WebSocket event broadcaster for live telemetry streaming.
  - REST API endpoints for scans, reputation, lists, rules, stats, and health metrics.
- **Security Operations Dashboard (React + Vite)**:
  - Live Telemetry Stream with interactive filtering and WebSocket connectivity.
  - Threat Intelligence & Deep URL Scanner with explainable heuristics findings.
  - Whitelist and Blacklist manager with search and CRUD operations.
  - Adaptive Threat Rules and Heuristic Shields toggle.
  - False Positive review queue for user feedback.
  - Infrastructure and System Health monitoring panel.
- **Packaging & DevOps**:
  - Automated Chrome Extension ZIP packager script.
  - Multi-service Docker Compose configuration (API, PostgreSQL, Redis, Dashboard).
  - Comprehensive documentation suite (Security, Privacy, Deployment, Web Store checklist, API limitations).

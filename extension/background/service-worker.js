/**
 * SafeBrowse X - Background Service Worker (Manifest V3)
 * Core Real-Time Pre-Navigation & Download Security Engine
 */

import { normalizeURL } from '../utils/url-normalize.js';
import { checkBrandSpoofLocal } from '../utils/brand-matcher.js';
import { reputationCache } from '../utils/cache.js';

const DEFAULT_CONFIG = {
  enabled: true,
  backendUrl: 'http://127.0.0.1:8000',
  securityMode: 'NORMAL', // NORMAL, STRICT, MAXIMUM
  privacyMode: 'BALANCED', // MINIMAL, BALANCED, MAXIMUM
  whitelist: [
    'google.com', 'microsoft.com', 'microsoftonline.com', 'live.com', 'office.com',
    'apple.com', 'github.com', 'wikipedia.org', 'mozilla.org', 'amazon.com',
    'youtube.com', 'facebook.com', 'instagram.com', 'linkedin.com', 'twitter.com',
    'x.com', 'partner.microsoft.com', 'azure.com', 'windows.net'
  ],
  blacklist: [
    'malware-traffic-analysis.net', 'evil-phishing-test.com',
    'secure-login-apple-support-verify.com', 'paypal-security-alert-center.top'
  ],
};

// Initialize settings on install
chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get(['config']);
  if (!existing.config) {
    await chrome.storage.local.set({ config: DEFAULT_CONFIG });
  } else {
    // Merge any missing safe whitelist items
    const mergedWl = Array.from(new Set([...(existing.config.whitelist || []), ...DEFAULT_CONFIG.whitelist]));
    existing.config.whitelist = mergedWl;
    await chrome.storage.local.set({ config: existing.config });
  }
  console.log('[SafeBrowse X] Extension initialized successfully.');
});

// Helper to get active configuration
async function getConfig() {
  const result = await chrome.storage.local.get(['config']);
  return result.config || DEFAULT_CONFIG;
}

// Check if domain is in local whitelist
function isWhitelisted(domain, whitelist) {
  if (!domain || !whitelist) return false;
  return whitelist.some(item => domain === item || domain.endsWith('.' + item));
}

// Check if domain is in local blacklist
function isBlacklisted(domain, blacklist) {
  if (!domain || !blacklist) return false;
  return blacklist.some(item => domain === item || domain.endsWith('.' + item));
}

// Pre-Navigation Interception via webNavigation
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only intercept top-level navigation
  if (details.frameId !== 0) return;

  const config = await getConfig();
  if (!config.enabled) return;

  const norm = normalizeURL(details.url);
  if (!norm.isValid || norm.isInternal) return;

  // 1. Check Local Whitelist (Instant ALLOW)
  if (isWhitelisted(norm.registeredDomain, config.whitelist) || isWhitelisted(norm.hostname, config.whitelist)) {
    return;
  }

  // 2. Check Local Blacklist (Instant BLOCK)
  if (isBlacklisted(norm.registeredDomain, config.blacklist) || isBlacklisted(norm.hostname, config.blacklist)) {
    redirectToWarning(details.tabId, details.url, 'BLACKLISTED', 100, 100, [
      'Domain is listed in local security blacklist'
    ]);
    return;
  }

  // 3. Check Local Cache
  const cached = await reputationCache.get(norm.normalizedUrl);
  if (cached) {
    if (cached.decision === 'BLOCK') {
      redirectToWarning(details.tabId, details.url, cached.threat_type, cached.risk_score, cached.confidence, cached.reasons);
    }
    return;
  }

  // 4. Fast Local Deterministic Heuristics
  const localSpoof = checkBrandSpoofLocal(norm.registeredDomain);
  if (localSpoof.isSpoofed) {
    redirectToWarning(details.tabId, details.url, 'BRAND_SPOOF', 95, 95, [
      localSpoof.reason,
      'Pre-navigation brand spoofing shield triggered'
    ]);
    return;
  }

  // 5. Query Cloud Backend API
  try {
    const scanPayload = {
      url: norm.normalizedUrl,
      source: 'extension_pre_nav',
      client_version: '1.0.0'
    };

    const response = await fetch(`${config.backendUrl}/api/v1/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(scanPayload),
    });

    if (response.ok) {
      const data = await response.json();
      await reputationCache.set(norm.normalizedUrl, data);

      if (data.decision === 'BLOCK') {
        redirectToWarning(details.tabId, details.url, data.threat_type, data.risk_score, data.confidence, data.reasons);
      }
    }
  } catch (err) {
    // Fail-safe: In case backend is offline, do NOT break normal user browsing!
    console.warn('[SafeBrowse X] Backend unreachable, falling back to local protection:', err.message);
  }
});

// Helper to redirect unsafe tab to the Warning Page
function redirectToWarning(tabId, blockedUrl, threatType, riskScore, confidence, reasons) {
  const warningUrl = chrome.runtime.getURL('warning/warning.html') + 
    `?url=${encodeURIComponent(blockedUrl)}` +
    `&threat=${encodeURIComponent(threatType || 'MALICIOUS')}` +
    `&risk=${encodeURIComponent(riskScore || 90)}` +
    `&confidence=${encodeURIComponent(confidence || 95)}` +
    `&reasons=${encodeURIComponent(JSON.stringify(reasons || []))}`;

  chrome.tabs.update(tabId, { url: warningUrl });
}

// Download Protection Monitor
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const config = await getConfig();
  if (!config.enabled) return;

  const filename = (downloadItem.filename || '').toLowerCase();
  const downloadUrl = downloadItem.url || '';

  // Double extension detection (.pdf.exe, .jpg.scr, etc.)
  const parts = filename.split('.');
  if (parts.length >= 3) {
    const penultimate = '.' + parts[parts.length - 2];
    const finalExt = '.' + parts[parts.length - 1];
    const riskyFinal = ['.exe', '.scr', '.vbs', '.bat', '.ps1', '.hta', '.cmd'];
    const fakeDocs = ['.pdf', '.doc', '.docx', '.jpg', '.png', '.xlsx', '.zip'];

    if (fakeDocs.includes(penultimate) && riskyFinal.includes(finalExt)) {
      try {
        await chrome.downloads.pause(downloadItem.id);
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'assets/icon128.png',
          title: 'SafeBrowse X — Suspicious Download Intercepted',
          message: `Blocked double-extension executable disguised as a document: "${filename}".`,
          priority: 2
        });
      } catch (e) {}
    }
  }
});

// Message Listener for Content Scripts & Popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'PAGE_DOM_ANALYSIS') {
    handlePageDOMAnalysis(message.data, sender.tab?.id);
    sendResponse({ status: 'received' });
    return true;
  }

  if (message.type === 'GET_TAB_STATUS') {
    handleGetTabStatus(message.url).then(sendResponse);
    return true;
  }

  if (message.type === 'ADD_WHITELIST') {
    handleAddWhitelist(message.domain).then(sendResponse);
    return true;
  }
});

async function handlePageDOMAnalysis(pageData, tabId) {
  if (!pageData || !pageData.url) return;
  const config = await getConfig();
  if (!config.enabled) return;

  try {
    const res = await fetch(`${config.backendUrl}/api/v1/scan/page`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(pageData),
    });

    if (res.ok) {
      const data = await res.json();
      if (data.decision === 'BLOCK' && tabId) {
        redirectToWarning(tabId, pageData.url, data.threat_type, data.risk_score, data.confidence, data.reasons);
      }
    }
  } catch (e) {
    // Fail-safe
  }
}

async function handleGetTabStatus(url) {
  if (!url) return { status: 'SAFE', risk: 0, confidence: 99 };
  const norm = normalizeURL(url);
  const config = await getConfig();

  if (isWhitelisted(norm.registeredDomain, config.whitelist) || isWhitelisted(norm.hostname, config.whitelist)) {
    return { status: 'SAFE', risk: 0, confidence: 99, domain: norm.registeredDomain, reasons: ['In verified whitelist'] };
  }

  if (isBlacklisted(norm.registeredDomain, config.blacklist) || isBlacklisted(norm.hostname, config.blacklist)) {
    return { status: 'BLOCKED', risk: 100, confidence: 100, domain: norm.registeredDomain, reasons: ['In security blacklist'] };
  }

  const cached = await reputationCache.get(norm.normalizedUrl);
  if (cached) {
    return {
      status: cached.decision === 'BLOCK' ? 'DANGEROUS' : (cached.decision === 'WARN' ? 'SUSPICIOUS' : 'SAFE'),
      risk: cached.risk_score,
      confidence: cached.confidence,
      threat_type: cached.threat_type,
      domain: norm.registeredDomain,
      reasons: cached.reasons,
    };
  }

  return { status: 'SAFE', risk: 5, confidence: 90, domain: norm.registeredDomain, reasons: ['No active threats detected'] };
}

async function handleAddWhitelist(domain) {
  const config = await getConfig();
  if (!config.whitelist.includes(domain)) {
    config.whitelist.push(domain);
    await chrome.storage.local.set({ config });
    try {
      await fetch(`${config.backendUrl}/api/v1/whitelist`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain_or_url: domain, match_type: 'domain', reason: 'Added from extension' })
      });
    } catch (e) {}
  }
  return { success: true };
}

/**
 * SafeBrowse X - Popup Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  const currentDomainEl = document.getElementById('currentDomain');
  const verdictBadgeEl = document.getElementById('verdictBadge');
  const riskScoreEl = document.getElementById('riskScore');
  const confidenceScoreEl = document.getElementById('confidenceScore');
  const meterFillEl = document.getElementById('meterFill');
  const primaryReasonEl = document.getElementById('primaryReason');
  const protectionToggle = document.getElementById('protectionToggle');
  const protectionBadge = document.getElementById('protectionBadge');
  const modeSelect = document.getElementById('modeSelect');
  const whitelistBtn = document.getElementById('whitelistBtn');
  const reportBtn = document.getElementById('reportBtn');

  // 1. Load config
  const storage = await chrome.storage.local.get(['config']);
  const config = storage.config || {};

  protectionToggle.checked = config.enabled !== false;
  modeSelect.value = config.securityMode || 'NORMAL';
  updateProtectionBadge(protectionToggle.checked);

  // 2. Query active tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let activeUrl = tab ? tab.url : '';
  let activeDomain = '';

  if (activeUrl && !activeUrl.startsWith('chrome') && !activeUrl.startsWith('about')) {
    try {
      activeDomain = new URL(activeUrl).hostname;
      currentDomainEl.textContent = activeDomain;

      // Ask background script for active tab security status
      chrome.runtime.sendMessage({ type: 'GET_TAB_STATUS', url: activeUrl }, (response) => {
        if (response) {
          renderStatus(response);
        }
      });
    } catch (e) {
      currentDomainEl.textContent = 'Browser Internal';
    }
  } else {
    currentDomainEl.textContent = 'System Page';
  }

  function renderStatus(statusData) {
    const risk = statusData.risk || 0;
    const confidence = statusData.confidence || 90;
    const verdict = statusData.status || 'SAFE';

    riskScoreEl.textContent = `${risk}/100`;
    confidenceScoreEl.textContent = `${confidence}%`;
    meterFillEl.style.width = `${Math.max(5, risk)}%`;

    verdictBadgeEl.className = 'verdict-badge';
    if (verdict === 'BLOCKED' || verdict === 'DANGEROUS') {
      verdictBadgeEl.classList.add('blocked');
      verdictBadgeEl.textContent = 'THREAT';
      meterFillEl.style.backgroundColor = 'var(--danger-crimson)';
    } else if (verdict === 'SUSPICIOUS') {
      verdictBadgeEl.classList.add('suspicious');
      verdictBadgeEl.textContent = 'WARNING';
      meterFillEl.style.backgroundColor = 'var(--warn-amber)';
    } else {
      verdictBadgeEl.classList.add('safe');
      verdictBadgeEl.textContent = 'SAFE';
      meterFillEl.style.backgroundColor = 'var(--safe-emerald)';
    }

    if (statusData.reasons && statusData.reasons.length > 0) {
      primaryReasonEl.textContent = statusData.reasons[0];
    } else {
      primaryReasonEl.textContent = 'No threat signatures or malicious patterns';
    }
  }

  function updateProtectionBadge(isEnabled) {
    if (isEnabled) {
      protectionBadge.className = 'status-pill active';
      protectionBadge.textContent = 'ACTIVE';
    } else {
      protectionBadge.className = 'status-pill paused';
      protectionBadge.textContent = 'PAUSED';
    }
  }

  // Toggle protection
  protectionToggle.addEventListener('change', async () => {
    config.enabled = protectionToggle.checked;
    await chrome.storage.local.set({ config });
    updateProtectionBadge(protectionToggle.checked);
  });

  // Change Security Mode
  modeSelect.addEventListener('change', async () => {
    config.securityMode = modeSelect.value;
    await chrome.storage.local.set({ config });
  });

  // Add to Whitelist
  whitelistBtn.addEventListener('click', async () => {
    if (activeDomain) {
      chrome.runtime.sendMessage({ type: 'ADD_WHITELIST', domain: activeDomain }, () => {
        whitelistBtn.textContent = 'Trusted!';
        whitelistBtn.style.color = 'var(--safe-emerald)';
        setTimeout(() => {
          whitelistBtn.textContent = 'Trust This Domain';
          whitelistBtn.style.color = '';
        }, 2000);
      });
    }
  });

  // Report Issue
  reportBtn.addEventListener('click', () => {
    if (activeUrl) {
      chrome.tabs.create({
        url: `http://localhost:5173/reports?url=${encodeURIComponent(activeUrl)}`
      });
    }
  });
});

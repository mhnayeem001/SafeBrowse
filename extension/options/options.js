/**
 * SafeBrowse X - Options Controller
 */

import { reputationCache } from '../utils/cache.js';

document.addEventListener('DOMContentLoaded', async () => {
  const backendUrlInput = document.getElementById('backendUrl');
  const securityModeSelect = document.getElementById('securityMode');
  const privacyModeSelect = document.getElementById('privacyMode');
  const whitelistTagsEl = document.getElementById('whitelistTags');
  const blacklistTagsEl = document.getElementById('blacklistTags');
  const newWhitelistItem = document.getElementById('newWhitelistItem');
  const newBlacklistItem = document.getElementById('newBlacklistItem');
  const addWhitelistBtn = document.getElementById('addWhitelistBtn');
  const addBlacklistBtn = document.getElementById('addBlacklistBtn');
  const clearCacheBtn = document.getElementById('clearCacheBtn');
  const testConnBtn = document.getElementById('testConnBtn');
  const connResult = document.getElementById('connResult');
  const saveStatus = document.getElementById('saveStatus');

  // Load config
  const storage = await chrome.storage.local.get(['config']);
  const config = storage.config || {
    backendUrl: 'http://127.0.0.1:8000',
    securityMode: 'NORMAL',
    privacyMode: 'BALANCED',
    whitelist: ['google.com', 'microsoft.com', 'apple.com', 'github.com'],
    blacklist: ['malware-traffic-analysis.net', 'evil-phishing-test.com'],
  };

  backendUrlInput.value = config.backendUrl || 'http://127.0.0.1:8000';
  securityModeSelect.value = config.securityMode || 'NORMAL';
  privacyModeSelect.value = config.privacyMode || 'BALANCED';

  function renderTags() {
    // Whitelist
    whitelistTagsEl.innerHTML = '';
    config.whitelist.forEach((dom, index) => {
      const tag = document.createElement('span');
      tag.className = 'tag-item';
      tag.innerHTML = `${dom} <span class="remove-tag" data-type="wl" data-idx="${index}">&times;</span>`;
      whitelistTagsEl.appendChild(tag);
    });

    // Blacklist
    blacklistTagsEl.innerHTML = '';
    config.blacklist.forEach((dom, index) => {
      const tag = document.createElement('span');
      tag.className = 'tag-item';
      tag.innerHTML = `${dom} <span class="remove-tag" data-type="bl" data-idx="${index}">&times;</span>`;
      blacklistTagsEl.appendChild(tag);
    });
  }

  renderTags();

  async function saveConfig() {
    config.backendUrl = backendUrlInput.value.trim().replace(/\/+$/, '');
    config.securityMode = securityModeSelect.value;
    config.privacyMode = privacyModeSelect.value;
    await chrome.storage.local.set({ config });
    saveStatus.textContent = 'Changes saved successfully';
    setTimeout(() => { saveStatus.textContent = 'All changes saved'; }, 2000);
  }

  backendUrlInput.addEventListener('change', saveConfig);
  securityModeSelect.addEventListener('change', saveConfig);
  privacyModeSelect.addEventListener('change', saveConfig);

  // Add Whitelist
  addWhitelistBtn.addEventListener('click', () => {
    const val = newWhitelistItem.value.trim().toLowerCase();
    if (val && !config.whitelist.includes(val)) {
      config.whitelist.push(val);
      newWhitelistItem.value = '';
      saveConfig();
      renderTags();
    }
  });

  // Add Blacklist
  addBlacklistBtn.addEventListener('click', () => {
    const val = newBlacklistItem.value.trim().toLowerCase();
    if (val && !config.blacklist.includes(val)) {
      config.blacklist.push(val);
      newBlacklistItem.value = '';
      saveConfig();
      renderTags();
    }
  });

  // Remove Tag Event delegation
  document.addEventListener('click', (e) => {
    if (e.target.classList.contains('remove-tag')) {
      const type = e.target.getAttribute('data-type');
      const idx = parseInt(e.target.getAttribute('data-idx'), 10);
      if (type === 'wl') {
        config.whitelist.splice(idx, 1);
      } else if (type === 'bl') {
        config.blacklist.splice(idx, 1);
      }
      saveConfig();
      renderTags();
    }
  });

  // Clear Cache
  clearCacheBtn.addEventListener('click', async () => {
    await reputationCache.clear();
    alert('Local reputation cache has been cleared.');
  });

  // Test Connection
  testConnBtn.addEventListener('click', async () => {
    connResult.textContent = 'Connecting to Security Core API...';
    connResult.style.color = 'var(--text-muted)';
    try {
      const res = await fetch(`${config.backendUrl}/api/v1/health`);
      if (res.ok) {
        const data = await res.json();
        connResult.textContent = `ONLINE: API operational (Status: ${data.status}, DB: ${data.database})`;
        connResult.style.color = 'var(--safe-green)';
      } else {
        connResult.textContent = `HTTP ${res.status}: Unexpected response from backend`;
        connResult.style.color = 'var(--danger-red)';
      }
    } catch (e) {
      connResult.textContent = `Connection failed: ${e.message}. Is backend server running?`;
      connResult.style.color = 'var(--danger-red)';
    }
  });
});

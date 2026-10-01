/**
 * SafeBrowse X - Fast Dual-Layer (Memory + Storage) Reputation Cache
 */

class ReputationCache {
  constructor() {
    this.memoryCache = new Map();
    this.defaultTtlMs = 15 * 60 * 1000; // 15 minutes
  }

  async get(key) {
    const now = Date.now();
    
    // Check in-memory first (<1ms)
    if (this.memoryCache.has(key)) {
      const entry = this.memoryCache.get(key);
      if (entry.expiresAt > now) {
        return entry.data;
      }
      this.memoryCache.delete(key);
    }

    // Check chrome.storage.local
    try {
      const storageKey = `cache_${key}`;
      const result = await chrome.storage.local.get(storageKey);
      if (result[storageKey]) {
        const entry = result[storageKey];
        if (entry.expiresAt > now) {
          // Re-populate memory cache
          this.memoryCache.set(key, entry);
          return entry.data;
        } else {
          await chrome.storage.local.remove(storageKey);
        }
      }
    } catch (e) {
      // Storage unavailable or errored
    }

    return null;
  }

  async set(key, data, ttlMs = this.defaultTtlMs) {
    const entry = {
      data,
      expiresAt: Date.now() + ttlMs,
    };

    // Store in memory
    this.memoryCache.set(key, entry);

    // Persist to storage
    try {
      const storageKey = `cache_${key}`;
      await chrome.storage.local.set({ [storageKey]: entry });
    } catch (e) {
      // Ignore storage write failure
    }
  }

  async clear() {
    this.memoryCache.clear();
    try {
      const all = await chrome.storage.local.get(null);
      const cacheKeys = Object.keys(all).filter(k => k.startsWith('cache_'));
      if (cacheKeys.length > 0) {
        await chrome.storage.local.remove(cacheKeys);
      }
    } catch (e) {}
  }
}

export const reputationCache = new ReputationCache();

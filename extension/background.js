



const CACHE_TTL_MS = 60 * 60 * 1000;

const CACHE_PREFIX = "phishguard_cache_";


function getDomainKey(url) {
  try {
    const parsed = new URL(url);
    return CACHE_PREFIX + parsed.hostname;
  } catch {
    return CACHE_PREFIX + url;
  }
}


chrome.runtime.onInstalled.addListener((details) => {
  console.log(`PhishGuard installed (reason: ${details.reason})`);
});



chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const { action, url, result } = message;

  if (action === "getCachedResult") {
    const key = getDomainKey(url);

    chrome.storage.local.get(key, (data) => {
      const cached = data[key];

      if (cached && cached.timestamp) {
        const age = Date.now() - cached.timestamp;
        if (age < CACHE_TTL_MS) {
          sendResponse({ result: cached.result });
          return;
        }
        chrome.storage.local.remove(key);
      }

      sendResponse({ result: null });
    });

    return true;
  }

  if (action === "cacheResult") {
    const key = getDomainKey(url);

    chrome.storage.local.set({
      [key]: {
        result,
        timestamp: Date.now(),
        url,
      },
    }, () => {
      console.log(`Cached result for ${key}`);
    });

    return false;
  }

  if (action === "clearCache") {
    const key = getDomainKey(url);

    chrome.storage.local.remove(key, () => {
      console.log(`Cleared cache for ${key}`);
    });

    return false;
  }

  return false;
});

// FILE: background.js
// PURPOSE: Service worker that caches scan results per domain in chrome.storage.local
// CONNECTS TO: extension/manifest.json, extension/popup.js
//
// FLOW: popup.js sends messages → background.js receives them
//       → reads/writes chrome.storage.local → responds to popup.js
//
// HOW TO LOAD IN CHROME:
// 1. Open chrome://extensions
// 2. Enable Developer Mode
// 3. Click Load Unpacked → select /extension folder

// =====================================================================
// WHY CACHE SCAN RESULTS?
// =====================================================================
// Without caching, every time the user clicks the PhishGuard icon on the
// same website, we'd fire a full API call to the backend.  That call
// involves:
//   • ML inference (~2 ms)
//   • VirusTotal API (~300-800 ms)
//   • URLhaus API (~200-500 ms)
//   • WHOIS lookup (~100-3000 ms)
//
// For a site the user visits 10× a day, that's 10 redundant network
// round-trips.  Caching the result per domain means the 2nd–10th clicks
// return INSTANTLY (< 1 ms) from local storage.
//
// We use a 1-hour TTL so results eventually refresh, catching cases where
// a previously-safe domain gets compromised.

// =====================================================================
// chrome.storage.local vs localStorage — WHAT'S THE DIFFERENCE?
// =====================================================================
//
//   localStorage:
//     • Standard Web API — works in regular web pages and popup.html.
//     • NOT available in service workers (background.js in MV3).
//     • Synchronous API — blocks the thread during read/write.
//     • Scoped to the popup's origin — data is lost when the popup closes
//       and re-opens if Chrome garbage-collects the context.
//     • No size tracking or events.
//
//   chrome.storage.local:
//     • Chrome extension API — works EVERYWHERE: popup, content scripts,
//       service workers, options pages.
//     • Asynchronous API — non-blocking, uses callbacks or Promises.
//     • Persists across popup open/close cycles and browser restarts.
//     • Up to 10 MB of storage (vs 5 MB for localStorage).
//     • Fires chrome.storage.onChanged events so all extension contexts
//       can react to data changes in real time.
//
//   For an extension's background service worker, chrome.storage.local
//   is the ONLY option because localStorage doesn't exist in that context.

// =====================================================================
// CONSTANTS
// =====================================================================

// Cache entries expire after 1 hour (in milliseconds).
const CACHE_TTL_MS = 60 * 60 * 1000;

// Prefix for storage keys to avoid collisions with other extension data.
const CACHE_PREFIX = "phishguard_cache_";

// =====================================================================
// HELPER: extract domain from a URL for use as a cache key
// =====================================================================

function getDomainKey(url) {
  try {
    const parsed = new URL(url);
    // Use the hostname (e.g. "example.com") as the cache key.
    // This means all paths under the same domain share one cached result,
    // which is correct because our phishing verdict is domain-level.
    return CACHE_PREFIX + parsed.hostname;
  } catch {
    return CACHE_PREFIX + url;
  }
}

// =====================================================================
// INSTALLATION EVENT
// =====================================================================

// chrome.runtime.onInstalled.addListener():
//   Fires ONCE when the extension is first installed, updated to a new
//   version, or when Chrome itself updates.  We use it for one-time setup
//   like logging or initialising default settings.
chrome.runtime.onInstalled.addListener((details) => {
  console.log(`PhishGuard installed (reason: ${details.reason})`);
});

// =====================================================================
// MESSAGE HANDLER
// =====================================================================

// chrome.runtime.onMessage.addListener():
//   Registers a listener for messages sent via chrome.runtime.sendMessage()
//   from other parts of the extension (popup.js, content scripts, etc.).
//
//   The callback receives three arguments:
//     • message    — the data object sent by the caller
//     • sender     — metadata about who sent the message (tab ID, extension ID)
//     • sendResponse — a function to call with the reply data
//
//   IMPORTANT: If the listener needs to respond asynchronously (e.g. after
//   a chrome.storage.local.get call), it MUST return `true` to tell Chrome
//   "don't close the message channel yet, I'll call sendResponse later."

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const { action, url, result } = message;

  // -----------------------------------------------------------------
  // ACTION: getCachedResult
  // popup.js asks: "Do you have a cached scan result for this domain?"
  // -----------------------------------------------------------------
  if (action === "getCachedResult") {
    const key = getDomainKey(url);

    // chrome.storage.local.get(keys, callback):
    //   Reads one or more keys from the extension's local storage.
    //   The callback receives an object with the requested key-value pairs.
    //   If a key doesn't exist, it simply won't be in the result object.
    chrome.storage.local.get(key, (data) => {
      const cached = data[key];

      if (cached && cached.timestamp) {
        const age = Date.now() - cached.timestamp;
        if (age < CACHE_TTL_MS) {
          // Cache hit — return the stored result
          sendResponse({ result: cached.result });
          return;
        }
        // Cache expired — delete it and return nothing
        chrome.storage.local.remove(key);
      }

      sendResponse({ result: null });
    });

    // Return true = "I will call sendResponse asynchronously"
    return true;
  }

  // -----------------------------------------------------------------
  // ACTION: cacheResult
  // popup.js says: "Store this scan result for this domain."
  // -----------------------------------------------------------------
  if (action === "cacheResult") {
    const key = getDomainKey(url);

    // chrome.storage.local.set(items, callback):
    //   Writes one or more key-value pairs to local storage.
    //   The data is persisted across browser restarts.
    chrome.storage.local.set({
      [key]: {
        result,
        timestamp: Date.now(),
        url,
      },
    }, () => {
      console.log(`Cached result for ${key}`);
    });

    // No async response needed — return false (default)
    return false;
  }

  // -----------------------------------------------------------------
  // ACTION: clearCache
  // popup.js says: "User clicked Rescan — delete the cache for this domain."
  // -----------------------------------------------------------------
  if (action === "clearCache") {
    const key = getDomainKey(url);

    // chrome.storage.local.remove(keys, callback):
    //   Deletes one or more keys from local storage.
    chrome.storage.local.remove(key, () => {
      console.log(`Cleared cache for ${key}`);
    });

    return false;
  }

  return false;
});

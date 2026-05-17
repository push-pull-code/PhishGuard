
const API_BASE = "http://localhost:8000";
const CACHE_TTL_MS = 60 * 60 * 1000;
const DB_NAME = "PhishGuardCache";
const DB_VERSION = 1;
const STORE_NAME = "scanResults";
//indexDB 
function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: "key" });
        store.createIndex("timestamp", "timestamp", { unique: false });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function idbGet(key) {
  try {
    const db = await openDB();
    return new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const store = tx.objectStore(STORE_NAME);
      const req = store.get(key);
      req.onsuccess = () => {
        const entry = req.result;
        if (entry && (Date.now() - entry.timestamp < CACHE_TTL_MS)) {
          resolve(entry.result);
        } else {
          resolve(null);
        }
      };
      req.onerror = () => resolve(null);
    });
  } catch {
    return null;
  }
}

async function idbPut(key, result) {
  try {
    const db = await openDB();
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    store.put({ key, result, timestamp: Date.now() });
  } catch (e) {
    console.warn("IndexedDB put failed:", e);
  }
}

async function idbDelete(key) {
  try {
    const db = await openDB();
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).delete(key);
  } catch (e) {
    console.warn("IndexedDB delete failed:", e);
  }
}

async function idbClearExpired() {
  try {
    const db = await openDB();
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const cutoff = Date.now() - CACHE_TTL_MS;
    const idx = store.index("timestamp");
    const range = IDBKeyRange.upperBound(cutoff);
    const req = idx.openCursor(range);
    req.onsuccess = (e) => {
      const cursor = e.target.result;
      if (cursor) {
        cursor.delete();
        cursor.continue();
      }
    };
  } catch (e) {
    console.warn("IndexedDB cleanup failed:", e);
  }
}

function getDomainKey(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

function isScannableUrl(url) {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return ["http:", "https:"].includes(parsed.protocol);
  } catch {
    return false;
  }
}
//icon colour control
function setIconColor(tabId, color) {
  // color: "green", "orange", "red", "grey"
  const canvas = new OffscreenCanvas(32, 32);
  const ctx = canvas.getContext("2d");

  // Shield shape
  const colors = {
    green: { fill: "#22c55e", stroke: "#16a34a", glow: "rgba(34,197,94,0.3)" },
    orange: { fill: "#f59e0b", stroke: "#d97706", glow: "rgba(245,158,11,0.3)" },
    red: { fill: "#ef4444", stroke: "#dc2626", glow: "rgba(239,68,68,0.3)" },
    grey: { fill: "#94a3b8", stroke: "#64748b", glow: "rgba(148,163,184,0.2)" },
  };
  const c = colors[color] || colors.grey;

  // Draw shield icon
  ctx.clearRect(0, 0, 32, 32);

  // Glow
  ctx.shadowColor = c.glow;
  ctx.shadowBlur = 4;

  // Shield body
  ctx.beginPath();
  ctx.moveTo(16, 2);
  ctx.quadraticCurveTo(4, 4, 4, 12);
  ctx.quadraticCurveTo(4, 24, 16, 30);
  ctx.quadraticCurveTo(28, 24, 28, 12);
  ctx.quadraticCurveTo(28, 4, 16, 2);
  ctx.closePath();
  ctx.fillStyle = c.fill;
  ctx.fill();
  ctx.shadowBlur = 0;
  ctx.strokeStyle = c.stroke;
  ctx.lineWidth = 1.5;
  ctx.stroke();

  // Inner symbol
  ctx.fillStyle = "#ffffff";
  ctx.font = "bold 14px sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  if (color === "green") {
    ctx.fillText("✓", 16, 16);
  } else if (color === "red") {
    ctx.fillText("✕", 16, 16);
  } else if (color === "orange") {
    ctx.fillText("!", 16, 17);
  } else {
    ctx.fillText("?", 16, 16);
  }

  const imageData = ctx.getImageData(0, 0, 32, 32);
  chrome.action.setIcon({ tabId, imageData });
}

function setIconForResult(tabId, result) {
  if (!result || !result.final) {
    setIconColor(tabId, "grey");
    return;
  }
  const level = result.final.threat_level;
  if (level === "safe") {
    setIconColor(tabId, "green");
  } else if (level === "suspicious") {
    setIconColor(tabId, "orange");
  } else {
    setIconColor(tabId, "red");
  }
}
//scan logic
async function scanUrl(url, tabId) {
  const key = getDomainKey(url);

  // Set scanning state
  setIconColor(tabId, "grey");
  chrome.action.setTitle({ tabId, title: "PhishGuard — Scanning…" });

  // 1. Check IndexedDB cache first
  const cached = await idbGet(key);
  if (cached) {
    setIconForResult(tabId, cached);
    const label = cached.final?.threat_level?.toUpperCase() || "UNKNOWN";
    const score = cached.final?.score ?? "?";
    chrome.action.setTitle({ tabId, title: `PhishGuard — ${label} (${score}/100) [cached]` });
    return cached;
  }

  // 2. Call backend API
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000); // 10s timeout

    const res = await fetch(`${API_BASE}/scan/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const data = await res.json();

    // Store in IndexedDB
    await idbPut(key, data);

    // Update icon
    setIconForResult(tabId, data);
    const label = data.final?.threat_level?.toUpperCase() || "UNKNOWN";
    const score = data.final?.score ?? "?";
    chrome.action.setTitle({ tabId, title: `PhishGuard — ${label} (${score}/100)` });

    return data;
  } catch (err) {
    console.warn("PhishGuard scan failed:", err.message);
    setIconColor(tabId, "grey");
    chrome.action.setTitle({ tabId, title: "PhishGuard — Backend unavailable" });
    return null;
  }
}

// ══════════════════════════════════════════════════════════════
// Auto-scan on page navigation
// ══════════════════════════════════════════════════════════════

// Fires when a navigation is committed (page starts loading)
chrome.webNavigation.onCommitted.addListener((details) => {
  // Only main frame, ignore iframes
  if (details.frameId !== 0) return;
  if (!isScannableUrl(details.url)) return;

  scanUrl(details.url, details.tabId);
});

// Also scan when tab becomes active (e.g., switching tabs)
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url && isScannableUrl(tab.url)) {
      const key = getDomainKey(tab.url);
      const cached = await idbGet(key);
      if (cached) {
        setIconForResult(activeInfo.tabId, cached);
        const label = cached.final?.threat_level?.toUpperCase() || "UNKNOWN";
        const score = cached.final?.score ?? "?";
        chrome.action.setTitle({
          tabId: activeInfo.tabId,
          title: `PhishGuard — ${label} (${score}/100) [cached]`,
        });
      } else {
        scanUrl(tab.url, activeInfo.tabId);
      }
    }
  } catch {
    // Tab may have been closed
  }
});

// ══════════════════════════════════════════════════════════════
// Message API for popup.js
// ══════════════════════════════════════════════════════════════

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const { action, url } = message;

  if (action === "getCachedResult") {
    const key = getDomainKey(url);
    idbGet(key).then((result) => {
      sendResponse({ result: result || null });
    });
    return true; // async response
  }

  if (action === "scanUrl") {
    // Popup requests a fresh scan
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      if (tab) {
        scanUrl(url, tab.id).then((result) => {
          sendResponse({ result });
        });
      } else {
        sendResponse({ result: null });
      }
    });
    return true;
  }

  if (action === "clearCache") {
    const key = getDomainKey(url);
    idbDelete(key).then(() => {
      sendResponse({ cleared: true });
    });
    return true;
  }

  return false;
});

// ══════════════════════════════════════════════════════════════
// Lifecycle
// ══════════════════════════════════════════════════════════════

chrome.runtime.onInstalled.addListener((details) => {
  console.log(`PhishGuard installed (reason: ${details.reason})`);
  // Clean up expired cache entries
  idbClearExpired();
});

// Periodic cleanup every 30 minutes
chrome.alarms.create("cacheCleanup", { periodInMinutes: 30 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "cacheCleanup") {
    idbClearExpired();
  }
});

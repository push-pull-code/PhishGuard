// FILE: popup.js
// PURPOSE: Popup logic — reads the active tab URL, sends it to the PhishGuard API, and renders the result
// CONNECTS TO: extension/popup.html, extension/background.js, backend/routes/scan.py
//
// FLOW: chrome.tabs.query (active tab URL)
//       → POST http://localhost:8000/scan { url }
//       → receive JSON verdict
//       → render threat badge + forensics in popup.html
//       → cache result via background.js message
//
// HOW TO LOAD IN CHROME:
// 1. Open chrome://extensions
// 2. Enable Developer Mode
// 3. Click Load Unpacked → select /extension folder

// ---------------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------------

const API_BASE = "http://localhost:8000";

// ---------------------------------------------------------------------------
// DOM REFERENCES
// ---------------------------------------------------------------------------

const $currentUrl    = document.getElementById("current-url");
const $loadingState  = document.getElementById("loading-state");
const $resultCard    = document.getElementById("result-card");
const $errorState    = document.getElementById("error-state");
const $errorTitle    = document.getElementById("error-title");
const $errorDetail   = document.getElementById("error-detail");
const $rescanBtn     = document.getElementById("rescan-btn");

// Result card elements
const $threatBadge   = document.getElementById("threat-badge");
const $threatIcon    = document.getElementById("threat-icon");
const $threatLabel   = document.getElementById("threat-label");
const $threatScore   = document.getElementById("threat-score");
const $confidenceText = document.getElementById("confidence-text");
const $reasonsList   = document.getElementById("reasons-list");
const $forensicsGrid = document.getElementById("forensics-grid");
const $responseTime  = document.getElementById("response-time");


// ---------------------------------------------------------------------------
// UI STATE HELPERS
// ---------------------------------------------------------------------------

function showLoading() {
  $loadingState.classList.remove("hidden");
  $resultCard.classList.add("hidden");
  $errorState.classList.add("hidden");
  $rescanBtn.classList.add("hidden");
}

function showResult() {
  $loadingState.classList.add("hidden");
  $resultCard.classList.remove("hidden");
  $errorState.classList.add("hidden");
  $rescanBtn.classList.remove("hidden");
}

function showError(title, detail) {
  $loadingState.classList.add("hidden");
  $resultCard.classList.add("hidden");
  $errorState.classList.remove("hidden");
  $rescanBtn.classList.remove("hidden");
  $errorTitle.textContent = title;
  if (detail) $errorDetail.innerHTML = detail;
}


// ---------------------------------------------------------------------------
// THREAT LEVEL → VISUAL MAPPING
// ---------------------------------------------------------------------------
// Green / Yellow / Red color scheme based on threat_level from the API.

const THREAT_STYLES = {
  safe: {
    icon: "✅",
    borderClass: "border-emerald-500/40",
    bgClass: "bg-emerald-500/10",
    labelColor: "text-emerald-400",
    scoreColor: "text-emerald-300",
  },
  suspicious: {
    icon: "⚠️",
    borderClass: "border-amber-500/40",
    bgClass: "bg-amber-500/10",
    labelColor: "text-amber-400",
    scoreColor: "text-amber-300",
  },
  malicious: {
    icon: "🚨",
    borderClass: "border-red-500/40",
    bgClass: "bg-red-500/10",
    labelColor: "text-red-400",
    scoreColor: "text-red-300",
  },
};


// ---------------------------------------------------------------------------
// RENDER SCAN RESULT
// ---------------------------------------------------------------------------

function renderResult(data) {
  const level = data.threat_score?.threat_level || "safe";
  const style = THREAT_STYLES[level] || THREAT_STYLES.safe;

  // --- Threat badge styling ---
  // Remove old color classes then apply new ones
  $threatBadge.className = `rounded-xl p-4 mb-3 border ${style.borderClass} ${style.bgClass}`;
  $threatIcon.textContent = style.icon;
  $threatLabel.textContent = level.toUpperCase();
  $threatLabel.className = `text-sm font-bold uppercase tracking-wider ${style.labelColor}`;
  $threatScore.textContent = `${data.threat_score?.score ?? 0}/100`;
  $threatScore.className = `text-2xl font-bold ${style.scoreColor}`;
  $confidenceText.textContent = `ML confidence: ${(data.confidence * 100).toFixed(1)}%`;

  // --- Reasons list ---
  $reasonsList.innerHTML = "";
  const reasons = data.threat_score?.reasons || ["No threats detected"];
  for (const reason of reasons) {
    const li = document.createElement("li");
    li.className = "flex items-start gap-1.5";
    li.innerHTML = `<span class="text-slate-500 mt-0.5">•</span><span>${reason}</span>`;
    $reasonsList.appendChild(li);
  }

  // --- Forensics grid ---
  $forensicsGrid.innerHTML = "";
  const forensics = data.forensics || {};

  const gridItems = [];

  // WHOIS
  const whois = forensics.whois || {};
  if (whois.available) {
    gridItems.push({
      label: "Domain Age",
      value: whois.domain_age_days != null ? `${whois.domain_age_days} days` : "Unknown",
      warn: whois.is_newly_registered,
    });
    gridItems.push({
      label: "Registrar",
      value: whois.registrar || "Unknown",
    });
  }

  // DNS
  const dnsData = forensics.dns || {};
  if (dnsData.available !== false) {
    gridItems.push({
      label: "A Record",
      value: dnsData.has_a_record ? "Yes ✓" : "No ✗",
      warn: !dnsData.has_a_record,
    });
    gridItems.push({
      label: "MX Record",
      value: dnsData.has_mx_record ? "Yes ✓" : "No ✗",
      warn: !dnsData.has_mx_record,
    });
  }

  // Typosquatting
  const typo = forensics.typosquatting || {};
  if (typo.is_typosquat) {
    gridItems.push({
      label: "Typosquat",
      value: `→ ${typo.original_brand} (dist ${typo.edit_distance})`,
      warn: true,
    });
  }

  for (const item of gridItems) {
    const div = document.createElement("div");
    div.className = `bg-slate-800/60 rounded-lg px-2.5 py-2 ${item.warn ? "border border-amber-500/30" : ""}`;
    div.innerHTML = `
      <p class="text-[10px] uppercase tracking-wider text-slate-500">${item.label}</p>
      <p class="text-xs font-medium ${item.warn ? "text-amber-400" : "text-slate-300"}">${item.value}</p>
    `;
    $forensicsGrid.appendChild(div);
  }

  // --- Response time ---
  $responseTime.textContent = `Scanned in ${data.response_time_ms?.toFixed(0) || "?"}ms`;

  showResult();
}


// ---------------------------------------------------------------------------
// SCAN LOGIC
// ---------------------------------------------------------------------------

async function scanUrl(url) {
  showLoading();

  // -------------------------------------------------------------------
  // First, check if we have a cached result for this domain.
  //
  // chrome.runtime.sendMessage():
  //   Sends a one-shot message to the background service worker.
  //   The service worker can respond asynchronously via sendResponse().
  //   We use this to ask the background script if it has a cached result
  //   for this domain, avoiding a redundant API call.
  // -------------------------------------------------------------------
  try {
    const cached = await new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { action: "getCachedResult", url },
        (response) => resolve(response)
      );
    });

    if (cached && cached.result) {
      renderResult(cached.result);
      $responseTime.textContent += " (cached)";
      return;
    }
  } catch {
    // Background script not available — proceed without cache
  }

  // -------------------------------------------------------------------
  // No cache hit — call the PhishGuard API
  // -------------------------------------------------------------------
  try {
    const res = await fetch(`${API_BASE}/scan/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }

    const data = await res.json();
    renderResult(data);

    // -----------------------------------------------------------------
    // Cache the result in the background service worker.
    //
    // chrome.runtime.sendMessage():
    //   We send the scan result to background.js which stores it in
    //   chrome.storage.local keyed by domain.  Next time the user opens
    //   the popup on the same domain, we'll get a cache hit and skip
    //   the API call entirely.
    // -----------------------------------------------------------------
    chrome.runtime.sendMessage({
      action: "cacheResult",
      url,
      result: data,
    });

  } catch (err) {
    console.error("Scan failed:", err);

    if (err.message.includes("Failed to fetch") || err.message.includes("NetworkError")) {
      showError(
        "Backend not running",
        `Start the API server with:<br/>
         <code class="bg-slate-800 px-2 py-0.5 rounded text-[11px] mt-1 inline-block">
           python backend/main.py
         </code>`
      );
    } else {
      showError("Scan failed", `<span class="text-xs text-slate-500">${err.message}</span>`);
    }
  }
}


// ---------------------------------------------------------------------------
// ENTRY POINT — runs when the popup DOM is fully loaded
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  // -------------------------------------------------------------------
  // chrome.tabs.query({ active: true, currentWindow: true })
  //
  // WHAT THIS DOES:
  //   Queries the Chrome tab manager for tabs matching the filter:
  //     • active: true   → only the tab the user is currently viewing
  //     • currentWindow: true → only in the window that owns this popup
  //
  //   Returns an array of Tab objects.  We destructure the first (and
  //   only) result.  Each Tab object has properties like:
  //     • tab.url     — the full URL of the page (e.g. "https://example.com/path")
  //     • tab.title   — the page's <title>
  //     • tab.id      — unique numeric ID for this tab
  //
  //   We need the "activeTab" permission in manifest.json for this to
  //   return the URL.  Without it, tab.url would be undefined.
  // -------------------------------------------------------------------
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    const url = tab?.url;

    if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
      // Can't scan internal Chrome pages
      $currentUrl.textContent = url || "N/A";
      showError(
        "Cannot scan this page",
        "<span class='text-xs text-slate-500'>Chrome internal pages cannot be scanned.</span>"
      );
      return;
    }

    // Display the URL being scanned (truncated in the UI via CSS)
    $currentUrl.textContent = url;
    $currentUrl.title = url; // full URL on hover

    // Start scanning
    scanUrl(url);
  });

  // -------------------------------------------------------------------
  // RESCAN BUTTON
  // Clears the cache for this domain and re-runs the scan.
  // -------------------------------------------------------------------
  $rescanBtn.addEventListener("click", () => {
    const url = $currentUrl.textContent;
    if (url && url !== "Loading…") {
      // Tell background to clear cache for this URL
      chrome.runtime.sendMessage({ action: "clearCache", url });
      scanUrl(url);
    }
  });
});

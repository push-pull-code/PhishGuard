const API_BASE = "http://localhost:8000";

const $currentUrl = document.getElementById("current-url");
const $loadingState = document.getElementById("loading-state");
const $resultCard = document.getElementById("result-card");
const $errorState = document.getElementById("error-state");
const $errorTitle = document.getElementById("error-title");
const $errorDetail = document.getElementById("error-detail");
const $rescanBtn = document.getElementById("rescan-btn");

const $threatBadge = document.getElementById("threat-badge");
const $threatIcon = document.getElementById("threat-icon");
const $threatLabel = document.getElementById("threat-label");
const $threatScore = document.getElementById("threat-score");
const $confidenceText = document.getElementById("confidence-text");
const $reasonsList = document.getElementById("reasons-list");
const $forensicsGrid = document.getElementById("forensics-grid");
const $responseTime = document.getElementById("response-time");

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

function renderResult(data) {
  const threatData = data.final || data.threat_score || {};
  const level = threatData.threat_level || "safe";
  const style = THREAT_STYLES[level] || THREAT_STYLES.safe;

  $threatBadge.className = `rounded-xl p-4 mb-3 border ${style.borderClass} ${style.bgClass}`;
  $threatIcon.textContent = style.icon;
  $threatLabel.textContent = level.toUpperCase();
  $threatLabel.className = `text-sm font-bold uppercase tracking-wider ${style.labelColor}`;
  $threatScore.textContent = `${threatData.score ?? 0}/100`;
  $threatScore.className = `text-2xl font-bold ${style.scoreColor}`;

  const confPct = (data.dataset_match?.found && data.dataset_match?.confidence)
    ? data.dataset_match.confidence
    : (data.ml?.confidence ?? data.confidence ?? 0);
  const confDisplay = (confPct * 100).toFixed(1);

  const srcLabel = data.source === 'cache' ? '⚡ Cached'
    : data.source === 'dataset' ? '📂 Dataset match'
      : '🤖 ML inference';
  $confidenceText.textContent = `${srcLabel}  •  Confidence: ${confDisplay}%`;

  $reasonsList.innerHTML = "";
  const reasons = threatData.reasons || ["No threats detected"];
  for (const reason of reasons) {
    const li = document.createElement("li");
    li.className = "flex items-start gap-1.5";
    li.innerHTML = `<span class="text-slate-500 mt-0.5">•</span><span>${reason}</span>`;
    $reasonsList.appendChild(li);
  }

  $forensicsGrid.innerHTML = "";
  const forensics = data.forensics || {};
  const gridItems = [];

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

  const dnsData = forensics.dns || {};
  if (dnsData.available) {
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

  const dsMatch = data.dataset_match;
  if (dsMatch && dsMatch.found) {
    const dsDiv = document.createElement('div');
    dsDiv.className = `bg-slate-800/60 rounded-lg px-2.5 py-2 border border-indigo-500/30`;
    dsDiv.innerHTML = `
      <p class="text-[10px] uppercase tracking-wider text-slate-500">Dataset</p>
      <p class="text-xs font-medium text-indigo-300">${dsMatch.source} → ${dsMatch.label}</p>
    `;
    $forensicsGrid.appendChild(dsDiv);
  }

  const timeMs = data.response_time_ms;
  const srcSuffix = data.source === 'dataset' ? ' (dataset)'
    : data.source === 'ml' ? ' (ML inference)'
      : '';

  if (timeMs != null) {
    $responseTime.textContent = `Scanned in ${timeMs.toFixed(0)}ms${srcSuffix}`;
  } else {
    $responseTime.textContent = '';
  }

  showResult();
}

async function scanUrl(url, forceRescan = false) {
  showLoading();

  if (forceRescan) {
    await new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: "clearCache", url }, () => resolve());
    });
  }

  if (!forceRescan) {
    try {
      const cached = await new Promise((resolve) => {
        chrome.runtime.sendMessage(
          { action: "getCachedResult", url },
          (response) => resolve(response)
        );
      });

      if (cached && cached.result) {
        renderResult(cached.result);
        return;
      }
    } catch {
    }
  }

  try {
    const result = await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(
        { action: "scanUrl", url },
        (response) => {
          if (response && response.result) {
            resolve(response.result);
          } else {
            reject(new Error("Scan failed"));
          }
        }
      );
    });

    renderResult(result);
  } catch (err) {
    console.error("Scan failed:", err);
    showError(
      "Scan failed",
      `<span class="text-xs text-slate-500">Backend may not be running. Start with:<br/>
       <code class="bg-slate-800 px-2 py-0.5 rounded text-[11px] mt-1 inline-block">
         python backend/main.py
       </code></span>`
    );
  }
}

document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    const url = tab?.url;

    if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
      $currentUrl.textContent = url || "N/A";
      showError(
        "Cannot scan this page",
        "<span class='text-xs text-slate-500'>Chrome internal pages cannot be scanned.</span>"
      );
      return;
    }

    $currentUrl.textContent = url;
    $currentUrl.title = url;

    scanUrl(url);
  });

  $rescanBtn.addEventListener("click", () => {
    const url = $currentUrl.textContent;
    if (url && url !== "Loading…") {
      chrome.runtime.sendMessage({ action: "clearCache", url }, () => {
        scanUrl(url, true);
      });
    }
  });
});

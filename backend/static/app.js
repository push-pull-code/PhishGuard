const API_URL = '/scan/';
const scanHistory = [];

const $urlInput   = document.getElementById('url-input');
const $scanBtn    = document.getElementById('scan-btn');
const $scanLabel  = document.getElementById('scan-label');
const $spinner    = document.getElementById('scan-spinner');
const $errorMsg   = document.getElementById('error-msg');
const $resultWrap = document.getElementById('result-wrap');
const $resultCard = document.getElementById('result-card');
const $chartSection  = document.getElementById('chart-section');
const $historySection = document.getElementById('history-section');
const $exportSection  = document.getElementById('export-section');
const $emptyState = document.getElementById('empty-state');

$urlInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') handleScan(); });
$scanBtn.addEventListener('click', handleScan);

async function handleScan() {
  const url = $urlInput.value.trim();
  if (!url) return;

  setLoading(true);
  $errorMsg.classList.add('hidden');
  $resultCard.classList.add('hidden');

  try {
    const res = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) throw new Error('Server returned ' + res.status);
    const data = await res.json();
    scanHistory.push(data);
    renderResult(data);
    renderChart();
    renderHistory();
    renderExport();
    $emptyState.classList.add('hidden');
  } catch (err) {
    const msg = (err.message.includes('Failed to fetch') || err.message.includes('NetworkError'))
      ? 'Backend not running — start with: python backend/main.py'
      : 'Scan failed: ' + err.message;
    $errorMsg.textContent = msg;
    $errorMsg.classList.remove('hidden');
  } finally {
    setLoading(false);
  }
}

function setLoading(on) {
  $scanBtn.disabled = on;
  $scanLabel.textContent = on ? 'Scanning…' : '🔍 Scan URL';
  $spinner.classList.toggle('hidden', !on);
  if (on) $resultWrap.style.opacity = '0.4';
  else $resultWrap.style.opacity = '1';
}

function renderResult(data) {
  const { url, cleaned_url, obfuscation_found = [], ml = {}, threat_intel = {}, final: ts = {}, forensics = {}, response_time_ms } = data;
  const level = ts.threat_level || 'safe';
  const score = ts.score ?? 0;
  const confidence = ml.confidence ?? 0;
  const reasons = ts.reasons || [];
  const vt = threat_intel.virustotal || {};
  const uh = threat_intel.urlhaus || {};
  const whois = forensics.whois || {};
  const dns = forensics.dns || {};
  const typo = forensics.typosquatting || {};

  const icons = { safe: '✅', suspicious: '⚠️', malicious: '🚨' };

  let html = `
    <div class="result-header">
      <div class="left">
        <span class="icon">${icons[level] || '✅'}</span>
        <div>
          <div class="level level-${level}">${level}</div>
          <div class="score-label">Threat Score: ${score}/100</div>
        </div>
      </div>
      <div class="time">${response_time_ms?.toFixed(0) || '?'} ms</div>
    </div>

    <div class="confidence-section">
      <div class="confidence-label">
        <span>ML Confidence</span>
        <span class="level-${level}">${(confidence * 100).toFixed(1)}%</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill bar-${level}" style="width:${Math.min(confidence * 100, 100)}%"></div>
      </div>
    </div>`;

  if (reasons.length > 0) {
    html += `<div class="findings"><div class="section-title">Findings</div><ul>`;
    reasons.forEach(r => { html += `<li>${escapeHtml(r)}</li>`; });
    html += `</ul></div>`;
  }

  let tiles = '';
  if (vt.available) tiles += infoTile('VirusTotal', `${vt.malicious_count||0}/${vt.total_engines||0} flagged`, vt.malicious_count > 0);
  if (uh.available) tiles += infoTile('URLhaus', uh.is_known_malicious ? 'Known malicious' : 'Not listed', uh.is_known_malicious);
  if (whois.available) tiles += infoTile('Domain Age', whois.domain_age_days != null ? `${whois.domain_age_days} days` : 'Unknown', whois.is_newly_registered);
  if (dns.available !== false) tiles += infoTile('MX Record', dns.has_mx_record ? 'Present ✓' : 'Missing ✗', !dns.has_mx_record);
  if (typo.is_typosquat) tiles += infoTile('Typosquat', `→ ${typo.original_brand} (dist ${typo.edit_distance})`, true);
  if (tiles) html += `<div class="info-grid">${tiles}</div>`;

  if (obfuscation_found.length > 0) {
    html += `<div><div class="section-title">Obfuscation Detected</div><div class="obfuscation-tags">`;
    obfuscation_found.forEach(t => { html += `<span class="obfuscation-tag">${escapeHtml(t)}</span>`; });
    html += `</div></div>`;
  }

  html += `<div class="scanned-url">${escapeHtml(url)}`;
  if (cleaned_url !== url) html += `<br>Cleaned: ${escapeHtml(cleaned_url)}`;
  html += `</div>`;

  $resultCard.className = `result-card glass-strong border-${level} bg-${level}`;
  $resultCard.innerHTML = html;
  $resultCard.classList.remove('hidden');
}

function infoTile(label, value, warn) {
  return `<div class="info-tile ${warn ? 'warn' : ''}">
    <div class="tile-label">${label}</div>
    <div class="tile-value">${escapeHtml(value)}</div>
  </div>`;
}

function renderChart() {
  $chartSection.classList.remove('hidden');
  const counts = { Safe: 0, Suspicious: 0, Malicious: 0 };
  scanHistory.forEach(s => {
    const l = s.final?.threat_level;
    if (l === 'safe') counts.Safe++;
    else if (l === 'suspicious') counts.Suspicious++;
    else if (l === 'malicious') counts.Malicious++;
  });

  const canvas = document.getElementById('risk-chart');
  const ctx = canvas.getContext('2d');

  if (window._chartInstance) window._chartInstance.destroy();

  window._chartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Safe', 'Suspicious', 'Malicious'],
      datasets: [{
        data: [counts.Safe, counts.Suspicious, counts.Malicious],
        backgroundColor: ['#4ade80', '#fbbf24', '#f87171'],
        borderRadius: 6,
        maxBarThickness: 60,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(10,10,15,0.9)',
          borderColor: 'rgba(255,255,255,0.15)',
          borderWidth: 1,
          titleFont: { family: 'Inter' },
          bodyFont: { family: 'Inter' },
        }
      },
      scales: {
        x: {
          ticks: { color: 'rgba(255,255,255,0.55)', font: { family: 'Inter', size: 12 } },
          grid: { display: false },
          border: { display: false },
        },
        y: {
          ticks: { color: 'rgba(255,255,255,0.35)', font: { family: 'Inter', size: 11 }, stepSize: 1 },
          grid: { color: 'rgba(255,255,255,0.05)' },
          border: { display: false },
        }
      }
    }
  });
}

function renderHistory() {
  $historySection.classList.remove('hidden');
  const $count = document.getElementById('history-count');
  const $tbody = document.getElementById('history-body');
  $count.textContent = scanHistory.length;
  $tbody.innerHTML = '';

  [...scanHistory].reverse().forEach(scan => {
    const level = scan.final?.threat_level || 'safe';
    const score = scan.final?.score ?? 0;
    const ms = scan.response_time_ms?.toFixed(0) ?? '?';
    const displayUrl = scan.url?.length > 50 ? scan.url.substring(0, 47) + '…' : (scan.url || '—');

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td title="${escapeHtml(scan.url || '')}">${escapeHtml(displayUrl)}</td>
      <td><span class="badge badge-${level}">${level}</span></td>
      <td>${score}/100</td>
      <td>${ms} ms</td>`;
    $tbody.appendChild(tr);
  });
}

function renderExport() {
  $exportSection.classList.remove('hidden');
  const $btn = document.getElementById('export-btn');
  $btn.textContent = `📄 Export IoC Report (${scanHistory.length} scans)`;
  $btn.onclick = exportIoC;
}

function exportIoC() {
  const report = {
    report_type: 'PhishGuard IoC Report',
    generated_at: new Date().toISOString(),
    total_scans: scanHistory.length,
    summary: {
      safe: scanHistory.filter(s => s.final?.threat_level === 'safe').length,
      suspicious: scanHistory.filter(s => s.final?.threat_level === 'suspicious').length,
      malicious: scanHistory.filter(s => s.final?.threat_level === 'malicious').length,
    },
    indicators: scanHistory.map(scan => ({
      url: scan.url,
      cleaned_url: scan.cleaned_url,
      threat_level: scan.final?.threat_level,
      threat_score: scan.final?.score,
      ml_confidence: scan.ml?.confidence,
      reasons: scan.final?.reasons,
      obfuscation: scan.obfuscation_found,
      virustotal: scan.threat_intel?.virustotal,
      urlhaus: scan.threat_intel?.urlhaus,
      forensics: scan.forensics,
      response_time_ms: scan.response_time_ms,
    })),
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `phishguard-ioc-report-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

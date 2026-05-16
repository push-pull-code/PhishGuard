// FILE: ResultCard.jsx
// PURPOSE: Displays the full scan verdict — threat badge, ML confidence, forensics, obfuscation, VT, typosquat
// CONNECTS TO: App.jsx
//
// FLOW: App passes scan result as props → ResultCard renders all fields

// =====================================================================
// WHY EACH FIELD IS SHOWN TO AN ANALYST
// =====================================================================
// Security analysts need more than a binary "safe/phishing" answer.
// Each field gives them a different LAYER of evidence:
//
//   • Threat badge + score       → at-a-glance severity (triage priority)
//   • ML confidence bar          → how certain the ML model is (low confidence
//                                  means the analyst should investigate manually)
//   • Obfuscation techniques     → shows if the attacker tried to hide the URL;
//                                  even a "safe" URL with heavy obfuscation is suspicious
//   • VirusTotal engine count    → independent validation from 70+ engines;
//                                  high count = high-confidence known threat
//   • WHOIS domain age           → newly-registered domains are the #1 phishing indicator;
//                                  legitimate brands own their domains for years
//   • Typosquatting warning      → tells the analyst which brand is being impersonated,
//                                  which is critical for incident response and takedown

export default function ResultCard({ result }) {
  if (!result) return null;

  const {
    url,
    cleaned_url,
    obfuscation_found = [],
    ml = {},
    threat_intel = {},
    final: threat_score = {},
    forensics = {},
    response_time_ms,
  } = result;

  const confidence = ml.confidence ?? 0;
  const level = threat_score.threat_level || "safe";
  const score = threat_score.score ?? 0;
  const reasons = threat_score.reasons || [];

  // --- Color scheme per threat level ---
  const palette = {
    safe:       { bg: "bg-emerald-500/10", border: "border-emerald-500/30", text: "text-emerald-400", bar: "bg-emerald-500", icon: "✅" },
    suspicious: { bg: "bg-amber-500/10",   border: "border-amber-500/30",   text: "text-amber-400",   bar: "bg-amber-500",   icon: "⚠️" },
    malicious:  { bg: "bg-red-500/10",     border: "border-red-500/30",     text: "text-red-400",     bar: "bg-red-500",     icon: "🚨" },
  };
  const p = palette[level] || palette.safe;

  const vt = threat_intel.virustotal || {};
  const uh = threat_intel.urlhaus || {};
  const whois = forensics.whois || {};
  const dns = forensics.dns || {};
  const typo = forensics.typosquatting || {};

  return (
    <div className={`w-full max-w-2xl mx-auto rounded-2xl border ${p.border} ${p.bg} p-6 mb-6 backdrop-blur-sm`}>

      {/* ============================================ */}
      {/* THREAT BADGE + SCORE                         */}
      {/* ============================================ */}
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-3">
          <span className="text-4xl">{p.icon}</span>
          <div>
            <p className={`text-lg font-bold uppercase tracking-wide ${p.text}`}>{level}</p>
            <p className="text-xs text-[var(--color-text-muted)]">Threat Score: {score}/100</p>
          </div>
        </div>
        <p className="text-xs text-[var(--color-text-muted)]">{response_time_ms?.toFixed(0)} ms</p>
      </div>

      {/* ============================================ */}
      {/* ML CONFIDENCE BAR                            */}
      {/* ============================================ */}
      <div className="mb-5">
        <div className="flex justify-between text-xs mb-1">
          <span className="text-[var(--color-text-muted)]">ML Confidence</span>
          <span className={`font-mono font-semibold ${p.text}`}>{(confidence * 100).toFixed(1)}%</span>
        </div>
        <div className="w-full h-2 rounded-full bg-[var(--color-surface-3)]">
          <div
            className={`h-full rounded-full ${p.bar} transition-all duration-500`}
            style={{ width: `${Math.min(confidence * 100, 100)}%` }}
          />
        </div>
      </div>

      {/* ============================================ */}
      {/* REASONS                                      */}
      {/* ============================================ */}
      {reasons.length > 0 && (
        <div className="mb-5">
          <p className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)] mb-2">Findings</p>
          <ul className="space-y-1">
            {reasons.map((r, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-slate-300">
                <span className="text-[var(--color-text-muted)] mt-0.5">•</span>
                <span>{r}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* ============================================ */}
      {/* INFO GRID (VT, URLhaus, WHOIS, DNS, Typo)   */}
      {/* ============================================ */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mb-4">

        {/* VirusTotal engine count */}
        {vt.available && (
          <InfoTile
            label="VirusTotal"
            value={`${vt.malicious_count || 0}/${vt.total_engines || 0} flagged`}
            warn={vt.malicious_count > 0}
          />
        )}

        {/* URLhaus */}
        {uh.available && (
          <InfoTile
            label="URLhaus"
            value={uh.is_known_malicious ? `Known malicious` : "Not listed"}
            warn={uh.is_known_malicious}
          />
        )}

        {/* WHOIS domain age */}
        {whois.available && (
          <InfoTile
            label="Domain Age"
            value={whois.domain_age_days != null ? `${whois.domain_age_days} days` : "Unknown"}
            warn={whois.is_newly_registered}
          />
        )}

        {/* DNS records */}
        {dns.available !== false && (
          <InfoTile
            label="MX Record"
            value={dns.has_mx_record ? "Present ✓" : "Missing ✗"}
            warn={!dns.has_mx_record}
          />
        )}

        {/* Typosquatting */}
        {typo.is_typosquat && (
          <InfoTile
            label="Typosquat"
            value={`→ ${typo.original_brand} (dist ${typo.edit_distance})`}
            warn={true}
          />
        )}
      </div>

      {/* ============================================ */}
      {/* OBFUSCATION TECHNIQUES                       */}
      {/* ============================================ */}
      {obfuscation_found.length > 0 && (
        <div className="mb-3">
          <p className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)] mb-1.5">Obfuscation Detected</p>
          <div className="flex flex-wrap gap-1.5">
            {obfuscation_found.map((tech, i) => (
              <span key={i} className="px-2 py-0.5 rounded-md bg-amber-500/15 text-amber-400 text-[11px] font-medium">
                {tech}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ============================================ */}
      {/* SCANNED URL                                  */}
      {/* ============================================ */}
      <div className="pt-3 border-t border-white/5">
        <p className="text-[10px] text-[var(--color-text-muted)] break-all">{url}</p>
        {cleaned_url !== url && (
          <p className="text-[10px] text-[var(--color-text-muted)] break-all mt-0.5">
            Cleaned: {cleaned_url}
          </p>
        )}
      </div>
    </div>
  );
}

// =====================================================================
// HELPER: Small info tile used in the grid
// =====================================================================

function InfoTile({ label, value, warn = false }) {
  return (
    <div className={`bg-[var(--color-surface-2)]/60 rounded-lg px-3 py-2
                     ${warn ? "border border-amber-500/25" : "border border-transparent"}`}>
      <p className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)]">{label}</p>
      <p className={`text-xs font-medium mt-0.5 ${warn ? "text-amber-400" : "text-slate-300"}`}>{value}</p>
    </div>
  );
}

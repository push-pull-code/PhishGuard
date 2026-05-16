// FILE: ScanHistory.jsx
// PURPOSE: Displays the last 10 scans in a table with URL, threat level, score, and time
// CONNECTS TO: App.jsx
//
// FLOW: App passes scanHistory[] as prop → ScanHistory renders a table

// =====================================================================
// WHY useState ARRAY AND NOT localStorage?
// =====================================================================
// We store scan history in a React useState array instead of localStorage
// because:
//
//   1. REACTIVITY — When a new scan completes, we push it into the state
//      array and React automatically re-renders the table.  With
//      localStorage we'd have to manually read, parse JSON, write back,
//      AND trigger a re-render — much more glue code for no benefit.
//
//   2. CONSISTENCY — The same history array feeds both ScanHistory AND
//      RiskChart.  If we used localStorage, two components would be
//      independently reading/parsing the same key, risking stale reads
//      or race conditions.
//
//   3. SCOPE — The dashboard is a single-page app that runs in one tab.
//      We don't need cross-tab or cross-session persistence (the backend
//      already has GET /scan/history for that).  When the user refreshes,
//      a clean slate is fine — they can always re-scan.
//
//   4. PERFORMANCE — Array operations (push, slice, map) are in-memory
//      and instant.  localStorage requires JSON.stringify/parse on every
//      read/write, which adds ~1-5 ms per operation for large objects.

export default function ScanHistory({ history = [] }) {
  if (history.length === 0) {
    return (
      <div className="w-full max-w-2xl mx-auto text-center py-8">
        <p className="text-sm text-[var(--color-text-muted)]">No scans yet — enter a URL above to get started.</p>
      </div>
    );
  }

  // Color mapping for the threat level badge
  const levelColor = {
    safe:       "bg-emerald-500/15 text-emerald-400",
    suspicious: "bg-amber-500/15 text-amber-400",
    malicious:  "bg-red-500/15 text-red-400",
  };

  return (
    <div className="w-full max-w-2xl mx-auto mb-8">
      <h2 className="text-sm font-semibold text-[var(--color-text-muted)] uppercase tracking-wider mb-3">
        Scan History ({history.length})
      </h2>

      <div className="overflow-hidden rounded-xl border border-[var(--color-border)]">
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-[var(--color-surface-2)] text-[var(--color-text-muted)] uppercase tracking-wider text-[10px]">
              <th className="text-left px-4 py-2.5 font-medium">URL</th>
              <th className="text-center px-3 py-2.5 font-medium">Threat Level</th>
              <th className="text-center px-3 py-2.5 font-medium">Score</th>
              <th className="text-right px-4 py-2.5 font-medium">Time</th>
            </tr>
          </thead>
          <tbody>
            {/* Show most recent first */}
            {[...history].reverse().map((scan, idx) => {
              const level = scan.final?.threat_level || "safe";
              const score = scan.final?.score ?? 0;
              const ms = scan.response_time_ms?.toFixed(0) ?? "?";

              // Truncate long URLs for display
              const displayUrl =
                scan.url?.length > 50
                  ? scan.url.substring(0, 47) + "…"
                  : scan.url || "—";

              return (
                <tr
                  key={idx}
                  className="border-t border-[var(--color-border)]/50 hover:bg-[var(--color-surface-2)]/40 transition-colors"
                >
                  <td className="px-4 py-2.5 text-slate-300 font-mono" title={scan.url}>
                    {displayUrl}
                  </td>
                  <td className="px-3 py-2.5 text-center">
                    <span className={`px-2 py-0.5 rounded-md text-[10px] font-semibold uppercase ${levelColor[level] || ""}`}>
                      {level}
                    </span>
                  </td>
                  <td className="px-3 py-2.5 text-center font-mono text-slate-300">
                    {score}/100
                  </td>
                  <td className="px-4 py-2.5 text-right text-[var(--color-text-muted)]">
                    {ms} ms
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

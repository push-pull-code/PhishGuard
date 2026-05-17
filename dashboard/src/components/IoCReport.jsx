

export default function IoCReport({ history = [] }) {
  if (history.length === 0) return null;

  const handleExport = () => {
    const report = {
      report_type: "PhishGuard IoC Report",
      generated_at: new Date().toISOString(),
      total_scans: history.length,
      summary: {
        safe: history.filter((s) => s.final?.threat_level === "safe").length,
        suspicious: history.filter((s) => s.final?.threat_level === "suspicious").length,
        malicious: history.filter((s) => s.final?.threat_level === "malicious").length,
      },
      indicators: history.map((scan) => ({
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

    const jsonString = JSON.stringify(report, null, 2);
    const blob = new Blob([jsonString], { type: "application/json" });

    const objectUrl = URL.createObjectURL(blob);

    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = `phishguard-ioc-report-${Date.now()}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);

    URL.revokeObjectURL(objectUrl);
  };

  return (
    <div className="w-full max-w-2xl mx-auto mb-8 flex justify-center">
      <button
        id="export-ioc-btn"
        onClick={handleExport}
        className="flex items-center gap-2 px-5 py-2.5 rounded-xl
                   bg-[var(--color-surface-2)] border border-[var(--color-border)]
                   hover:border-[var(--color-accent)] hover:bg-[var(--color-accent)]/10
                   text-sm font-medium text-[var(--color-text)] transition cursor-pointer"
      >
        📄 Export IoC Report ({history.length} scans)
      </button>
    </div>
  );
}

// FILE: IoCReport.jsx
// PURPOSE: "Export IoC Report" button — downloads all scan data as a JSON file
// CONNECTS TO: App.jsx
//
// FLOW: App passes scanHistory[] as prop → user clicks Export
//       → build JSON → Blob → Object URL → trigger download → revoke URL

// =====================================================================
// WHAT IS IoC (Indicators of Compromise)?
// =====================================================================
// In cybersecurity, an Indicator of Compromise (IoC) is a piece of
// forensic evidence that suggests a system or network has been breached.
// Examples of IoCs include:
//
//   • Malicious URLs or domains (what PhishGuard detects)
//   • IP addresses of known C2 (command & control) servers
//   • File hashes of malware samples
//   • Email addresses used in phishing campaigns
//   • Registry keys or file paths created by malware
//
// Security teams share IoC reports (often as JSON or STIX/TAXII feeds)
// so that firewalls, SIEMs, and other tools can automatically block
// known threats.  Our export gives analysts a ready-to-share list of
// every URL that PhishGuard flagged, along with all the supporting
// evidence (ML confidence, VT results, WHOIS data, etc.).

export default function IoCReport({ history = [] }) {
  // Don't show the button if there's nothing to export
  if (history.length === 0) return null;

  const handleExport = () => {
    // -----------------------------------------------------------------
    // BUILD THE REPORT
    // -----------------------------------------------------------------
    // We include every field from every scan so the analyst has full
    // context without needing to re-scan.
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

    // -----------------------------------------------------------------
    // DOWNLOAD TRICK: Blob + URL.createObjectURL
    // -----------------------------------------------------------------
    // Browsers don't let JavaScript directly write files to disk (security
    // sandbox).  The workaround is a three-step trick:
    //
    //   1. CREATE A BLOB
    //      A Blob (Binary Large Object) is an in-memory file-like object.
    //      We pass the JSON string and a MIME type so the browser knows
    //      it's a JSON file.
    //
    //   2. CREATE AN OBJECT URL
    //      URL.createObjectURL(blob) generates a temporary URL that
    //      points to the Blob in memory (e.g. "blob:http://localhost/abc").
    //      This URL can be used as an <a> href just like a regular file.
    //
    //   3. SIMULATE A CLICK ON A HIDDEN <a> TAG
    //      We create an invisible anchor element, set its href to the
    //      Blob URL, set the `download` attribute (which tells the
    //      browser to save instead of navigate), and programmatically
    //      click it.  This triggers the "Save As" dialog.
    //
    //   4. REVOKE THE URL
    //      After the download starts, we call URL.revokeObjectURL() to
    //      free the memory held by the Blob.  Without this, the Blob
    //      stays in memory until the page is closed — a memory leak if
    //      the user exports many times.

    // Step 1: Create Blob from JSON string
    const jsonString = JSON.stringify(report, null, 2);
    const blob = new Blob([jsonString], { type: "application/json" });

    // Step 2: Create temporary Object URL pointing to the Blob
    const objectUrl = URL.createObjectURL(blob);

    // Step 3: Create hidden <a>, set download filename, and click
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = `phishguard-ioc-report-${Date.now()}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);

    // Step 4: Revoke the Object URL to free memory
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

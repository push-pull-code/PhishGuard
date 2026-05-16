// FILE: ScanInput.jsx
// PURPOSE: URL input field + Scan button — sends POST /scan and lifts the result to App
// CONNECTS TO: App.jsx, backend/routes/scan.py
//
// FLOW: User types URL → clicks "Scan URL" → POST /scan → onResult(data) callback → App

import { useState } from "react";

// =====================================================================
// API ENDPOINT
// =====================================================================
// In development the Vite proxy rewrites "/api/*" to "http://localhost:8000/*"
// (configured in vite.config.js).  This avoids CORS issues during dev.
const API_URL = "/api/scan/";

export default function ScanInput({ onResult, onLoading }) {
  // ---------------------------------------------------------------
  // STATE
  // ---------------------------------------------------------------

  // url: string — the text the user has typed into the input field.
  //   Updated on every keystroke via the onChange handler.
  const [url, setUrl] = useState("");

  // loading: boolean — true while the fetch request is in-flight.
  //   Used to disable the button and show a spinner so the user
  //   knows the scan is running and can't accidentally fire duplicates.
  const [loading, setLoading] = useState(false);

  // error: string|null — holds an error message if the fetch fails.
  //   Displayed below the input.  Cleared on the next successful scan.
  const [error, setError] = useState(null);

  // ---------------------------------------------------------------
  // SCAN HANDLER
  // ---------------------------------------------------------------

  const handleScan = async () => {
    const trimmed = url.trim();
    if (!trimmed) return;

    setLoading(true);
    setError(null);
    onLoading?.(true);

    try {
      // ---------------------------------------------------------
      // fetch(API_URL, { method: "POST", ... })
      //
      // REQUEST shape (what we send):
      //   POST /api/scan/
      //   Content-Type: application/json
      //   Body: { "url": "https://example.com" }
      //
      // RESPONSE shape (what we expect back):
      //   {
      //     url: string,
      //     cleaned_url: string,
      //     obfuscation_found: string[],
      //     is_phishing: boolean,
      //     confidence: number,          // 0.0 – 1.0
      //     feature_values: { ... },
      //     threat_intel: {
      //       virustotal: { malicious_count, total_engines, ... },
      //       urlhaus: { is_known_malicious, tags, ... }
      //     },
      //     threat_score: {
      //       threat_level: "safe" | "suspicious" | "malicious",
      //       score: number,             // 0 – 100
      //       reasons: string[]
      //     },
      //     forensics: {
      //       whois: { domain_age_days, is_newly_registered, ... },
      //       dns: { has_a_record, has_mx_record, ... },
      //       typosquatting: { is_typosquat, closest_match, ... }
      //     },
      //     response_time_ms: number
      //   }
      // ---------------------------------------------------------
      const res = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: trimmed }),
      });

      if (!res.ok) {
        throw new Error(`Server returned ${res.status}`);
      }

      const data = await res.json();
      onResult?.(data);

    } catch (err) {
      const msg =
        err.message.includes("Failed to fetch") || err.message.includes("NetworkError")
          ? "Backend not running — start with: python backend/main.py"
          : `Scan failed: ${err.message}`;
      setError(msg);
      onResult?.(null);
    } finally {
      setLoading(false);
      onLoading?.(false);
    }
  };

  // Submit on Enter key
  const handleKeyDown = (e) => {
    if (e.key === "Enter") handleScan();
  };

  // ---------------------------------------------------------------
  // RENDER
  // ---------------------------------------------------------------

  return (
    <div className="w-full max-w-2xl mx-auto mb-8">
      <div className="flex gap-3">
        <input
          id="url-input"
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="https://example.com"
          className="flex-1 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-2)]/60
                     px-4 py-3 text-sm text-[var(--color-text)] placeholder:text-[var(--color-text-muted)]
                     outline-none focus:ring-2 focus:ring-[var(--color-accent)] transition"
        />
        <button
          id="scan-button"
          onClick={handleScan}
          disabled={loading || !url.trim()}
          className="rounded-xl bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)]
                     disabled:opacity-40 disabled:cursor-not-allowed
                     px-6 py-3 text-sm font-semibold text-white transition cursor-pointer
                     flex items-center gap-2"
        >
          {loading ? (
            <>
              {/* Simple CSS spinner */}
              <span className="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Scanning…
            </>
          ) : (
            "🔍 Scan URL"
          )}
        </button>
      </div>

      {/* Error message */}
      {error && (
        <p className="mt-3 text-sm text-[var(--color-malicious)] bg-red-500/10 border border-red-500/20
                      rounded-lg px-4 py-2">
          {error}
        </p>
      )}
    </div>
  );
}

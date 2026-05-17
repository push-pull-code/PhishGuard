
import { useState } from "react";

const API_URL = "/api/scan/";

export default function ScanInput({ onResult, onLoading }) {

  const [url, setUrl] = useState("");

  const [loading, setLoading] = useState(false);

  const [error, setError] = useState(null);

  const handleScan = async () => {
    const trimmed = url.trim();
    if (!trimmed) return;

    setLoading(true);
    setError(null);
    onLoading?.(true);

    try {
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

  const handleKeyDown = (e) => {
    if (e.key === "Enter") handleScan();
  };

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

              <span className="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Scanning…
            </>
          ) : (
            "🔍 Scan URL"
          )}
        </button>
      </div>

      {error && (
        <p className="mt-3 text-sm text-[var(--color-malicious)] bg-red-500/10 border border-red-500/20
                      rounded-lg px-4 py-2">
          {error}
        </p>
      )}
    </div>
  );
}

// FILE: App.jsx
// PURPOSE: Root React component — wires all dashboard components together
// CONNECTS TO: dashboard/src/main.jsx, all components in dashboard/src/components/
//
// DATA FLOW:
// User enters URL → ScanInput → POST /scan
// → ResultCard shows result
// → ScanHistory stores it
// → RiskChart updates
// → IoCReport can export it

import { useState } from "react";

import ScanInput   from "./components/ScanInput.jsx";
import ResultCard  from "./components/ResultCard.jsx";
import ScanHistory from "./components/ScanHistory.jsx";
import RiskChart   from "./components/RiskChart.jsx";
import IoCReport   from "./components/IoCReport.jsx";

// Maximum number of scans to keep in the history array.
const MAX_HISTORY = 10;

export default function App() {
  // ---------------------------------------------------------------
  // STATE
  // ---------------------------------------------------------------

  // latestResult: object|null — the scan response from the most recent
  //   POST /scan call.  Passed to ResultCard for display.
  //   null means no scan has been performed yet.
  const [latestResult, setLatestResult] = useState(null);

  // scanHistory: array — ordered list of the last MAX_HISTORY scan
  //   results (oldest first).  Fed to ScanHistory table, RiskChart,
  //   and IoCReport.
  const [scanHistory, setScanHistory] = useState([]);

  // isLoading: boolean — true while a scan is in-flight.
  //   Used to dim the result card and show a global loading indicator.
  const [isLoading, setIsLoading] = useState(false);

  // ---------------------------------------------------------------
  // HANDLERS
  // ---------------------------------------------------------------

  const handleResult = (data) => {
    setLatestResult(data);

    if (data) {
      setScanHistory((prev) => {
        // Append the new scan and keep only the last MAX_HISTORY entries
        const updated = [...prev, data];
        return updated.slice(-MAX_HISTORY);
      });
    }
  };

  // ---------------------------------------------------------------
  // RENDER
  // ---------------------------------------------------------------

  return (
    <div className="min-h-screen flex flex-col items-center px-4 py-10">

      {/* ============================== */}
      {/* HEADER                         */}
      {/* ============================== */}
      <header className="text-center mb-8">
        <h1 className="text-4xl font-bold tracking-tight mb-2
                        bg-gradient-to-r from-indigo-400 to-cyan-400 bg-clip-text text-transparent">
          🛡️ PhishGuard
        </h1>
        <p className="text-[var(--color-text-muted)] text-sm max-w-md">
          Real-time phishing URL detection — powered by ML, threat intelligence, and domain forensics.
        </p>
      </header>

      {/* ============================== */}
      {/* URL INPUT                      */}
      {/* ============================== */}
      <ScanInput
        onResult={handleResult}
        onLoading={setIsLoading}
      />

      {/* ============================== */}
      {/* LATEST RESULT                  */}
      {/* ============================== */}
      <div className={`w-full transition-opacity duration-300 ${isLoading ? "opacity-40" : "opacity-100"}`}>
        <ResultCard result={latestResult} />
      </div>

      {/* ============================== */}
      {/* RISK CHART                     */}
      {/* ============================== */}
      <RiskChart history={scanHistory} />

      {/* ============================== */}
      {/* SCAN HISTORY TABLE             */}
      {/* ============================== */}
      <ScanHistory history={scanHistory} />

      {/* ============================== */}
      {/* IOC EXPORT                     */}
      {/* ============================== */}
      <IoCReport history={scanHistory} />

      {/* ============================== */}
      {/* FOOTER                         */}
      {/* ============================== */}
      <footer className="mt-12 text-center text-[10px] text-[var(--color-text-muted)]">
        PhishGuard v1.0.0 — ML + Threat Intel + Domain Forensics
      </footer>
    </div>
  );
}

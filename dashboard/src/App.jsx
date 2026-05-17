
import { useState } from "react";

import ScanInput   from "./components/ScanInput.jsx";
import ResultCard  from "./components/ResultCard.jsx";
import ScanHistory from "./components/ScanHistory.jsx";
import RiskChart   from "./components/RiskChart.jsx";
import IoCReport   from "./components/IoCReport.jsx";

const MAX_HISTORY = 10;

export default function App() {

  const [latestResult, setLatestResult] = useState(null);

  const [scanHistory, setScanHistory] = useState([]);

  const [isLoading, setIsLoading] = useState(false);

  const handleResult = (data) => {
    setLatestResult(data);

    if (data) {
      setScanHistory((prev) => {
        const updated = [...prev, data];
        return updated.slice(-MAX_HISTORY);
      });
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center px-4 py-10">

      <header className="text-center mb-8">
        <h1 className="text-4xl font-bold tracking-tight mb-2
                        bg-gradient-to-r from-pink-500 via-purple-500 to-indigo-500 bg-clip-text text-transparent">
          🛡️ PhishGuard
        </h1>
        <p className="text-[var(--color-text-muted)] text-sm max-w-md">
          Real-time phishing URL detection — powered by ML, threat intelligence, and domain forensics.
        </p>
      </header>

      <ScanInput
        onResult={handleResult}
        onLoading={setIsLoading}
      />

      <div className={`w-full transition-opacity duration-300 ${isLoading ? "opacity-40" : "opacity-100"}`}>
        <ResultCard result={latestResult} />
      </div>

      <RiskChart history={scanHistory} />

      <ScanHistory history={scanHistory} />

      <IoCReport history={scanHistory} />

      <footer className="mt-12 text-center text-[10px] text-[var(--color-text-muted)]">
        PhishGuard v1.0.0 — ML + Threat Intel + Domain Forensics
      </footer>
    </div>
  );
}

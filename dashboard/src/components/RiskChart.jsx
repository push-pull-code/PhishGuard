// FILE: RiskChart.jsx
// PURPOSE: Bar chart showing the count of safe / suspicious / malicious scans from history
// CONNECTS TO: App.jsx
//
// FLOW: App passes scanHistory[] as prop → RiskChart aggregates counts → renders Recharts BarChart

// =====================================================================
// RECHARTS COMPONENT GLOSSARY
// =====================================================================
// Recharts is a React charting library built on D3.  Every visual element
// is a declarative React component:
//
//   <ResponsiveContainer>
//     Wraps the chart and makes it resize automatically to fill its
//     parent container.  You set width="100%" and a fixed height.
//     Without this, the chart would overflow or collapse.
//
//   <BarChart data={[...]}>
//     The top-level chart component.  Accepts an array of data objects
//     and renders bars for each entry.  The `data` prop is the single
//     source of truth — all child components read from it.
//
//   <XAxis dataKey="name">
//     Draws the horizontal axis.  `dataKey` tells it which field in each
//     data object to use as the category label (e.g. "Safe", "Suspicious").
//
//   <YAxis allowDecimals={false}>
//     Draws the vertical axis.  `allowDecimals={false}` forces integer
//     ticks since we're counting scans (you can't have 1.5 scans).
//
//   <Tooltip>
//     Shows a floating box when the user hovers over a bar, displaying
//     the exact value.  Adds interactivity without cluttering the chart.
//
//   <Bar dataKey="count" fill="...">
//     Renders one bar per data entry.  `dataKey` maps to the numeric
//     field to visualise.  `fill` sets the bar color.  `radius` rounds
//     the top corners for a modern look.
//
//   <Cell>
//     Allows per-bar customisation (e.g. different colors for each bar).
//     We use it to color Safe=green, Suspicious=amber, Malicious=red.

import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
} from "recharts";

// Colors matching our threat level palette
const COLORS = {
  Safe: "#22c55e",        // emerald-500
  Suspicious: "#f59e0b",  // amber-500
  Malicious: "#ef4444",   // red-500
};

export default function RiskChart({ history = [] }) {
  // --- Aggregate counts from the scan history array ---
  const counts = { Safe: 0, Suspicious: 0, Malicious: 0 };

  for (const scan of history) {
    const level = scan.final?.threat_level;
    if (level === "safe") counts.Safe++;
    else if (level === "suspicious") counts.Suspicious++;
    else if (level === "malicious") counts.Malicious++;
  }

  // Recharts expects an array of objects, one per bar
  const chartData = [
    { name: "Safe",       count: counts.Safe },
    { name: "Suspicious", count: counts.Suspicious },
    { name: "Malicious",  count: counts.Malicious },
  ];

  // Don't render the chart if there's no data yet
  if (history.length === 0) return null;

  return (
    <div className="w-full max-w-2xl mx-auto mb-8">
      <h2 className="text-sm font-semibold text-[var(--color-text-muted)] uppercase tracking-wider mb-3">
        Risk Distribution
      </h2>

      <div className="bg-[var(--color-surface-2)]/40 border border-[var(--color-border)] rounded-xl p-4">
        {/* ResponsiveContainer: makes the chart fill available width */}
        <ResponsiveContainer width="100%" height={220}>
          {/* BarChart: the main chart, fed by chartData */}
          <BarChart data={chartData} barCategoryGap="30%">

            {/* XAxis: horizontal axis showing category names */}
            <XAxis
              dataKey="name"
              axisLine={false}
              tickLine={false}
              tick={{ fill: "#94a3b8", fontSize: 12 }}
            />

            {/* YAxis: vertical axis showing scan counts (integers only) */}
            <YAxis
              allowDecimals={false}
              axisLine={false}
              tickLine={false}
              tick={{ fill: "#64748b", fontSize: 11 }}
              width={30}
            />

            {/* Tooltip: hover popup showing exact value */}
            <Tooltip
              contentStyle={{
                background: "#1e293b",
                border: "1px solid #334155",
                borderRadius: "8px",
                fontSize: "12px",
                color: "#f8fafc",
              }}
              cursor={{ fill: "rgba(255,255,255,0.03)" }}
            />

            {/* Bar: the actual bars, one per data entry */}
            <Bar dataKey="count" radius={[6, 6, 0, 0]} maxBarSize={60}>
              {/* Cell: per-bar color based on threat level */}
              {chartData.map((entry) => (
                <Cell key={entry.name} fill={COLORS[entry.name]} />
              ))}
            </Bar>

          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

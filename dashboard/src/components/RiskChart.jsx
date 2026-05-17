

import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
} from "recharts";

const COLORS = {
  Safe: "#22c55e",
  Suspicious: "#f59e0b",
  Malicious: "#ef4444",
};

export default function RiskChart({ history = [] }) {
  const counts = { Safe: 0, Suspicious: 0, Malicious: 0 };

  for (const scan of history) {
    const level = scan.final?.threat_level;
    if (level === "safe") counts.Safe++;
    else if (level === "suspicious") counts.Suspicious++;
    else if (level === "malicious") counts.Malicious++;
  }

  const chartData = [
    { name: "Safe",       count: counts.Safe },
    { name: "Suspicious", count: counts.Suspicious },
    { name: "Malicious",  count: counts.Malicious },
  ];

  if (history.length === 0) return null;

  return (
    <div className="w-full max-w-2xl mx-auto mb-8">
      <h2 className="text-sm font-semibold text-[var(--color-text-muted)] uppercase tracking-wider mb-3">
        Risk Distribution
      </h2>

      <div className="bg-[var(--color-surface-2)]/40 border border-[var(--color-border)] rounded-xl p-4">
        
        <ResponsiveContainer width="100%" height={220}>
          
          <BarChart data={chartData} barCategoryGap="30%">

            <XAxis
              dataKey="name"
              axisLine={false}
              tickLine={false}
              tick={{ fill: "#94a3b8", fontSize: 12 }}
            />

            <YAxis
              allowDecimals={false}
              axisLine={false}
              tickLine={false}
              tick={{ fill: "#64748b", fontSize: 11 }}
              width={30}
            />

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

            <Bar dataKey="count" radius={[6, 6, 0, 0]} maxBarSize={60}>
              
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

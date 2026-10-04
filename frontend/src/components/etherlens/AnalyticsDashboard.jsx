import { AreaChart, Area, PieChart, Pie, Cell, Tooltip, ResponsiveContainer, XAxis, YAxis, CartesianGrid, Legend } from "recharts";
import { fmtBytes, fmtBps, PROTO_COLOR } from "./lib";
import { Activity, Server, Shield, Zap } from "lucide-react";

export default function AnalyticsDashboard({ status, timeline, topTalkers }) {
  const chartData = timeline.map((b) => ({
    time: new Date(b.t * 1000).toLocaleTimeString([], { minute: "2-digit", second: "2-digit" }),
    pps: b.pps,
    kbps: Math.round(b.bps / 1000),
  }));

  const protoCounts = status.protocol_counts || {};
  const pie = Object.entries(protoCounts).map(([k, v]) => ({ name: k, value: v })).sort((a, b) => b.value - a.value);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <KPI testId="kpi-total-packets" icon={<Activity size={16} />} label="Total Packets" value={(status.total_packets || 0).toLocaleString()} tone="blue" />
        <KPI testId="kpi-throughput" icon={<Zap size={16} />} label="Throughput" value={fmtBps((status.mbps || 0) * 1_000_000)} tone="emerald" />
        <KPI testId="kpi-hosts" icon={<Server size={16} />} label="Unique Hosts" value={status.unique_hosts || 0} tone="indigo" />
        <KPI testId="kpi-threats" icon={<Shield size={16} />} label="Threats Detected" value={status.threats || 0} tone={status.threats ? "rose" : "slate"} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card title="Traffic over time" testId="chart-traffic" className="lg:col-span-2">
          <div style={{ height: 260 }}>
            <ResponsiveContainer>
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="g-pps" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#2563eb" stopOpacity={0.6} />
                    <stop offset="100%" stopColor="#2563eb" stopOpacity={0.02} />
                  </linearGradient>
                  <linearGradient id="g-bps" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#059669" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#059669" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(100,116,139,0.15)" />
                <XAxis dataKey="time" tick={{ fontSize: 11 }} stroke="#64748b" />
                <YAxis yAxisId="l" tick={{ fontSize: 11 }} stroke="#64748b" />
                <YAxis yAxisId="r" orientation="right" tick={{ fontSize: 11 }} stroke="#64748b" />
                <Tooltip contentStyle={{ background: "rgba(15,23,42,0.95)", border: "none", borderRadius: 8, color: "#fff", fontSize: 12 }} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Area yAxisId="l" type="monotone" dataKey="pps" name="Packets/sec" stroke="#2563eb" strokeWidth={2} fill="url(#g-pps)" />
                <Area yAxisId="r" type="monotone" dataKey="kbps" name="Kbps" stroke="#059669" strokeWidth={2} fill="url(#g-bps)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card title="Protocol distribution" testId="chart-proto">
          <div style={{ height: 260 }}>
            <ResponsiveContainer>
              <PieChart>
                <Pie data={pie} dataKey="value" nameKey="name" innerRadius={60} outerRadius={95} paddingAngle={2}>
                  {pie.map((e) => <Cell key={e.name} fill={PROTO_COLOR[e.name] || "#94a3b8"} />)}
                </Pie>
                <Tooltip contentStyle={{ background: "rgba(15,23,42,0.95)", border: "none", borderRadius: 8, color: "#fff", fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-x-3 gap-y-1 mt-2">
            {pie.slice(0, 8).map((e) => (
              <div key={e.name} className="flex items-center gap-2 text-xs">
                <span className="w-2.5 h-2.5 rounded-sm" style={{ background: PROTO_COLOR[e.name] || "#94a3b8" }} />
                <span className="font-mono-code">{e.name}</span>
                <span className="ml-auto text-slate-500">{e.value}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card title="Top talkers" testId="top-talkers">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-slate-500 dark:text-slate-400 text-xs uppercase tracking-wider">
              <th className="py-2 font-semibold">Host</th>
              <th className="py-2 font-semibold text-right">Packets</th>
              <th className="py-2 font-semibold text-right">Bytes</th>
              <th className="py-2 font-semibold">Ports seen</th>
              <th className="py-2 font-semibold w-1/4">Usage</th>
            </tr>
          </thead>
          <tbody className="font-mono-code">
            {topTalkers.length === 0 && (
              <tr><td colSpan={5} className="py-6 text-center text-slate-400">No data yet</td></tr>
            )}
            {(() => {
              const max = Math.max(1, ...topTalkers.map((t) => t.bytes));
              return topTalkers.map((t) => (
                <tr key={t.ip} data-testid={`talker-${t.ip}`} className="border-t border-slate-100 dark:border-slate-800">
                  <td className="py-1.5">{t.ip}</td>
                  <td className="py-1.5 text-right">{t.packets.toLocaleString()}</td>
                  <td className="py-1.5 text-right">{fmtBytes(t.bytes)}</td>
                  <td className="py-1.5 text-xs text-slate-500">{t.ports.slice(0, 6).join(", ") || "—"}</td>
                  <td className="py-1.5">
                    <div className="h-1.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-gradient-to-r from-blue-500 to-indigo-500" style={{ width: `${(t.bytes / max) * 100}%` }} />
                    </div>
                  </td>
                </tr>
              ));
            })()}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function KPI({ icon, label, value, tone = "slate", testId }) {
  const tones = {
    blue: "bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-200/60 dark:border-blue-500/30",
    emerald: "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-200/60 dark:border-emerald-500/30",
    indigo: "bg-indigo-50 dark:bg-indigo-500/10 text-indigo-700 dark:text-indigo-300 border-indigo-200/60 dark:border-indigo-500/30",
    rose: "bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-200/60 dark:border-rose-500/30",
    slate: "bg-slate-50 dark:bg-slate-800/60 text-slate-700 dark:text-slate-200 border-slate-200 dark:border-slate-700",
  };
  return (
    <div data-testid={testId} className={`rounded-xl border p-4 ${tones[tone]}`}>
      <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider opacity-80">
        {icon} {label}
      </div>
      <div className="mt-1.5 text-2xl font-display font-bold">{value}</div>
    </div>
  );
}

function Card({ title, children, className = "", testId }) {
  return (
    <div data-testid={testId} className={`bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-4 ${className}`}>
      <h3 className="font-display font-bold text-sm mb-3">{title}</h3>
      {children}
    </div>
  );
}

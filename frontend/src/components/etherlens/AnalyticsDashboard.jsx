import { AreaChart, Area, PieChart, Pie, Cell, Tooltip, ResponsiveContainer, XAxis, YAxis, CartesianGrid, Legend } from "recharts";
import { fmtBytes, fmtBps, PROTO_COLOR } from "./lib";
import { Activity, AlertTriangle, ArrowRight, Clock3, Radar, Server, Shield, Zap } from "lucide-react";
import NetworkBaselinePanel from "./NetworkBaselinePanel";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEVERITY_STYLES = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-blue-500",
  info: "bg-slate-400",
};

export default function AnalyticsDashboard({ status, timeline = [], topTalkers = [], hosts = [], threats = [], onInvestigate, onOpenThreats }) {
  const chartData = timeline.map((bucket) => ({
    time: new Date(bucket.t * 1000).toLocaleTimeString([], { minute: "2-digit", second: "2-digit" }),
    pps: bucket.pps,
    kbps: Math.round(bucket.bps / 1000),
  }));
  const protoCounts = status.protocol_counts || {};
  const pie = Object.entries(protoCounts).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  const findings = mergeFindings(threats, hosts.flatMap((host) => host.findings || []));
  const severityCounts = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]));
  findings.forEach((finding) => {
    const severity = String(finding.severity || "info").toLowerCase();
    severityCounts[SEVERITIES.includes(severity) ? severity : "info"] += 1;
  });
  const prioritized = severityCounts.critical + severityCounts.high;
  const riskyHosts = [...hosts].filter((host) => Number(host.risk?.score || 0) > 0).sort((a, b) => Number(b.risk?.score || 0) - Number(a.risk?.score || 0));
  const maxRisk = Number(riskyHosts[0]?.risk?.score || 0);
  const posture = maxRisk >= 75 || severityCounts.critical ? "critical" : maxRisk >= 50 || severityCounts.high ? "elevated" : findings.length ? "guarded" : "clear";
  const totalFindings = findings.length;

  return (
    <div className="space-y-4">
      <PostureBanner posture={posture} prioritized={prioritized} total={totalFindings} running={status.running} mode={status.mode} onOpenThreats={onOpenThreats} />

      <NetworkBaselinePanel capturePacketCount={Number(status.total_packets || 0)} />

      <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
        <KPI testId="kpi-total-packets" icon={<Activity size={16} />} label="Total Packets" value={(status.total_packets || 0).toLocaleString()} tone="blue" />
        <KPI testId="kpi-throughput" icon={<Zap size={16} />} label="Throughput" value={fmtBps((status.mbps || 0) * 1_000_000)} tone="emerald" />
        <KPI testId="kpi-hosts" icon={<Server size={16} />} label="Observed Hosts" value={hosts.length || status.unique_hosts || 0} helper={`${riskyHosts.length} with risk evidence`} tone="indigo" />
        <KPI testId="kpi-threats" icon={<Shield size={16} />} label="Security Findings" value={totalFindings || status.threats || 0} helper={`${prioritized} high priority`} tone={(totalFindings || status.threats) ? "rose" : "slate"} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <Card title="Traffic over time" subtitle="Live packet rate and network throughput" testId="chart-traffic" className="xl:col-span-2">
          {chartData.length ? <div style={{ height: 260 }}>
            <ResponsiveContainer>
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="g-pps" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#2563eb" stopOpacity={0.6} /><stop offset="100%" stopColor="#2563eb" stopOpacity={0.02} /></linearGradient>
                  <linearGradient id="g-bps" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#059669" stopOpacity={0.5} /><stop offset="100%" stopColor="#059669" stopOpacity={0.02} /></linearGradient>
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
          </div> : <EmptyState icon={<Activity size={22} />} text="Start a capture or import a PCAP to chart network activity." />}
        </Card>

        <Card title="Protocol distribution" subtitle="Observed application and transport mix" testId="chart-proto">
          {pie.length ? <><div style={{ height: 220 }}><ResponsiveContainer><PieChart><Pie data={pie} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={2}>{pie.map((entry) => <Cell key={entry.name} fill={PROTO_COLOR[entry.name] || "#94a3b8"} />)}</Pie><Tooltip contentStyle={{ background: "rgba(15,23,42,0.95)", border: "none", borderRadius: 8, color: "#fff", fontSize: 12 }} /></PieChart></ResponsiveContainer></div><div className="grid grid-cols-2 gap-x-3 gap-y-1 mt-2">{pie.slice(0, 8).map((entry) => <div key={entry.name} className="flex items-center gap-2 text-xs"><span className="w-2.5 h-2.5 rounded-sm" style={{ background: PROTO_COLOR[entry.name] || "#94a3b8" }} /><span className="font-mono-code">{entry.name}</span><span className="ml-auto text-slate-500">{entry.value}</span></div>)}</div></> : <EmptyState icon={<Radar size={22} />} text="Protocol telemetry will appear here." />}
        </Card>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <Card title="Security priority" subtitle="Current findings grouped by severity" testId="security-priority">
          <div className="space-y-3">
            {SEVERITIES.map((severity) => {
              const count = severityCounts[severity];
              const width = totalFindings ? Math.max(count ? 5 : 0, (count / totalFindings) * 100) : 0;
              return <div key={severity}><div className="flex items-center text-xs"><span className="capitalize font-semibold">{severity}</span><span className="ml-auto font-mono-code text-slate-500">{count}</span></div><div className="mt-1.5 h-2 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden"><div className={`h-full rounded-full ${SEVERITY_STYLES[severity]}`} style={{ width: `${width}%` }} /></div></div>;
            })}
          </div>
          <button onClick={onOpenThreats} className="mt-4 w-full inline-flex items-center justify-center gap-2 rounded-lg bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 px-3 py-2 text-xs font-semibold">Review all findings <ArrowRight size={13} /></button>
        </Card>

        <Card title="Highest-risk hosts" subtitle="Prioritized using finding severity and confidence" testId="risk-hosts" className="xl:col-span-2">
          {riskyHosts.length ? <div className="divide-y divide-slate-100 dark:divide-slate-800">{riskyHosts.slice(0, 5).map((host) => <button key={host.ip} onClick={() => onInvestigate?.({ source: host.ip })} className="w-full grid grid-cols-[minmax(0,1fr)_90px_88px] gap-3 items-center py-2.5 text-left hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-lg px-2 transition-colors"><span className="min-w-0"><span className="block font-mono-code text-xs font-semibold truncate">{host.ip}</span><span className="block text-[11px] text-slate-500 truncate mt-1">{host.hostname || (host.is_local ? "Local host" : "External host")} · {(host.protocols || []).slice(0, 4).join(", ") || "No protocol label"}</span></span><span className="text-right text-xs text-slate-500">{host.finding_count || 0} findings</span><RiskScore risk={host.risk} /></button>)}</div> : <EmptyState icon={<Shield size={22} />} text="No host risk evidence has been observed." compact />}
        </Card>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <Card title="Top talkers" subtitle="Hosts ranked by observed traffic volume" testId="top-talkers" className="xl:col-span-2">
          <div className="overflow-x-auto el-scroll"><table className="w-full text-sm"><thead><tr className="text-left text-slate-500 dark:text-slate-400 text-xs uppercase tracking-wider"><th className="py-2 font-semibold">Host</th><th className="py-2 font-semibold text-right">Packets</th><th className="py-2 font-semibold text-right">Bytes</th><th className="py-2 font-semibold">Ports seen</th><th className="py-2 font-semibold w-1/4">Usage</th></tr></thead><tbody className="font-mono-code">{!topTalkers.length && <tr><td colSpan={5} className="py-8 text-center text-slate-400">No traffic data yet</td></tr>}{(() => { const max = Math.max(1, ...topTalkers.map((talker) => talker.bytes)); return topTalkers.map((talker) => <tr key={talker.ip} data-testid={`talker-${talker.ip}`} className="border-t border-slate-100 dark:border-slate-800"><td className="py-1.5">{talker.ip}</td><td className="py-1.5 text-right">{talker.packets.toLocaleString()}</td><td className="py-1.5 text-right">{fmtBytes(talker.bytes)}</td><td className="py-1.5 text-xs text-slate-500">{talker.ports.slice(0, 6).join(", ") || "—"}</td><td className="py-1.5"><div className="h-1.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden"><div className="h-full bg-gradient-to-r from-blue-500 to-indigo-500" style={{ width: `${(talker.bytes / max) * 100}%` }} /></div></td></tr>); })()}</tbody></table></div>
        </Card>

        <Card title="Recent detections" subtitle="Newest investigation leads" testId="recent-detections">
          {findings.length ? <div className="space-y-2">{findings.slice(0, 5).map((finding, index) => <button key={finding.id || `${finding.type}-${index}`} onClick={onOpenThreats} className="w-full text-left rounded-lg border border-slate-100 dark:border-slate-800 p-3 hover:bg-slate-50 dark:hover:bg-slate-800"><div className="flex items-center gap-2"><SeverityBadge severity={finding.severity} /><span className="text-xs font-semibold truncate">{finding.title || finding.type || "Investigation lead"}</span></div><div className="mt-1.5 text-[11px] text-slate-500 font-mono-code truncate">{finding.src_ip || finding.src || "unknown"} → {finding.dst_ip || finding.dst || finding.target || "unknown"}</div></button>)}</div> : <EmptyState icon={<Clock3 size={22} />} text="No security detections have been recorded." compact />}
        </Card>
      </div>
    </div>
  );
}

function PostureBanner({ posture, prioritized, total, running, mode, onOpenThreats }) {
  const config = {
    critical: { title: "Critical investigation required", body: `${prioritized} high-priority finding(s) need review.`, style: "border-red-300 bg-red-50 dark:border-red-500/30 dark:bg-red-500/10 text-red-800 dark:text-red-200" },
    elevated: { title: "Elevated security posture", body: `${prioritized} high-priority finding(s) should be triaged.`, style: "border-orange-300 bg-orange-50 dark:border-orange-500/30 dark:bg-orange-500/10 text-orange-800 dark:text-orange-200" },
    guarded: { title: "Guarded security posture", body: `${total} finding(s) are available for investigation.`, style: "border-amber-300 bg-amber-50 dark:border-amber-500/30 dark:bg-amber-500/10 text-amber-800 dark:text-amber-200" },
    clear: { title: "No active security findings", body: "nScout has not observed suspicious evidence in the current capture.", style: "border-emerald-300 bg-emerald-50 dark:border-emerald-500/30 dark:bg-emerald-500/10 text-emerald-800 dark:text-emerald-200" },
  }[posture];
  return <div data-testid="security-posture" className={`rounded-xl border p-4 flex flex-wrap items-center gap-4 ${config.style}`}><div className="rounded-lg bg-white/60 dark:bg-black/10 p-2"><AlertTriangle size={20} /></div><div className="min-w-0 flex-1"><div className="font-display font-bold">{config.title}</div><div className="text-xs mt-1 opacity-80">{config.body}</div></div><div className="text-right"><div className="text-[10px] uppercase tracking-wider opacity-70">Capture state</div><div className="text-xs font-mono-code font-semibold mt-1">{running ? String(mode || "live").toUpperCase() : "IDLE"}</div></div>{total > 0 && <button onClick={onOpenThreats} className="rounded-lg bg-white/70 dark:bg-black/20 px-3 py-2 text-xs font-semibold">Open findings</button>}</div>;
}

function KPI({ icon, label, value, helper, tone = "slate", testId }) {
  const tones = { blue: "bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-200/60 dark:border-blue-500/30", emerald: "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-200/60 dark:border-emerald-500/30", indigo: "bg-indigo-50 dark:bg-indigo-500/10 text-indigo-700 dark:text-indigo-300 border-indigo-200/60 dark:border-indigo-500/30", rose: "bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-200/60 dark:border-rose-500/30", slate: "bg-slate-50 dark:bg-slate-800/60 text-slate-700 dark:text-slate-200 border-slate-200 dark:border-slate-700" };
  return <div data-testid={testId} className={`rounded-xl border p-4 ${tones[tone]}`}><div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider opacity-80">{icon} {label}</div><div className="mt-1.5 text-2xl font-display font-bold">{value}</div>{helper && <div className="mt-1 text-[11px] opacity-70">{helper}</div>}</div>;
}

function Card({ title, subtitle, children, className = "", testId }) { return <section data-testid={testId} className={`bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-4 ${className}`}><div className="mb-3"><h3 className="font-display font-bold text-sm">{title}</h3>{subtitle && <p className="text-[11px] text-slate-500 mt-1">{subtitle}</p>}</div>{children}</section>; }
function RiskScore({ risk = {} }) { const score = Number(risk.score || 0); const style = score >= 75 ? "bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-300" : score >= 50 ? "bg-orange-100 text-orange-700 dark:bg-orange-500/10 dark:text-orange-300" : score >= 25 ? "bg-amber-100 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300" : "bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-300"; return <span className={`rounded-full px-2 py-1 text-[10px] font-bold uppercase text-center ${style}`}>{score} {risk.level || "low"}</span>; }
function SeverityBadge({ severity = "info" }) { const value = String(severity).toLowerCase(); return <span className={`rounded-full px-2 py-0.5 text-[9px] uppercase font-bold text-white ${SEVERITY_STYLES[value] || SEVERITY_STYLES.info}`}>{value}</span>; }
function EmptyState({ icon, text, compact = false }) { return <div className={`flex flex-col items-center justify-center text-center text-slate-400 ${compact ? "py-8" : "py-16"}`}><span className="mb-2">{icon}</span><span className="text-xs max-w-xs">{text}</span></div>; }
function mergeFindings(...groups) { const seen = new Set(); return groups.flat().filter((finding, index) => { const key = [finding.id, finding.type, finding.packet_id, finding.src_ip || finding.src, finding.dst_ip || finding.dst, finding.title].filter(Boolean).join("|") || `finding-${index}`; if (seen.has(key)) return false; seen.add(key); return true; }); }

import { useRef } from "react";
import { Play, Square, Trash2, Upload, Moon, Sun, Radio, Zap, HardDrive, ShieldAlert, Search, Download, Settings, Archive, Activity, CircleHelp } from "lucide-react";
import { fmtBps, API } from "./lib";

const PROTOCOLS = ["", "TCP", "UDP", "HTTPS", "HTTP", "DNS", "ICMP", "ARP", "SSH", "TLS"];

export default function HeaderNav({
  theme, setTheme, interfaces, iface, setIface, status,
  onStart, onStop, onClear, onUpload, filter, setFilter, protocolFilter, setProtocolFilter,
  onOpenSettings, onOpenShortcuts, onOpenSessions,
}) {
  const fileRef = useRef(null);

  return (
    <header className="sticky top-0 z-30 bg-white/95 dark:bg-slate-950/90 backdrop-blur-md border-b border-slate-200 dark:border-slate-800">
      <div className="mx-auto max-w-[1700px] px-4 sm:px-6 lg:px-8 py-3">
        <div className="flex items-center gap-4 flex-wrap">
          {/* Logo */}
          <div className="flex items-center gap-2">
            <div className="relative">
              <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center shadow-md">
                <Radio size={18} className="text-white" />
              </div>
            </div>
            <div>
              <div className="font-display text-base font-bold tracking-tight leading-none">nScout</div>
              <div className="text-[10px] text-slate-500 dark:text-slate-400 font-mono-code tracking-wide">PACKET TELEMETRY</div>
            </div>
          </div>

          <div className="h-8 w-px bg-slate-200 dark:bg-slate-800" />

          {/* Interface select */}
          <div className="flex items-center gap-2">
            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Interface</label>
            <select
              data-testid="interface-select"
              value={iface}
              onChange={(e) => setIface(e.target.value)}
              className="rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm px-2.5 py-1.5 font-mono-code focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {interfaces.map((i) => (
                <option key={i.name} value={i.name}>{i.label}</option>
              ))}
            </select>
          </div>

          {/* Capture controls */}
          <div className="flex items-center gap-2">
            {!status.running ? (
              <button
                data-testid="live-capture-start-btn"
                onClick={onStart}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-semibold shadow-sm transition-colors"
              >
                <Play size={14} /> Start
              </button>
            ) : (
              <button
                data-testid="live-capture-stop-btn"
                onClick={onStop}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-rose-600 hover:bg-rose-700 text-white text-sm font-semibold shadow-sm transition-colors"
              >
                <Square size={14} /> Stop
              </button>
            )}
            <button
              data-testid="capture-clear-btn"
              onClick={onClear}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-sm font-semibold text-slate-700 dark:text-slate-200 transition-colors"
            >
              <Trash2 size={14} /> Clear
            </button>
            <button
              data-testid="pcap-upload-btn"
              onClick={() => fileRef.current?.click()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold shadow-sm transition-colors"
            >
              <Upload size={14} /> Upload PCAP
            </button>
            <input
              ref={fileRef}
              data-testid="pcap-file-upload-input"
              type="file"
              accept=".pcap,.pcapng,.cap"
              hidden
              onChange={(e) => { const f = e.target.files?.[0]; if (f) onUpload(f); e.target.value = ""; }}
            />
            <a
              data-testid="pcap-export-btn"
              href={`${API}/pcap/export`}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-900 dark:bg-slate-100 hover:bg-slate-800 dark:hover:bg-white text-white dark:text-slate-900 text-sm font-semibold shadow-sm transition-colors"
            >
              <Download size={14} /> Export
            </a>
            <button
              data-testid="sessions-open-btn"
              onClick={onOpenSessions}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-violet-600 hover:bg-violet-700 text-white text-sm font-semibold shadow-sm transition-colors"
              title="Save / replay sessions"
            >
              <Archive size={14} /> Sessions
            </button>
            <button
              data-testid="shortcuts-open-btn"
              onClick={onOpenShortcuts}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-sm font-semibold text-slate-700 dark:text-slate-200 transition-colors"
              title="Keyboard shortcuts (?)"
              aria-label="Keyboard shortcuts"
            >
              <CircleHelp size={14} />
            </button>
            <button
              data-testid="settings-open-btn"
              onClick={onOpenSettings}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-sm font-semibold text-slate-700 dark:text-slate-200 transition-colors"
              title="Settings (Ctrl / Command + comma)"
            >
              <Settings size={14} />
            </button>
          </div>

          <div className="flex-1" />

          {/* Status pills */}
          <div className="flex items-center gap-2 flex-wrap">
            <StatusPill
              testId="status-mode"
              icon={(status.running || status.mode === "replay") ? <span className="live-pulse" /> : <Radio size={12} />}
              label={status.mode === "replay" ? "REPLAY" : (status.running ? (status.mode === "live" ? "LIVE" : status.mode === "simulated" ? "SIM" : "PCAP") : "IDLE")}
              tone={(status.running || status.mode === "replay") ? "emerald" : "slate"}
            />
            <StatusPill testId="status-pps" icon={<Zap size={12} />} label={`${status.pps || 0} pps`} />
            <StatusPill testId="status-mbps" icon={<HardDrive size={12} />} label={fmtBps((status.mbps || 0) * 1_000_000)} />
            <StatusPill testId="status-health" icon={<Activity size={12} />} label={(status.capture_health?.state || "idle").toUpperCase()} tone={["degraded","error"].includes(status.capture_health?.state)?"rose":status.capture_health?.state==="warning"?"amber":status.capture_health?.state==="healthy"?"emerald":"slate"} />
            <StatusPill testId="status-threats" icon={<ShieldAlert size={12} />} label={`${status.threats || 0} alerts`} tone={status.threats ? "rose" : "slate"} />
          </div>

          {/* Theme toggle */}
          <button
            data-testid="theme-toggle-btn"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            className="p-2 rounded-md bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
            aria-label="Toggle theme"
          >
            {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
          </button>
        </div>

        {/* Filter bar */}
        <div className="flex items-center gap-2 mt-3">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              data-testid="display-filter-input"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by IP, port, protocol, text (e.g. 192.168.1.10 or 443 or dns)"
              className="w-full pl-9 pr-3 py-2 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm font-mono-code focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <select
            data-testid="protocol-filter-select"
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            className="rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm px-3 py-2 font-mono-code focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            {PROTOCOLS.map((p) => <option key={p} value={p}>{p || "All protocols"}</option>)}
          </select>
        </div>
      </div>
    </header>
  );
}

function StatusPill({ icon, label, tone = "slate", testId }) {
  const styles = {
    slate: "bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 border-slate-200 dark:border-slate-700",
    emerald: "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-500/30",
    rose: "bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-500/30",
    amber: "bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-500/30",
  };
  return (
    <span data-testid={testId} className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${styles[tone]}`}>
      {icon}
      <span className="font-mono-code">{label}</span>
    </span>
  );
}

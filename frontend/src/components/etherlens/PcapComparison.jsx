import { useMemo, useState } from "react";
import { ArrowRight, Download, FileDiff, ShieldAlert } from "lucide-react";
import { api } from "./lib";

const ACCEPT = ".pcap,.pcapng,.cap";

function formatNumber(value) {
  return Number(value || 0).toLocaleString(undefined, { maximumFractionDigits: 2 });
}

function FilePicker({ label, file, onChange }) {
  return <label className="block rounded-lg border border-dashed border-slate-300 dark:border-slate-700 p-3 cursor-pointer hover:border-blue-400">
    <span className="block text-[10px] uppercase tracking-wider text-slate-500">{label}</span>
    <span className="block text-sm font-semibold mt-1 truncate">{file?.name || "Choose PCAP / PCAPNG"}</span>
    <span className="block text-[11px] text-slate-500 mt-1">{file ? `${formatNumber(file.size)} bytes` : "Maximum 50 MB"}</span>
    <input type="file" accept={ACCEPT} hidden onChange={event => onChange(event.target.files?.[0] || null)} />
  </label>;
}

function Metric({ label, value }) {
  const delta = Number(value?.delta || 0);
  return <div className="rounded-lg bg-slate-50 dark:bg-slate-800 p-3">
    <div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
    <div className="flex items-baseline gap-2 mt-1"><span className="font-bold">{formatNumber(value?.current)}</span><span className={`text-xs font-semibold ${delta > 0 ? "text-amber-600 dark:text-amber-400" : delta < 0 ? "text-emerald-600 dark:text-emerald-400" : "text-slate-400"}`}>{delta > 0 ? "+" : ""}{formatNumber(delta)}</span></div>
    <div className="text-[10px] text-slate-400 mt-1">Baseline {formatNumber(value?.baseline)}</div>
  </div>;
}

function ChangedRows({ title, rows }) {
  const changed = (rows || []).filter(row => Number(row.delta));
  return <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-3">
    <h4 className="text-xs font-bold mb-2">{title}</h4>
    {changed.length ? <div className="space-y-1 max-h-48 overflow-auto el-scroll">{changed.slice(0, 25).map(row => <div key={row.name} className="grid grid-cols-[1fr_auto_auto] gap-3 text-xs py-1 border-b border-slate-100 dark:border-slate-800 last:border-0"><span className="truncate font-mono-code">{row.name}</span><span className="text-slate-500">{formatNumber(row.baseline)} → {formatNumber(row.current)}</span><span className={row.delta > 0 ? "text-amber-500" : "text-emerald-500"}>{row.delta > 0 ? "+" : ""}{formatNumber(row.delta)}</span></div>)}</div> : <p className="text-xs text-slate-400">No observed changes.</p>}
  </div>;
}

function EntityChanges({ title, value }) {
  return <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-3">
    <h4 className="text-xs font-bold">{title}</h4>
    <div className="mt-2 space-y-2 text-xs">
      <div><span className="text-amber-600 dark:text-amber-400 font-semibold">Added ({value?.added?.length || 0})</span><p className="text-slate-500 font-mono-code break-words mt-0.5">{value?.added?.slice(0, 20).join(", ") || "None"}</p></div>
      <div><span className="text-emerald-600 dark:text-emerald-400 font-semibold">Removed ({value?.removed?.length || 0})</span><p className="text-slate-500 font-mono-code break-words mt-0.5">{value?.removed?.slice(0, 20).join(", ") || "None"}</p></div>
    </div>
  </div>;
}

export default function PcapComparison() {
  const [baseline, setBaseline] = useState(null);
  const [current, setCurrent] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const canCompare = useMemo(() => baseline && current && !loading, [baseline, current, loading]);

  const compare = async () => {
    if (!canCompare) return;
    const form = new FormData(); form.append("baseline", baseline); form.append("current", current);
    setLoading(true); setError("");
    try { setResult((await api.post("/pcap/compare", form, { headers: { "Content-Type": "multipart/form-data" } })).data); }
    catch (exc) { setResult(null); setError(exc?.response?.data?.detail || exc.message || "Comparison failed"); }
    finally { setLoading(false); }
  };

  const download = () => {
    if (!result) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = "nscout-pcap-comparison.json"; link.click(); URL.revokeObjectURL(url);
  };

  const comparison = result?.comparison;
  return <section className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-5" data-testid="pcap-comparison">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><div className="flex items-center gap-2"><FileDiff size={18} className="text-violet-500"/><h3 className="font-display font-bold">PCAP Comparison</h3></div><p className="text-xs text-slate-500 mt-1">Compare two captures without replacing the active nScout session.</p></div>
      {result && <button onClick={download} className="inline-flex items-center gap-1.5 rounded-md bg-slate-100 dark:bg-slate-800 px-3 py-2 text-xs font-semibold"><Download size={13}/> Export comparison JSON</button>}
    </div>
    <div className="grid grid-cols-1 md:grid-cols-[1fr_auto_1fr_auto] gap-3 items-center mt-4">
      <FilePicker label="Baseline capture" file={baseline} onChange={setBaseline}/><ArrowRight className="hidden md:block text-slate-400" size={18}/><FilePicker label="Current capture" file={current} onChange={setCurrent}/><button disabled={!canCompare} onClick={compare} className="rounded-md bg-violet-600 hover:bg-violet-700 disabled:opacity-40 text-white text-xs font-semibold px-4 py-2.5">{loading ? "Comparing…" : "Compare"}</button>
    </div>
    {error && <div className="mt-3 rounded-md bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-300 px-3 py-2 text-xs">{error}</div>}
    {result && <div className="mt-5 space-y-4">
      {(result.baseline?.truncated || result.current?.truncated) && <div className="flex gap-2 rounded-md bg-amber-50 dark:bg-amber-500/10 text-amber-800 dark:text-amber-200 px-3 py-2 text-xs"><ShieldAlert size={15}/><span>At least one capture exceeded the 100,000-packet analysis bound. Results describe the analyzed prefix and include the truncation flag.</span></div>}
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-7 gap-2">{Object.entries(comparison.metrics || {}).map(([key, value]) => <Metric key={key} label={key.replaceAll("_", " ")} value={value}/>)}</div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3"><ChangedRows title="Protocol changes" rows={comparison.protocols}/><ChangedRows title="Finding changes" rows={comparison.finding_types}/><ChangedRows title="Service-port changes" rows={comparison.ports}/><ChangedRows title="TCP-health changes" rows={comparison.tcp_health}/></div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3"><EntityChanges title="Hosts" value={comparison.hosts}/><EntityChanges title="Domains" value={comparison.domains}/></div>
      <p className="text-[11px] text-slate-500">{comparison.interpretation}</p>
    </div>}
  </section>;
}

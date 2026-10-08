import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, BarChart3, Plus, RefreshCw, Trash2 } from "lucide-react";
import { api } from "./lib";

const LEVEL_STYLE = {
  high: "bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-300",
  elevated: "bg-amber-100 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300",
  low: "bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-300",
  none: "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300",
};

function displayValue(value) {
  if (typeof value === "number") return value.toLocaleString(undefined, { maximumFractionDigits: 2 });
  return String(value ?? "—");
}

export default function NetworkBaselinePanel({ capturePacketCount = 0 }) {
  const [baselines, setBaselines] = useState([]);
  const [selected, setSelected] = useState("");
  const [name, setName] = useState("");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const rows = (await api.get("/baselines")).data.baselines || [];
      setBaselines(rows);
      setSelected(current => rows.some(row => row.id === current) ? current : (rows[0]?.id || ""));
    } catch (exc) { setError(exc?.response?.data?.detail || "Could not load baselines"); }
  }, []);
  useEffect(() => { refresh(); }, [refresh]);

  const create = async () => {
    if (!name.trim() || !capturePacketCount || busy) return;
    setBusy(true); setError("");
    try {
      const created = (await api.post("/baselines", { name: name.trim() })).data.baseline;
      setName(""); setResult(null); await refresh(); setSelected(created.id);
    } catch (exc) { setError(exc?.response?.data?.detail || exc.message || "Could not save baseline"); }
    finally { setBusy(false); }
  };
  const compare = async () => {
    if (!selected || !capturePacketCount || busy) return;
    setBusy(true); setError("");
    try { setResult((await api.get(`/baselines/${encodeURIComponent(selected)}/compare`)).data); }
    catch (exc) { setResult(null); setError(exc?.response?.data?.detail || exc.message || "Could not compare baseline"); }
    finally { setBusy(false); }
  };
  const remove = async () => {
    if (!selected || busy) return;
    setBusy(true); setError("");
    try { await api.delete(`/baselines/${encodeURIComponent(selected)}`); setResult(null); await refresh(); }
    catch (exc) { setError(exc?.response?.data?.detail || exc.message || "Could not delete baseline"); }
    finally { setBusy(false); }
  };

  const comparison = result?.comparison;
  return <section data-testid="network-baselines" className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-4">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><div className="flex items-center gap-2"><BarChart3 size={18} className="text-cyan-500"/><h3 className="font-display font-bold text-sm">Network baselines</h3></div><p className="text-[11px] text-slate-500 mt-1">Save current capture metadata and compare later activity with explicit, deterministic deviation reasons.</p></div>
      <button onClick={refresh} className="rounded-md p-2 bg-slate-100 dark:bg-slate-800" title="Refresh baselines"><RefreshCw size={14}/></button>
    </div>
    <div className="grid grid-cols-1 lg:grid-cols-[minmax(220px,1fr)_auto_minmax(260px,1fr)_auto_auto] gap-2 mt-4 items-center">
      <input value={name} onChange={event => setName(event.target.value)} maxLength={160} placeholder="Baseline name, e.g. Office morning" className="rounded-md border border-slate-200 dark:border-slate-700 bg-transparent px-3 py-2 text-xs"/>
      <button onClick={create} disabled={!name.trim() || !capturePacketCount || busy} className="inline-flex justify-center items-center gap-1.5 rounded-md bg-cyan-600 hover:bg-cyan-700 disabled:opacity-40 text-white px-3 py-2 text-xs font-semibold"><Plus size={13}/> Save current</button>
      <select value={selected} onChange={event => { setSelected(event.target.value); setResult(null); }} className="rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-xs">
        {!baselines.length && <option value="">No saved baselines</option>}
        {baselines.map(row => <option key={row.id} value={row.id}>{row.name} · {Number(row.packet_count || 0).toLocaleString()} packets</option>)}
      </select>
      <button onClick={compare} disabled={!selected || !capturePacketCount || busy} className="rounded-md bg-violet-600 hover:bg-violet-700 disabled:opacity-40 text-white px-3 py-2 text-xs font-semibold">{busy ? "Working…" : "Compare current"}</button>
      <button onClick={remove} disabled={!selected || busy} title="Delete selected baseline" className="rounded-md border border-red-200 dark:border-red-500/30 text-red-600 dark:text-red-300 p-2 disabled:opacity-40"><Trash2 size={14}/></button>
    </div>
    {!capturePacketCount && <p className="mt-3 text-xs text-slate-400">Start a capture or import a PCAP before saving or comparing a baseline.</p>}
    {error && <div className="mt-3 rounded-md bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-300 px-3 py-2 text-xs">{error}</div>}
    {comparison && <div className="mt-4 space-y-3">
      <div className="flex flex-wrap gap-3 items-center rounded-lg bg-slate-50 dark:bg-slate-800 p-3">
        <span className={`rounded-full px-2.5 py-1 text-[10px] font-bold uppercase ${LEVEL_STYLE[comparison.level] || LEVEL_STYLE.low}`}>{comparison.level} deviation</span>
        <span className="font-display font-bold text-xl">{comparison.score}/100</span>
        <span className="text-xs text-slate-500">{result.baseline?.name} · {comparison.baseline_packet_count.toLocaleString()} baseline vs {comparison.current_packet_count.toLocaleString()} current packets</span>
      </div>
      {comparison.reasons.length ? <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">{comparison.reasons.map((reason, index) => <div key={`${reason.type}-${index}`} className="rounded-lg border border-slate-200 dark:border-slate-800 p-3">
        <div className="flex gap-2 items-start"><AlertTriangle size={14} className="text-amber-500 mt-0.5 shrink-0"/><div className="min-w-0"><div className="text-xs font-semibold">{reason.title}</div><div className="text-[11px] text-slate-500 mt-1">Observed {displayValue(reason.observed)} · baseline {displayValue(reason.baseline)}</div><div className="text-[10px] text-slate-400 mt-1">Rule: {reason.threshold} · +{reason.score} score</div>{reason.evidence?.added?.length > 0 && <div className="mt-2 font-mono-code text-[10px] text-slate-500 break-words">{reason.evidence.added.join(", ")}</div>}</div></div>
      </div>)}</div> : <div className="rounded-lg border border-emerald-200 dark:border-emerald-500/30 bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 p-3 text-xs">No configured deviation threshold was crossed.</div>}
      <p className="text-[11px] text-slate-500">{comparison.interpretation}</p>
    </div>}
  </section>;
}

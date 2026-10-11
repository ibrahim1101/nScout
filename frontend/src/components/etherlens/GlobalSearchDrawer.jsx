import { useEffect, useMemo, useRef, useState } from "react";
import { AlertCircle, FileSearch2, Loader2, Search, X } from "lucide-react";
import { api } from "./lib";

const LABELS = {
  packet: "Packet", host: "Host", connection: "Connection", dns: "DNS",
  finding: "Finding", timeline: "Timeline", investigation: "Investigation",
  note: "Note", evidence: "Evidence",
};

export default function GlobalSearchDrawer({ open, onClose, onOpenResult }) {
  const [query, setQuery] = useState("");
  const [data, setData] = useState({ results: [], categories: {}, count: 0, truncated: false });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const inputRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    requestAnimationFrame(() => inputRef.current?.focus());
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const normalized = query.trim();
    if (normalized.length < 2) {
      setData({ results: [], categories: {}, count: 0, truncated: false });
      setLoading(false);
      setError("");
      return undefined;
    }
    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      setLoading(true);
      setError("");
      try {
        const response = await api.get("/search", { params: { q: normalized, limit: 75 }, signal: controller.signal });
        setData(response.data);
      } catch (err) {
        if (err?.code !== "ERR_CANCELED") setError(err?.response?.data?.detail || "Search is unavailable.");
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }, 250);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [open, query]);

  const categories = useMemo(() => Object.entries(data.categories || {}), [data.categories]);
  if (!open) return null;
  const choose = (result) => { onOpenResult?.(result); onClose(); };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/55 backdrop-blur-sm p-4 sm:p-10" role="dialog" aria-modal="true" aria-label="Global investigation search" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <div className="mx-auto max-w-3xl overflow-hidden rounded-2xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 shadow-2xl">
        <div className="flex items-center gap-3 border-b border-slate-200 dark:border-slate-800 px-4">
          <Search size={18} className="shrink-0 text-blue-500" />
          <input
            ref={inputRef}
            data-testid="global-search-input"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Escape") onClose();
              if (event.key === "Enter" && data.results?.[0]) choose(data.results[0]);
            }}
            maxLength={200}
            placeholder="Search packets, hosts, DNS, findings, cases, notes and evidence…"
            className="h-14 min-w-0 flex-1 bg-transparent text-sm outline-none"
          />
          {loading && <Loader2 size={16} className="animate-spin text-slate-400" aria-label="Searching" />}
          <button onClick={onClose} className="rounded-md p-2 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800" aria-label="Close global search"><X size={17} /></button>
        </div>
        <div className="flex min-h-10 flex-wrap items-center gap-1.5 border-b border-slate-100 dark:border-slate-800 px-4 py-2 text-[11px] text-slate-500">
          {categories.length ? categories.map(([type, count]) => <span key={type} className="rounded-full bg-slate-100 dark:bg-slate-800 px-2 py-1">{LABELS[type] || type} · {count}</span>) : <span>Type at least 2 characters. Raw payload and hex data are not indexed.</span>}
          {data.truncated && <span className="ml-auto text-amber-600 dark:text-amber-300">Showing the highest-ranked matches</span>}
        </div>
        <div className="max-h-[62vh] overflow-auto el-scroll">
          {error && <div className="m-4 flex items-center gap-2 rounded-lg border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/30 p-3 text-xs text-red-600 dark:text-red-300"><AlertCircle size={15} />{error}</div>}
          {!error && query.trim().length >= 2 && !loading && !data.results?.length && <div className="p-12 text-center"><FileSearch2 size={28} className="mx-auto text-slate-400" /><div className="mt-3 text-sm font-semibold">No investigation data matched</div><p className="mt-1 text-xs text-slate-500">Try an IP, domain, port, protocol, finding, case name, or analyst note.</p></div>}
          {(data.results || []).map((result) => (
            <button key={result.id} onClick={() => choose(result)} className="flex w-full items-start gap-3 border-b border-slate-100 dark:border-slate-800 px-4 py-3 text-left hover:bg-slate-50 dark:hover:bg-slate-800 focus:bg-blue-50 dark:focus:bg-blue-950/30 focus:outline-none">
              <span className="mt-0.5 min-w-20 rounded bg-blue-50 dark:bg-blue-500/10 px-2 py-1 text-center text-[10px] font-bold uppercase text-blue-600 dark:text-blue-300">{LABELS[result.type] || result.type}</span>
              <span className="min-w-0"><span className="block truncate text-sm font-semibold">{result.title}</span><span className="mt-1 block truncate text-xs text-slate-500">{result.subtitle || "Open matching investigation data"}</span></span>
            </button>
          ))}
        </div>
        <div className="flex items-center justify-between border-t border-slate-200 dark:border-slate-800 px-4 py-2 text-[10px] text-slate-400"><span>Enter opens the first result · Esc closes</span><span>Local metadata search</span></div>
      </div>
    </div>
  );
}

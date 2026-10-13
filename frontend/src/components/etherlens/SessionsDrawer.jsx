import { useEffect, useState } from "react";
import { api } from "./lib";
import { X, Save, Play, Trash2, Clock, Package, ShieldAlert, Activity, AlertCircle, Loader2, RefreshCw } from "lucide-react";
import { describeCaptureSessionsState } from "./captureSessionsState";

export default function SessionsDrawer({ open, onClose, onLoaded, status = {} }) {
  const [sessions, setSessions] = useState([]);
  const [name, setName] = useState("");
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [actionError, setActionError] = useState("");

  const refresh = async () => {
    setLoading(true); setLoadError("");
    try {
      const r = await api.get("/sessions");
      setSessions(r.data.sessions || []);
      setLoaded(true);
      return true;
    } catch (e) {
      setLoadError(e?.response?.data?.detail || e.message || "Could not load saved sessions.");
      return false;
    } finally { setLoading(false); }
  };

  useEffect(() => { if (open) refresh(); }, [open]);

  const save = async () => {
    setSaving(true); setActionError("");
    try {
      const response = await api.post("/sessions/save", { name: name || "Untitled" });
      const saved = response.data;
      setSessions((current) => [saved, ...current.filter((row) => row.id !== saved.id)]);
      setLoaded(true);
      setName("");
      await refresh();
    } catch (e) {
      setActionError(e?.response?.data?.detail || e.message || "Could not save this session.");
    } finally { setSaving(false); }
  };

  const load = async (sid) => {
    setActionError("");
    try {
      const r = await api.post(`/sessions/${sid}/load`);
      onLoaded && onLoaded(r.data);
      onClose();
    } catch (e) {
      setActionError(e?.response?.data?.detail || e.message || "Could not replay this session.");
    }
  };

  const remove = async (sid) => {
    if (!window.confirm("Delete this saved session?")) return;
    setActionError("");
    try {
      await api.delete(`/sessions/${sid}`);
      setSessions((current) => current.filter((row) => row.id !== sid));
      await refresh();
    } catch (e) { setActionError(e?.response?.data?.detail || e.message || "Could not delete this session."); }
  };

  if (!open) return null;
  const emptyState = describeCaptureSessionsState({ loading, loaded, error: loadError, sessionCount: sessions.length });

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-end bg-slate-950/50 backdrop-blur-sm" onClick={onClose}>
      <div
        onClick={(e) => e.stopPropagation()}
        data-testid="sessions-drawer"
        className="w-full sm:w-[min(70vw,860px)] 2xl:w-[min(55vw,1120px)] min-w-0 h-[100dvh] bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-800 shadow-2xl flex flex-col"
      >
        <div className="px-5 py-3 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="font-display font-bold">Saved Sessions</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">Local snapshots — MongoDB not required</p>
          </div>
          <button data-testid="sessions-close" onClick={onClose} className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md"><X size={16} /></button>
        </div>

        <div className="px-5 py-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60">
          <div className="mb-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 p-3 text-xs">
            <div className="flex items-center justify-between gap-2"><span className="font-semibold inline-flex items-center gap-1.5"><Activity size={13}/>Current capture</span><span className="font-mono-code text-slate-500">{status.capture_id?status.capture_id.slice(0,8):"not started"}</span></div>
            <div className="mt-2 grid grid-cols-2 gap-2 text-[11px] text-slate-500"><span>Interface: <b className="text-slate-700 dark:text-slate-300">{status.interface||"none"}</b></span><span>Switches: <b className="text-slate-700 dark:text-slate-300">{status.switch_count||0}</b></span><span>Buffer: <b className="text-slate-700 dark:text-slate-300">{Number(status.total_packets||0).toLocaleString()} / {Number(status.packet_limit||0).toLocaleString()}</b></span><span>Evicted: <b className="text-slate-700 dark:text-slate-300">{Number(status.dropped_packets||0).toLocaleString()}</b></span></div>
          </div>
          <div className="flex gap-2">
            <input
              data-testid="session-name-input"
              placeholder="Name this session (e.g. Monday incident)"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="filter-control flex-1 px-3 py-2 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 text-sm font-mono-code focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button
              data-testid="session-save-btn"
              onClick={save}
              disabled={saving}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white text-sm font-semibold"
            >
              <Save size={14} /> Save current
            </button>
          </div>
          {actionError && <div className="mt-2 text-xs text-rose-600 dark:text-rose-400">{actionError}</div>}
        </div>

        <div className="flex-1 overflow-auto el-scroll divide-y divide-slate-100 dark:divide-slate-800">
          {emptyState && (
            <div className={`p-10 text-center text-sm flex flex-col items-center gap-2 ${emptyState.tone === "error" ? "text-rose-500" : emptyState.tone === "warning" ? "text-amber-500" : "text-slate-400"}`}>
              {emptyState.tone === "loading" ? <Loader2 size={28} className="animate-spin" /> : emptyState.tone === "empty" ? <Package size={28} /> : <AlertCircle size={28} />}
              <span className="font-semibold">{emptyState.title}</span>
              <span className="text-xs">{emptyState.message}</span>
              {(emptyState.tone === "error" || emptyState.tone === "warning") && <button onClick={refresh} disabled={loading} className="mt-1 inline-flex items-center gap-1 rounded-md border border-current px-2.5 py-1 text-xs font-semibold disabled:opacity-50"><RefreshCw size={12} className={loading ? "animate-spin" : ""} /> Retry</button>}
            </div>
          )}
          {sessions.map((s) => (
            <div key={s.id} data-testid={`session-row-${s.id}`} className="p-4 hover:bg-slate-50 dark:hover:bg-slate-800/40">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="font-display font-semibold text-sm truncate">{s.name}</div>
                  <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400 font-mono-code flex items-center gap-3 flex-wrap">
                    <span className="inline-flex items-center gap-1"><Clock size={11} />{new Date(s.created_at).toLocaleString()}</span>
                    <span className="inline-flex items-center gap-1"><Package size={11} />{s.packet_count.toLocaleString()} pkts</span>
                    <span className="uppercase tracking-wide text-blue-500">{s.storage || "local"}</span>
                    {s.truncated && <span className="text-amber-500">Newest {s.packet_count.toLocaleString()} of {s.source_packet_count.toLocaleString()}</span>}
                    {s.source_interface && <span>{s.source_interface}</span>}
                    {s.threat_count > 0 && <span className="inline-flex items-center gap-1 text-rose-500"><ShieldAlert size={11} />{s.threat_count} alerts</span>}
                  </div>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <button
                    data-testid={`session-load-${s.id}`}
                    onClick={() => load(s.id)}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold"
                  >
                    <Play size={11} /> Replay
                  </button>
                  <button
                    data-testid={`session-delete-${s.id}`}
                    onClick={() => remove(s.id)}
                    className="p-1.5 rounded-md hover:bg-rose-100 dark:hover:bg-rose-500/20 text-rose-500"
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

import { useEffect, useState } from "react";
import { api } from "./lib";
import { X, Save, Play, Trash2, Clock, Package, ShieldAlert } from "lucide-react";

export default function SessionsDrawer({ open, onClose, onLoaded }) {
  const [sessions, setSessions] = useState([]);
  const [name, setName] = useState("");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");

  const refresh = async () => {
    try {
      const r = await api.get("/sessions");
      setSessions(r.data.sessions || []);
    } catch (e) { /* ignore */ }
  };

  useEffect(() => { if (open) refresh(); }, [open]);

  const save = async () => {
    setSaving(true); setErr("");
    try {
      await api.post("/sessions/save", { name: name || "Untitled" });
      setName("");
      await refresh();
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    } finally { setSaving(false); }
  };

  const load = async (sid) => {
    try {
      const r = await api.post(`/sessions/${sid}/load`);
      onLoaded && onLoaded(r.data);
      onClose();
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    }
  };

  const remove = async (sid) => {
    if (!window.confirm("Delete this saved session?")) return;
    try {
      await api.delete(`/sessions/${sid}`);
      refresh();
    } catch (e) { setErr(e.message); }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-end bg-slate-950/50 backdrop-blur-sm" onClick={onClose}>
      <div
        onClick={(e) => e.stopPropagation()}
        data-testid="sessions-drawer"
        className="w-full max-w-md h-full bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-800 shadow-2xl flex flex-col"
      >
        <div className="px-5 py-3 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="font-display font-bold">Saved Sessions</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">Snapshot, archive & replay captures</p>
          </div>
          <button data-testid="sessions-close" onClick={onClose} className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md"><X size={16} /></button>
        </div>

        <div className="px-5 py-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60">
          <div className="flex gap-2">
            <input
              data-testid="session-name-input"
              placeholder="Name this session (e.g. Monday incident)"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="flex-1 px-3 py-2 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 text-sm font-mono-code focus:outline-none focus:ring-2 focus:ring-blue-500"
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
          {err && <div className="mt-2 text-xs text-rose-600 dark:text-rose-400">{err}</div>}
        </div>

        <div className="flex-1 overflow-auto el-scroll divide-y divide-slate-100 dark:divide-slate-800">
          {sessions.length === 0 && (
            <div className="p-10 text-center text-sm text-slate-400 flex flex-col items-center gap-2">
              <Package size={28} />
              <span>No sessions yet. Capture some traffic then click "Save current".</span>
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

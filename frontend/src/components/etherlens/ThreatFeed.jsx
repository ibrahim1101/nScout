import { useRef, useState } from "react";
import { api } from "./lib";
import { AlertTriangle, Shield, ShieldAlert, ShieldCheck, Sparkles, X } from "lucide-react";

const SEVERITY = {
  critical: { label: "Critical", cls: "bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-400/40", icon: ShieldAlert },
  high: { label: "High", cls: "bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-400/40", icon: AlertTriangle },
  medium: { label: "Medium", cls: "bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-400/40", icon: Shield },
  low: { label: "Low", cls: "bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-400/40", icon: ShieldCheck },
};

export default function ThreatFeed({ threats, onSelectPacket }) {
  const [filter, setFilter] = useState("all");
  const [drawerThreat, setDrawerThreat] = useState(null);

  const filtered = threats.filter((t) => filter === "all" || t.severity === filter);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <div className="lg:col-span-2 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
        <div className="px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between flex-wrap gap-2">
          <h3 className="font-display font-bold text-sm">AI Threat Feed</h3>
          <div className="flex items-center gap-1">
            {["all", "critical", "high", "medium", "low"].map((f) => (
              <button
                key={f}
                data-testid={`threat-filter-${f}`}
                onClick={() => setFilter(f)}
                className={`px-2.5 py-1 rounded-full text-xs font-semibold capitalize ${
                  filter === f ? "bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900" : "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300"
                }`}
              >{f}</button>
            ))}
          </div>
        </div>
        <div className="divide-y divide-slate-100 dark:divide-slate-800 max-h-[70vh] overflow-auto el-scroll">
          {filtered.length === 0 && (
            <div className="p-10 text-center text-sm text-slate-400 flex flex-col items-center gap-2">
              <ShieldCheck size={28} className="text-emerald-500" />
              <span>No anomalies detected. Your network looks clean.</span>
            </div>
          )}
          {filtered.map((t) => {
            const sev = SEVERITY[t.severity] || SEVERITY.low;
            const Icon = sev.icon;
            return (
              <div key={t.id} data-testid={`threat-${t.id}`} className="p-4 flex items-start gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/40">
                <div className={`shrink-0 w-8 h-8 rounded-full border flex items-center justify-center ${sev.cls}`}>
                  <Icon size={16} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border ${sev.cls}`}>{sev.label}</span>
                    <span className="font-display font-semibold text-sm truncate">{t.title}</span>
                  </div>
                  <div className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">{t.description}</div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-500 mt-1 font-mono-code">
                    {t.src || "?"} → {t.dst || "?"} · {t.type}
                  </div>
                </div>
                <div className="flex flex-col gap-1 shrink-0">
                  <button
                    data-testid={`threat-explain-${t.id}`}
                    onClick={() => setDrawerThreat(t)}
                    className="inline-flex items-center gap-1 text-xs px-2 py-1 rounded-md bg-indigo-600 hover:bg-indigo-700 text-white font-semibold"
                  >
                    <Sparkles size={11} /> AI
                  </button>
                  {t.packet_id && (
                    <button
                      data-testid={`threat-view-packet-${t.id}`}
                      onClick={() => onSelectPacket(t.packet_id)}
                      className="text-xs px-2 py-1 rounded-md bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-semibold"
                    >packet</button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <aside className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden flex flex-col">
        <div className="px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <h3 className="font-display font-bold text-sm">AI Explanation</h3>
          {drawerThreat && <button data-testid="ai-drawer-close" onClick={() => setDrawerThreat(null)} className="text-slate-400 hover:text-slate-900 dark:hover:text-slate-200"><X size={16} /></button>}
        </div>
        <ThreatExplainer threat={drawerThreat} />
      </aside>
    </div>
  );
}

function ThreatExplainer({ threat }) {
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const ran = useRef("");

  if (!threat) {
    return <div className="p-6 text-sm text-slate-400 dark:text-slate-500">Select a threat and click <span className="font-semibold text-indigo-500">AI</span> to get a plain-English explanation with recommended actions.</div>;
  }

  if (ran.current !== threat.id) {
    ran.current = threat.id;
    setText("");
    setLoading(true);
    (async () => {
      try {
        const resp = await fetch(`${api.defaults.baseURL}/ai/explain`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ threat_id: threat.id }),
        });
        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buf = "";
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          let idx;
          while ((idx = buf.indexOf("\n\n")) !== -1) {
            const chunk = buf.slice(0, idx); buf = buf.slice(idx + 2);
            if (!chunk.startsWith("data:")) continue;
            const payload = chunk.slice(5).trim();
            if (payload === "[DONE]") break;
            try { const o = JSON.parse(payload); if (o.delta) setText((t) => t + o.delta); } catch (_err) { /* ignore */ }
          }
        }
      } catch (e) {
        setText(`AI error: ${e.message}`);
      } finally { setLoading(false); }
    })();
  }

  return (
    <div className="flex-1 p-4 overflow-auto el-scroll" data-testid="threat-ai-explanation">
      <div className="mb-2 text-xs text-slate-500 font-mono-code">{threat.type}</div>
      <div className="font-display font-semibold">{threat.title}</div>
      <div className="mt-3 text-sm whitespace-pre-wrap leading-relaxed text-slate-800 dark:text-slate-200">
        {text || (loading ? "Analyzing with nScout AI…" : "")}
      </div>
    </div>
  );
}

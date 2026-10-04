import { useEffect, useState } from "react";
import { api } from "./lib";
import { X, ArrowRight, ArrowLeft } from "lucide-react";

export default function FlowDrawer({ open, onClose, flow }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open || !flow) { setData(null); return; }
    setLoading(true);
    api.get("/flow/stream", { params: { a_ip: flow.a_ip, a_port: flow.a_port, b_ip: flow.b_ip, b_port: flow.b_port } })
      .then((r) => setData(r.data))
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  }, [open, flow]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 backdrop-blur-sm" onClick={onClose}>
      <div
        onClick={(e) => e.stopPropagation()}
        data-testid="follow-flow-drawer"
        className="w-full max-w-4xl max-h-[85vh] bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-2xl flex flex-col overflow-hidden"
      >
        <div className="px-5 py-3 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="font-display font-bold text-sm">Follow TCP Stream</h3>
            {flow && (
              <div className="font-mono-code text-xs text-slate-500 mt-0.5">
                {flow.a_ip}:{flow.a_port} ↔ {flow.b_ip}:{flow.b_port}
                <span className="ml-2 text-slate-400">· {flow.protocols?.join("/")} · {flow.packets} pkts</span>
              </div>
            )}
          </div>
          <button data-testid="flow-drawer-close" onClick={onClose} className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md">
            <X size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-auto el-scroll p-4 space-y-4">
          {loading && <div className="text-sm text-slate-400">Reassembling stream…</div>}
          {!loading && data && (
            <>
              <StreamPane
                testId="stream-a-to-b"
                title={<>Client <ArrowRight size={12} className="inline mx-1" /> Server</>}
                subtitle={`${data.flow.a.ip}:${data.flow.a.port} → ${data.flow.b.ip}:${data.flow.b.port}`}
                stream={data.a_to_b}
                tone="blue"
              />
              <StreamPane
                testId="stream-b-to-a"
                title={<>Server <ArrowLeft size={12} className="inline mx-1" /> Client</>}
                subtitle={`${data.flow.b.ip}:${data.flow.b.port} → ${data.flow.a.ip}:${data.flow.a.port}`}
                stream={data.b_to_a}
                tone="emerald"
              />
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function StreamPane({ title, subtitle, stream, tone, testId }) {
  const toneCls = tone === "blue"
    ? "border-blue-200 dark:border-blue-500/30 bg-blue-50/40 dark:bg-blue-500/5"
    : "border-emerald-200 dark:border-emerald-500/30 bg-emerald-50/40 dark:bg-emerald-500/5";
  return (
    <div className={`rounded-lg border ${toneCls}`} data-testid={testId}>
      <div className="px-3 py-2 flex items-center justify-between text-xs font-semibold text-slate-700 dark:text-slate-200">
        <div>{title}</div>
        <div className="font-mono-code text-slate-500">{stream.packets} pkts · {stream.bytes} bytes · {stream.mode}</div>
      </div>
      <div className="text-xs font-mono-code text-slate-500 px-3 pb-1">{subtitle}</div>
      <pre className="px-3 pb-3 pt-1 font-mono-code text-[11.5px] leading-snug whitespace-pre-wrap break-all text-slate-800 dark:text-slate-200 max-h-56 overflow-auto el-scroll">
        {stream.data || <span className="text-slate-400 italic">(empty / no application-layer payload)</span>}
      </pre>
    </div>
  );
}

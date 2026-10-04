import { useEffect, useRef, useState } from "react";
import { api } from "./lib";
import { ChevronRight, ChevronDown, Sparkles, Copy } from "lucide-react";

export default function PacketAnalyzer({ packets, selected, setSelected, status, onFollowFlow }) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
      <div className="lg:col-span-7 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden flex flex-col" style={{ height: "calc(100vh - 260px)" }}>
        <div className="px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <h3 className="font-display font-bold text-sm">Packet Stream</h3>
          <div className="flex items-center gap-2">
            {selected && ["TCP", "HTTP", "HTTPS", "SSH", "TLS", "FTP", "SMTP"].includes(selected.protocol) && selected.src_port && selected.dst_port && (
              <button
                data-testid="follow-flow-btn"
                onClick={() => {
                  const [a_ip, a_port, b_ip, b_port] = (selected.src_ip < selected.dst_ip || (selected.src_ip === selected.dst_ip && selected.src_port < selected.dst_port))
                    ? [selected.src_ip, selected.src_port, selected.dst_ip, selected.dst_port]
                    : [selected.dst_ip, selected.dst_port, selected.src_ip, selected.src_port];
                  onFollowFlow && onFollowFlow({ a_ip, a_port, b_ip, b_port, protocols: [selected.protocol], packets: 0 });
                }}
                className="text-xs px-2 py-1 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-semibold"
              >
                Follow flow
              </button>
            )}
            <span className="text-xs text-slate-500 dark:text-slate-400 font-mono-code">{packets.length} packets</span>
          </div>
        </div>
        <PacketTable packets={packets} selected={selected} onSelect={setSelected} />
      </div>

      <div className="lg:col-span-5 flex flex-col gap-4" style={{ maxHeight: "calc(100vh - 260px)" }}>
        <ProtocolTree packet={selected} />
        <HexDump packet={selected} />
        <AIExplain packet={selected} />
      </div>
    </div>
  );
}

function PacketTable({ packets, selected, onSelect }) {
  return (
    <div className="flex-1 overflow-auto el-scroll">
      <table className="w-full text-xs">
        <thead className="sticky top-0 bg-slate-50 dark:bg-slate-800/70 backdrop-blur-sm z-10">
          <tr className="text-left text-slate-500 dark:text-slate-400 uppercase tracking-wider text-[10px]">
            <th className="px-3 py-2 font-semibold">#</th>
            <th className="px-3 py-2 font-semibold">Time</th>
            <th className="px-3 py-2 font-semibold">Source</th>
            <th className="px-3 py-2 font-semibold">Destination</th>
            <th className="px-3 py-2 font-semibold">Proto</th>
            <th className="px-3 py-2 font-semibold text-right">Len</th>
            <th className="px-3 py-2 font-semibold">Info</th>
          </tr>
        </thead>
        <tbody className="font-mono-code">
          {packets.length === 0 && (
            <tr><td colSpan={7} className="text-center text-slate-400 dark:text-slate-500 py-12 text-sm">No packets yet. Click <span className="font-semibold text-emerald-600">Start</span> or upload a PCAP file.</td></tr>
          )}
          {packets.map((p) => (
            <tr
              key={p.id}
              data-testid={`packet-row-${p.number}`}
              onClick={() => onSelect(p)}
              className={`row-hover border-t border-slate-100 dark:border-slate-800 cursor-pointer ${selected?.id === p.id ? "bg-blue-50 dark:bg-blue-500/10" : ""}`}
            >
              <td className="px-3 py-1.5 text-slate-400 dark:text-slate-500">{p.number}</td>
              <td className="px-3 py-1.5 whitespace-nowrap">{p.time_str}</td>
              <td className="px-3 py-1.5 whitespace-nowrap">
                {p.src_ip}{p.src_port ? <span className="text-slate-400">:{p.src_port}</span> : null}
              </td>
              <td className="px-3 py-1.5 whitespace-nowrap">
                {p.dst_ip}{p.dst_port ? <span className="text-slate-400">:{p.dst_port}</span> : null}
              </td>
              <td className="px-3 py-1.5"><span className={`proto-badge proto-${p.protocol}`}>{p.protocol}</span></td>
              <td className="px-3 py-1.5 text-right text-slate-500">{p.length}</td>
              <td className="px-3 py-1.5 truncate max-w-[260px] text-slate-700 dark:text-slate-300">{p.info}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ProtocolTree({ packet }) {
  const [detail, setDetail] = useState(null);
  const [open, setOpen] = useState({});

  useEffect(() => {
    if (!packet) { setDetail(null); return; }
    api.get(`/packets/${packet.id}`).then((r) => {
      setDetail(r.data);
      const initial = {};
      (r.data.layers || []).forEach((_, i) => (initial[i] = true));
      setOpen(initial);
    }).catch(() => setDetail(packet));
  }, [packet?.id]);

  if (!packet) return <EmptyBlock title="Protocol Decode" message="Select a packet to view its layered decode" />;
  const d = detail || packet;

  return (
    <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden flex flex-col" data-testid="protocol-tree">
      <div className="px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
        <h3 className="font-display font-bold text-sm">Protocol Decode</h3>
        <span className="font-mono-code text-xs text-slate-400">#{d.number}</span>
      </div>
      <div className="flex-1 overflow-auto el-scroll p-3 space-y-1">
        {(d.layers || []).map((layer, i) => (
          <div key={i} className="rounded-md border border-slate-100 dark:border-slate-800">
            <button
              data-testid={`protocol-tree-item-${i}`}
              onClick={() => setOpen((o) => ({ ...o, [i]: !o[i] }))}
              className="w-full flex items-center gap-1.5 px-2.5 py-1.5 text-left hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md"
            >
              {open[i] ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              <span className="font-display font-semibold text-xs">{layer.name}</span>
            </button>
            {open[i] && (
              <div className="px-6 pb-2 pt-1 font-mono-code text-[11px] space-y-0.5">
                {Object.entries(layer.fields || {}).map(([k, v]) => (
                  <div key={k} className="flex gap-2">
                    <span className="text-slate-500 dark:text-slate-400 min-w-[120px]">{k}:</span>
                    <span className="text-slate-800 dark:text-slate-200 break-all">{String(v)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function HexDump({ packet }) {
  const [detail, setDetail] = useState(null);
  useEffect(() => {
    if (!packet) { setDetail(null); return; }
    api.get(`/packets/${packet.id}`).then((r) => setDetail(r.data)).catch(() => setDetail(packet));
  }, [packet?.id]);

  if (!packet) return null;
  const hex = (detail?.hex) || packet.hex || "";
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) bytes.push(hex.slice(i, i + 2));
  const rows = [];
  for (let i = 0; i < bytes.length; i += 16) rows.push(bytes.slice(i, i + 16));

  return (
    <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden flex flex-col" data-testid="hex-dump-panel" style={{ maxHeight: "260px" }}>
      <div className="px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
        <h3 className="font-display font-bold text-sm">Hex &amp; ASCII</h3>
        <button
          data-testid="hex-copy-btn"
          onClick={() => navigator.clipboard?.writeText(hex)}
          className="inline-flex items-center gap-1 text-xs text-slate-500 hover:text-slate-900 dark:hover:text-slate-200"
        >
          <Copy size={12} /> copy
        </button>
      </div>
      <div className="flex-1 overflow-auto el-scroll p-3 hex-dump">
        {rows.map((row, i) => {
          const offset = (i * 16).toString(16).padStart(4, "0");
          const ascii = row.map((b) => {
            const c = parseInt(b, 16);
            return c >= 32 && c <= 126 ? String.fromCharCode(c) : ".";
          }).join("");
          return (
            <div key={i} className="flex gap-4 whitespace-pre">
              <span className="offset">{offset}</span>
              <span className="flex-1">{row.map((b, j) => <span key={j} className="byte">{b} </span>)}</span>
              <span className="text-slate-500 dark:text-slate-400">{ascii}</span>
            </div>
          );
        })}
        {rows.length === 0 && <div className="text-slate-400 text-sm">(no payload)</div>}
      </div>
    </div>
  );
}

function AIExplain({ packet }) {
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const abortRef = useRef(null);

  useEffect(() => { setText(""); }, [packet?.id]);

  const explain = async () => {
    if (!packet) return;
    setText("");
    setLoading(true);
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    try {
      const resp = await fetch(`${api.defaults.baseURL}/ai/explain`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ packet_id: packet.id }),
        signal: ctrl.signal,
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
          const chunk = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          if (!chunk.startsWith("data:")) continue;
          const payload = chunk.slice(5).trim();
          if (payload === "[DONE]") break;
          try {
            const o = JSON.parse(payload);
            if (o.delta) setText((t) => t + o.delta);
          } catch (_err) { /* ignore */ }
        }
      }
    } catch (e) {
      if (e.name !== "AbortError") setText((t) => t + `\n[error: ${e.message}]`);
    } finally {
      setLoading(false);
    }
  };

  if (!packet) return null;
  return (
    <div className="bg-gradient-to-br from-indigo-50 to-white dark:from-indigo-500/10 dark:to-slate-900 rounded-xl border border-indigo-200 dark:border-indigo-500/30 overflow-hidden">
      <div className="px-4 py-2.5 border-b border-indigo-200 dark:border-indigo-500/30 flex items-center justify-between">
        <h3 className="font-display font-bold text-sm flex items-center gap-1.5"><Sparkles size={14} className="text-indigo-500" /> AI Explain</h3>
        <button
          data-testid="ai-explain-packet-btn"
          onClick={explain}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-400 text-white text-xs font-semibold"
        >
          <Sparkles size={12} /> {loading ? "Analyzing…" : "Explain this packet"}
        </button>
      </div>
      <div data-testid="ai-explain-output" className="p-3 text-sm leading-relaxed whitespace-pre-wrap min-h-[80px] max-h-[220px] overflow-auto el-scroll text-slate-800 dark:text-slate-200">
        {text || <span className="text-slate-400 dark:text-slate-500">Click “Explain this packet” for a plain-English analysis.</span>}
      </div>
    </div>
  );
}

function EmptyBlock({ title, message }) {
  return (
    <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 text-center">
      <h3 className="font-display font-bold text-sm">{title}</h3>
      <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{message}</p>
    </div>
  );
}

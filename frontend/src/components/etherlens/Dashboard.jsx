import { useEffect, useRef, useState, useCallback } from "react";
import { api, wsUrl } from "./lib";
import HeaderNav from "./HeaderNav";
import PacketAnalyzer from "./PacketAnalyzer";
import AnalyticsDashboard from "./AnalyticsDashboard";
import TopologyMap from "./TopologyMap";
import ThreatFeed from "./ThreatFeed";
import FlowDrawer from "./FlowDrawer";
import SettingsDrawer from "./SettingsDrawer";
import SessionsDrawer from "./SessionsDrawer";
import { Activity, Network, ShieldAlert, LayoutDashboard, GitBranch } from "lucide-react";

const TABS = [
  { id: "analyzer", label: "Packet Analyzer", icon: Activity },
  { id: "analytics", label: "Analytics", icon: LayoutDashboard },
  { id: "flows", label: "Flows", icon: GitBranch },
  { id: "topology", label: "Topology", icon: Network },
  { id: "threats", label: "AI Threats", icon: ShieldAlert },
];

export default function Dashboard({ theme, setTheme }) {
  const [tab, setTab] = useState("analyzer");
  const [status, setStatus] = useState({ running: false, mode: "idle", total_packets: 0, pps: 0, mbps: 0, threats: 0, protocol_counts: {} });
  const [interfaces, setInterfaces] = useState([]);
  const [iface, setIface] = useState("simulated");
  const [filter, setFilter] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("");
  const [packets, setPackets] = useState([]);
  const [threats, setThreats] = useState([]);
  const [selected, setSelected] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [topTalkers, setTopTalkers] = useState([]);
  const [topology, setTopology] = useState({ nodes: [], edges: [] });
  const [flows, setFlows] = useState([]);
  const [activeFlow, setActiveFlow] = useState(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [sessionsOpen, setSessionsOpen] = useState(false);
  const [notice, setNotice] = useState("");
  const wsRef = useRef(null);
  const bufferRef = useRef([]);

  // Load interfaces
  useEffect(() => {
    api.get("/interfaces").then((r) => setInterfaces(r.data.interfaces || [])).catch(() => {});
  }, []);

  // WebSocket live stream (threats + stats; packets come via REST polling for robustness)
  useEffect(() => {
    const ws = new WebSocket(wsUrl());
    wsRef.current = ws;
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === "threat") {
          setThreats((prev) => [msg.data, ...prev].slice(0, 200));
        } else if (msg.type === "stats") {
          setStatus(msg.data);
        } else if (msg.type === "notice") {
          setNotice(msg.data.message);
          setTimeout(() => setNotice(""), 6000);
        }
      } catch (_err) { /* ignore malformed */ }
    };
    ws.onclose = () => (wsRef.current = null);
    return () => ws.close();
  }, []);

  // (removed WS packet buffer flushing – REST polling below drives packet list)

  // Periodic analytics + packets refresh (also serves as WS fallback)
  useEffect(() => {
    const refresh = async () => {
      try {
        const [tl, tt, topo, th, pk, st, fl] = await Promise.all([
          api.get("/stats/timeline"),
          api.get("/stats/top-talkers?limit=10"),
          api.get("/topology?enrich=true"),
          api.get("/threats"),
          api.get("/packets?limit=800"),
          api.get("/capture/status"),
          api.get("/flows?limit=50"),
        ]);
        setTimeline(tl.data.series || []);
        setTopTalkers(tt.data.talkers || []);
        setTopology(topo.data || { nodes: [], edges: [] });
        setThreats(th.data.threats || []);
        setPackets(pk.data.packets || []);
        setStatus(st.data || {});
        setFlows(fl.data.flows || []);
      } catch (_err) { /* ignore refresh errors */ }
    };
    refresh();
    const id = setInterval(refresh, 1200);
    return () => clearInterval(id);
  }, []);

  const startCapture = useCallback(async () => {
    setPackets([]); setThreats([]); setSelected(null); setTimeline([]);
    try {
      await api.post("/capture/start", { interface: iface });
    } catch (e) { setNotice("Failed to start capture"); setTimeout(() => setNotice(""), 4000); }
  }, [iface]);

  const stopCapture = useCallback(async () => {
    try { await api.post("/capture/stop"); } catch (_err) { /* ignore */ }
  }, []);

  const clearCapture = useCallback(async () => {
    setPackets([]); setThreats([]); setSelected(null);
    await api.post("/capture/clear");
  }, []);

  const uploadPcap = useCallback(async (file) => {
    const fd = new FormData();
    fd.append("file", file);
    try {
      await api.post("/pcap/upload", fd, { headers: { "Content-Type": "multipart/form-data" } });
      const r = await api.get("/packets?limit=1000");
      setPackets(r.data.packets || []);
      setNotice(`Loaded ${file.name}`);
      setTimeout(() => setNotice(""), 4000);
    } catch (e) {
      setNotice(`PCAP parse failed: ${e?.response?.data?.detail || e.message}`);
      setTimeout(() => setNotice(""), 6000);
    }
  }, []);

  // Filtered packet list
  const filtered = packets.filter((p) => {
    if (protocolFilter && p.protocol !== protocolFilter) return false;
    if (!filter) return true;
    const q = filter.toLowerCase();
    return (
      String(p.src_ip || "").toLowerCase().includes(q) ||
      String(p.dst_ip || "").toLowerCase().includes(q) ||
      String(p.protocol || "").toLowerCase().includes(q) ||
      String(p.info || "").toLowerCase().includes(q) ||
      String(p.src_port || "").includes(q) ||
      String(p.dst_port || "").includes(q)
    );
  });

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#090D16] text-slate-900 dark:text-slate-100">
      <HeaderNav
        theme={theme}
        setTheme={setTheme}
        interfaces={interfaces}
        iface={iface}
        setIface={setIface}
        status={status}
        onStart={startCapture}
        onStop={stopCapture}
        onClear={clearCapture}
        onUpload={uploadPcap}
        filter={filter}
        setFilter={setFilter}
        protocolFilter={protocolFilter}
        setProtocolFilter={setProtocolFilter}
        onOpenSettings={() => setSettingsOpen(true)}
        onOpenSessions={() => setSessionsOpen(true)}
      />

      {notice && (
        <div
          data-testid="toast-notice"
          className="mx-auto max-w-[1700px] px-4 sm:px-6 lg:px-8 mt-3"
        >
          <div className="rounded-lg border border-amber-200 dark:border-amber-500/30 bg-amber-50 dark:bg-amber-500/10 text-amber-900 dark:text-amber-200 px-4 py-2 text-sm">
            {notice}
          </div>
        </div>
      )}

      <nav className="mx-auto max-w-[1700px] px-4 sm:px-6 lg:px-8 mt-4">
        <div className="flex gap-1 border-b border-slate-200 dark:border-slate-800">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              data-testid={`tab-${id}`}
              onClick={() => setTab(id)}
              className={`relative flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors ${
                tab === id
                  ? "text-blue-600 dark:text-blue-400"
                  : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200"
              }`}
            >
              <Icon size={16} />
              {label}
              {tab === id && <span className="absolute bottom-[-1px] left-2 right-2 h-0.5 bg-blue-600 dark:bg-blue-400 rounded-full" />}
              {id === "threats" && threats.length > 0 && (
                <span className="ml-1 inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 rounded-full text-[10px] font-bold bg-red-500 text-white">{threats.length}</span>
              )}
            </button>
          ))}
        </div>
      </nav>

      <main className="mx-auto max-w-[1700px] px-4 sm:px-6 lg:px-8 py-4">
        {tab === "analyzer" && (
          <PacketAnalyzer packets={filtered} selected={selected} setSelected={setSelected} status={status} onFollowFlow={(f) => setActiveFlow(f)} />
        )}
        {tab === "analytics" && (
          <AnalyticsDashboard status={status} timeline={timeline} topTalkers={topTalkers} />
        )}
        {tab === "flows" && (
          <FlowsTab flows={flows} onOpen={(f) => setActiveFlow(f)} />
        )}
        {tab === "topology" && (
          <TopologyMap topology={topology} />
        )}
        {tab === "threats" && (
          <ThreatFeed threats={threats} onSelectPacket={(pid) => {
            const p = packets.find((x) => x.id === pid);
            if (p) { setSelected(p); setTab("analyzer"); }
          }} />
        )}
      </main>

      <FlowDrawer open={!!activeFlow} onClose={() => setActiveFlow(null)} flow={activeFlow} />
      <SettingsDrawer open={settingsOpen} onClose={() => setSettingsOpen(false)} />
      <SessionsDrawer
        open={sessionsOpen}
        onClose={() => setSessionsOpen(false)}
        onLoaded={(info) => {
          setNotice(`Loaded "${info.name}" — ${info.packet_count} packets`);
          setTimeout(() => setNotice(""), 5000);
        }}
      />
    </div>
  );
}

function FlowsTab({ flows, onOpen }) {
  return (
    <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
      <div className="px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
        <h3 className="font-display font-bold text-sm">TCP Conversations</h3>
        <span className="text-xs text-slate-500 dark:text-slate-400 font-mono-code">{flows.length} flows</span>
      </div>
      <div className="overflow-auto el-scroll">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-slate-500 dark:text-slate-400 text-xs uppercase tracking-wider border-b border-slate-100 dark:border-slate-800">
              <th className="px-4 py-2 font-semibold">Endpoint A</th>
              <th className="px-4 py-2 font-semibold">Endpoint B</th>
              <th className="px-4 py-2 font-semibold">Protocols</th>
              <th className="px-4 py-2 font-semibold text-right">Packets</th>
              <th className="px-4 py-2 font-semibold text-right">Bytes</th>
              <th className="px-4 py-2"></th>
            </tr>
          </thead>
          <tbody className="font-mono-code">
            {flows.length === 0 && (
              <tr><td colSpan={6} className="py-10 text-center text-slate-400">No TCP flows captured yet</td></tr>
            )}
            {flows.map((f, i) => (
              <tr key={i} data-testid={`flow-row-${i}`} className="row-hover border-t border-slate-100 dark:border-slate-800">
                <td className="px-4 py-2">{f.a_ip}:<span className="text-slate-400">{f.a_port}</span></td>
                <td className="px-4 py-2">{f.b_ip}:<span className="text-slate-400">{f.b_port}</span></td>
                <td className="px-4 py-2">
                  {(f.protocols || []).map((p) => <span key={p} className={`proto-badge proto-${p} mr-1`}>{p}</span>)}
                </td>
                <td className="px-4 py-2 text-right">{f.packets.toLocaleString()}</td>
                <td className="px-4 py-2 text-right">{(f.bytes || 0).toLocaleString()} B</td>
                <td className="px-4 py-2 text-right">
                  <button
                    data-testid={`flow-follow-btn-${i}`}
                    onClick={() => onOpen(f)}
                    className="text-xs px-2.5 py-1 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-semibold"
                  >Follow</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

import { useEffect, useState } from "react";
import { api } from "./lib";
import { Network, Monitor, Globe2, ShieldAlert, Search, FileDown, RefreshCw } from "lucide-react";

const PANELS = [
  { id: "connections", label: "Connections", icon: Network },
  { id: "devices", label: "Devices", icon: Monitor },
  { id: "dns", label: "DNS", icon: Globe2 },
  { id: "security", label: "Security", icon: ShieldAlert },
];

export default function IntelligenceWorkspace({ threats = [], onSelectPacket }) {
  const [panel, setPanel] = useState("connections");
  const [data, setData] = useState({ connections: [], devices: [], dns: {}, dashboard: {}, summary: {} });
  const [expression, setExpression] = useState("");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);

  const refresh = async () => {
    setLoading(true);
    try {
      const [connections, devices, dns, dashboard, summary] = await Promise.all([
        api.get("/intelligence/connections?limit=500"),
        api.get("/intelligence/devices"),
        api.get("/intelligence/dns"),
        api.get("/intelligence/dashboard"),
        api.get("/investigation/summary"),
      ]);
      setData({
        connections: connections.data.connections || [],
        devices: devices.data.devices || [],
        dns: dns.data || {},
        dashboard: dashboard.data || {},
        summary: summary.data || {},
      });
    } finally { setLoading(false); }
  };

  useEffect(() => { refresh(); const id = setInterval(refresh, 3000); return () => clearInterval(id); }, []);

  const search = async (e) => {
    e.preventDefault();
    if (!expression.trim()) { setResults([]); return; }
    try { const r = await api.get("/packets/search", { params: { expression, limit: 500 } }); setResults(r.data.packets || []); } catch (_) { setResults([]); }
  };

  return <div className="space-y-4">
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      <Metric label="Connections" value={data.connections.length} />
      <Metric label="Devices" value={data.devices.length} />
      <Metric label="DNS Events" value={(data.dns.events || []).length} />
      <Metric label="Security Findings" value={threats.length} danger={threats.length > 0} />
    </div>

    <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
      <div className="p-3 border-b border-slate-200 dark:border-slate-800 flex flex-wrap gap-2 items-center justify-between">
        <div className="flex gap-1">{PANELS.map(({id,label,icon:Icon}) => <button key={id} onClick={()=>setPanel(id)} className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold ${panel===id?"bg-blue-600 text-white":"bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300"}`}><Icon size={13}/>{label}</button>)}</div>
        <button onClick={refresh} className="inline-flex items-center gap-1 text-xs text-slate-500"><RefreshCw size={13} className={loading?"animate-spin":""}/> refresh</button>
      </div>
      {panel === "connections" && <Connections rows={data.connections}/>} 
      {panel === "devices" && <Devices rows={data.devices}/>} 
      {panel === "dns" && <DNS data={data.dns}/>} 
      {panel === "security" && <Security rows={threats} onSelectPacket={onSelectPacket}/>} 
    </div>

    <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
      <div className="xl:col-span-2 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-4">
        <div className="flex items-center gap-2 mb-3"><Search size={15}/><h3 className="font-display font-bold text-sm">Smart Packet Search</h3></div>
        <form onSubmit={search} className="flex gap-2"><input value={expression} onChange={e=>setExpression(e.target.value)} placeholder="tcp.reset   port:443   dns.query:example.com   bytes>1000" className="flex-1 rounded-md border border-slate-200 dark:border-slate-700 bg-transparent px-3 py-2 text-xs font-mono-code"/><button className="px-3 py-2 rounded-md bg-blue-600 text-white text-xs font-semibold">Search</button></form>
        <div className="mt-3 max-h-48 overflow-auto el-scroll text-xs font-mono-code">{results.map(p=><button key={p.id} onClick={()=>onSelectPacket?.(p)} className="w-full text-left px-2 py-1.5 border-t border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800"><span className="text-slate-400 mr-2">#{p.number}</span>{p.src_ip} → {p.dst_ip} <span className="ml-2 text-blue-500">{p.protocol}</span> <span className="ml-2 text-slate-500">{p.info}</span></button>)}{expression && !results.length && <div className="text-slate-400 py-3">No matching packets.</div>}</div>
      </div>
      <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-4">
        <div className="flex items-center gap-2"><FileDown size={15}/><h3 className="font-display font-bold text-sm">Investigation Reports</h3></div>
        <p className="text-xs text-slate-500 mt-2">Export the current investigation with protocol, connection and security findings.</p>
        <div className="flex gap-2 mt-4"><a href={`${api.defaults.baseURL}/investigation/report.html`} className="px-3 py-2 rounded-md bg-slate-900 dark:bg-slate-700 text-white text-xs font-semibold">HTML</a><a href={`${api.defaults.baseURL}/investigation/report.json`} className="px-3 py-2 rounded-md bg-slate-100 dark:bg-slate-800 text-xs font-semibold">JSON</a></div>
      </div>
    </div>
  </div>;
}

function Metric({label,value,danger}) { return <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-4"><div className="text-[11px] uppercase tracking-wider text-slate-500">{label}</div><div className={`mt-1 text-2xl font-bold ${danger?"text-red-500":""}`}>{Number(value||0).toLocaleString()}</div></div>; }
function Table({headers,children,empty}) { return <div className="overflow-auto el-scroll"><table className="w-full text-xs"><thead><tr className="text-left text-slate-500 border-b border-slate-100 dark:border-slate-800">{headers.map(h=><th key={h} className="px-4 py-2">{h}</th>)}</tr></thead><tbody>{children}</tbody></table>{empty&&<div className="p-8 text-center text-slate-400 text-sm">No data yet.</div>}</div>; }
function Connections({rows}) { return <Table headers={["Endpoint A","Endpoint B","State","Packets","Bytes","Retrans","Resets"]} empty={!rows.length}>{rows.map((r,i)=><tr key={i} className="border-t border-slate-100 dark:border-slate-800 font-mono-code"><td className="px-4 py-2">{r.a_ip}:{r.a_port}</td><td className="px-4 py-2">{r.b_ip}:{r.b_port}</td><td className="px-4 py-2">{r.state}</td><td className="px-4 py-2">{r.packet_count ?? r.packets}</td><td className="px-4 py-2">{r.bytes ?? r.total_bytes}</td><td className="px-4 py-2">{r.retransmissions||0}</td><td className="px-4 py-2">{r.resets||0}</td></tr>)}</Table>; }
function Devices({rows}) { return <Table headers={["IP","MAC","Hostname","Packets","Bytes","Protocols","Last Seen"]} empty={!rows.length}>{rows.map((r,i)=><tr key={i} className="border-t border-slate-100 dark:border-slate-800"><td className="px-4 py-2 font-mono-code">{r.ip}</td><td className="px-4 py-2 font-mono-code">{r.mac||"—"}</td><td className="px-4 py-2">{r.hostname||"—"}</td><td className="px-4 py-2">{r.packets||0}</td><td className="px-4 py-2">{r.bytes||0}</td><td className="px-4 py-2">{(r.protocols||[]).join(", ")}</td><td className="px-4 py-2 font-mono-code">{r.last_seen||"—"}</td></tr>)}</Table>; }
function DNS({data}) { const rows=data.events||[]; return <Table headers={["Time","Type","Domain","Result","RCODE","TTL"]} empty={!rows.length}>{rows.map((r,i)=><tr key={i} className="border-t border-slate-100 dark:border-slate-800"><td className="px-4 py-2 font-mono-code">{r.time_str||r.timestamp||"—"}</td><td className="px-4 py-2">{r.type||r.event||"DNS"}</td><td className="px-4 py-2 font-mono-code">{r.domain||r.query||"—"}</td><td className="px-4 py-2 font-mono-code">{(r.resolved_ips||r.answers||[]).join?.(", ") || r.answer || "—"}</td><td className="px-4 py-2">{r.rcode_name||r.rcode||"—"}</td><td className="px-4 py-2">{r.ttl??"—"}</td></tr>)}</Table>; }
function Security({rows,onSelectPacket}) { return <Table headers={["Severity","Finding","Source","Destination","Details"]} empty={!rows.length}>{rows.map((r,i)=><tr key={r.id||i} onClick={()=>r.packet_id&&onSelectPacket?.({id:r.packet_id})} className="border-t border-slate-100 dark:border-slate-800 cursor-pointer"><td className="px-4 py-2 font-semibold">{r.severity}</td><td className="px-4 py-2">{r.title||r.type}</td><td className="px-4 py-2 font-mono-code">{r.src||r.src_ip||"—"}</td><td className="px-4 py-2 font-mono-code">{r.dst||r.dst_ip||"—"}</td><td className="px-4 py-2 text-slate-500">{r.description||r.detail||"—"}</td></tr>)}</Table>; }

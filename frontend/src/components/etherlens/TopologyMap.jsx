import { useMemo, useState } from "react";
import { fmtBytes } from "./lib";
import { Search, Pause, Play, Focus, RotateCcw, Network, List, Map as MapIcon } from "lucide-react";

export default function TopologyMap({ topology }) {
  const { nodes = [], edges = [] } = topology;
  const [selected, setSelected] = useState(null);
  const [query, setQuery] = useState("");
  const [view, setView] = useState("map");
  const [paused, setPaused] = useState(false);
  const [focusOnly, setFocusOnly] = useState(false);
  const [noiseFloor, setNoiseFloor] = useState("auto");

  const edgeMap = useMemo(() => {
    const map = new Map();
    edges.forEach((e) => {
      [e.source, e.target].forEach((id) => {
        if (!map.has(id)) map.set(id, []);
        map.get(id).push(e);
      });
    });
    return map;
  }, [edges]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    const selectedId = selected?.id;
    const selectedEdges = selectedId ? (edgeMap.get(selectedId) || []) : [];
    const neighbors = new Set(selectedEdges.flatMap((e) => [e.source, e.target]));
    const maxBytes = Math.max(1, ...edges.map((e) => Number(e.bytes || 0)));
    const threshold = noiseFloor === "all" ? 0 : noiseFloor === "high" ? maxBytes * 0.05 : edges.length > 80 ? maxBytes * 0.01 : 0;
    let filteredEdges = edges.filter((e) => Number(e.bytes || 0) >= threshold);
    if (focusOnly && selectedId) filteredEdges = filteredEdges.filter((e) => e.source === selectedId || e.target === selectedId);
    const connected = new Set(filteredEdges.flatMap((e) => [e.source, e.target]));
    let filteredNodes = nodes.filter((n) => connected.has(n.id) || !edges.length);
    if (focusOnly && selectedId) filteredNodes = filteredNodes.filter((n) => neighbors.has(n.id));
    if (q) filteredNodes = filteredNodes.filter((n) => [n.id, n.geo?.country, n.geo?.city, n.geo?.asname, n.geo?.org, ...(n.ports || [])].some((v) => String(v || "").toLowerCase().includes(q)));
    const allowed = new Set(filteredNodes.map((n) => n.id));
    filteredEdges = filteredEdges.filter((e) => allowed.has(e.source) && allowed.has(e.target));
    return { nodes: filteredNodes, edges: filteredEdges, hiddenNodes: Math.max(0, nodes.length - filteredNodes.length), hiddenEdges: Math.max(0, edges.length - filteredEdges.length) };
  }, [nodes, edges, query, selected, focusOnly, noiseFloor, edgeMap]);

  const layout = useMemo(() => {
    const w = 1100, h = 610;
    const local = visible.nodes.filter((n) => n.type === "local");
    const ext = visible.nodes.filter((n) => n.type !== "local");
    const positions = {};
    const place = (list, cx, maxR) => {
      const rings = Math.max(1, Math.ceil(list.length / 18));
      list.forEach((n, i) => {
        const ring = Math.floor(i / 18);
        const ringItems = Math.min(18, list.length - ring * 18);
        const theta = ((i % 18) / Math.max(1, ringItems)) * Math.PI * 2;
        const r = Math.min(maxR, 75 + ring * 70 + Math.min(70, ringItems * 4));
        positions[n.id] = { x: cx + r * Math.cos(theta), y: h / 2 + r * Math.sin(theta) };
      });
    };
    if (focusOnly && selected) {
      positions[selected.id] = { x: w / 2, y: h / 2 };
      const others = visible.nodes.filter((n) => n.id !== selected.id);
      others.forEach((n, i) => { const theta = (i / Math.max(1, others.length)) * Math.PI * 2; const r = 205; positions[n.id] = { x: w / 2 + r * Math.cos(theta), y: h / 2 + r * Math.sin(theta) }; });
    } else { place(local, w * 0.3, 245); place(ext, w * 0.72, 245); }
    return { positions, w, h };
  }, [visible.nodes, focusOnly, selected]);

  const selectedEdges = selected ? (edgeMap.get(selected.id) || []) : [];
  const maxEdge = Math.max(1, ...visible.edges.map((e) => Number(e.bytes || 0)));
  const reset = () => { setSelected(null); setQuery(""); setFocusOnly(false); setNoiseFloor("auto"); };

  return <div className="space-y-3" data-testid="topology-map">
    <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-3">
      <div className="flex flex-wrap gap-3 items-center justify-between">
        <div><h3 className="font-display font-bold text-sm">Network Map</h3><p className="text-xs text-slate-500">{visible.nodes.length} visible hosts · {visible.edges.length} visible connections{visible.hiddenNodes || visible.hiddenEdges ? ` · ${visible.hiddenNodes} hosts / ${visible.hiddenEdges} connections hidden` : ""}</p></div>
        <div className="flex flex-wrap gap-2">
          <button onClick={()=>setPaused(!paused)} className="tool"><span>{paused?<Play size={14}/>:<Pause size={14}/>}</span>{paused?"Resume":"Pause"}</button>
          <button disabled={!selected} onClick={()=>setFocusOnly(!focusOnly)} className={`tool ${focusOnly?"active":""}`}><Focus size={14}/>Focus</button>
          <button onClick={reset} className="tool"><RotateCcw size={14}/>Reset</button>
          <button onClick={()=>setView(view==="map"?"list":"map")} className="tool">{view==="map"?<List size={14}/>:<MapIcon size={14}/>} {view==="map"?"List":"Map"}</button>
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-2 mt-3">
        <label className="relative"><Search size={14} className="absolute left-3 top-2.5 text-slate-400"/><input value={query} onChange={(e)=>setQuery(e.target.value)} placeholder="Search IP, port, ASN, organization or location" className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-transparent pl-9 pr-3 py-2 text-xs"/></label>
        <select value={noiseFloor} onChange={(e)=>setNoiseFloor(e.target.value)} className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-xs"><option value="auto">Low-noise: Auto</option><option value="all">Show all traffic</option><option value="high">High-volume only</option></select>
      </div>
    </div>

    <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_320px] gap-3">
      <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
        {view === "map" ? <div className="relative overflow-hidden" style={{height:610}}>
          <svg viewBox={`0 0 ${layout.w} ${layout.h}`} className="w-full h-full">
            {visible.edges.map((e,i)=>{const a=layout.positions[e.source],b=layout.positions[e.target];if(!a||!b)return null;const width=1+(Number(e.bytes||0)/maxEdge)*5;const highlighted=selected&&(e.source===selected.id||e.target===selected.id);return <g key={`${e.source}-${e.target}-${i}`}><line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={highlighted?"#2563eb":"rgba(100,116,139,.28)"} strokeWidth={highlighted?Math.max(2,width):width}/>{!paused&&highlighted&&<circle r="3" fill="#2563eb"><animateMotion dur="1.5s" repeatCount="indefinite" path={`M${a.x},${a.y} L${b.x},${b.y}`}/></circle>}</g>})}
            {visible.nodes.map((n)=>{const p=layout.positions[n.id];if(!p)return null;const active=selected?.id===n.id;const local=n.type==="local";const gateway=n.id.endsWith(".1");const r=active?19:Math.min(17,9+Math.log2(Number(n.bytes||1)+1)/2);return <g key={n.id} onClick={()=>setSelected(n)} className="cursor-pointer"><circle cx={p.x} cy={p.y} r={r+5} fill={active?"#2563eb":gateway?"#10b981":local?"#3b82f6":"#f97316"} opacity=".16"/><circle cx={p.x} cy={p.y} r={r} fill={gateway?"#10b981":local?"#2563eb":"#f97316"} stroke={active?"#fff":"rgba(255,255,255,.8)"} strokeWidth={active?4:2}/><text x={p.x} y={p.y+r+15} textAnchor="middle" fontSize="10" fill="currentColor" className="font-mono-code pointer-events-none">{n.id}</text></g>})}
          </svg>
          {!visible.nodes.length&&<Empty/>}
          <div className="absolute bottom-3 left-3 flex gap-3 text-[10px] bg-white/90 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2"><Legend color="#2563eb" text="Local"/><Legend color="#10b981" text="Gateway"/><Legend color="#f97316" text="External"/></div>
        </div> : <NodeList nodes={visible.nodes} selected={selected} onSelect={setSelected}/>} 
      </div>
      <Inspector node={selected} edges={selectedEdges} nodes={nodes} onFocus={()=>setFocusOnly(true)} focusOnly={focusOnly}/>
    </div>
    <style>{`.tool{display:inline-flex;align-items:center;gap:.35rem;padding:.45rem .65rem;border-radius:.5rem;font-size:.75rem;font-weight:600;background:rgb(241 245 249)}.dark .tool{background:rgb(30 41 59)}.tool:disabled{opacity:.4}.tool.active{background:#2563eb;color:white}`}</style>
  </div>;
}

function Inspector({node,edges,nodes,onFocus,focusOnly}) { if(!node)return <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 flex flex-col items-center justify-center text-center min-h-64"><Network size={28} className="text-slate-400"/><div className="font-semibold text-sm mt-3">Select a host</div><p className="text-xs text-slate-500 mt-1">Choose a node or use List view. Its connections stay in this side panel instead of cluttering the map.</p></div>; const peers=edges.map(e=>({edge:e,id:e.source===node.id?e.target:e.source})).sort((a,b)=>Number(b.edge.bytes||0)-Number(a.edge.bytes||0)); return <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden"><div className="p-4 border-b border-slate-200 dark:border-slate-800"><div className="text-[10px] uppercase tracking-wider text-slate-500">Selected host</div><div className="font-mono-code font-bold mt-1 break-all">{node.id}</div><div className="text-xs text-slate-500 mt-1">{node.type==="local"?"Local host":node.geo?.country||"External endpoint"}</div><button onClick={onFocus} disabled={focusOnly} className="mt-3 tool"><Focus size={14}/>{focusOnly?"Focused":"Focus on this host"}</button></div><div className="grid grid-cols-2 gap-2 p-3"><Stat label="Packets" value={Number(node.packets||0).toLocaleString()}/><Stat label="Traffic" value={fmtBytes(node.bytes||0)}/><Stat label="Connections" value={edges.length}/><Stat label="Ports" value={(node.ports||[]).length}/></div><div className="px-4 pb-3 text-xs space-y-1">{node.geo?.asname&&<div><span className="text-slate-500">ASN:</span> {node.geo.asname}</div>}{node.geo?.org&&<div><span className="text-slate-500">Org:</span> {node.geo.org}</div>}{node.ports?.length>0&&<div><span className="text-slate-500">Ports:</span> {node.ports.slice(0,12).join(", ")}</div>}</div><div className="border-t border-slate-200 dark:border-slate-800"><div className="px-4 py-2 text-xs font-semibold">Top connections</div><div className="max-h-72 overflow-auto el-scroll">{peers.slice(0,30).map(({edge,id},i)=><div key={`${id}-${i}`} className="px-4 py-2 border-t border-slate-100 dark:border-slate-800"><div className="font-mono-code text-xs truncate">{id}</div><div className="text-[10px] text-slate-500 mt-1">{fmtBytes(edge.bytes||0)}{edge.packets!=null?` · ${edge.packets} packets`:""}</div></div>)}{!peers.length&&<div className="p-4 text-xs text-slate-400">No visible connections.</div>}</div></div></div>; }
function NodeList({nodes,selected,onSelect}) { return <div className="max-h-[610px] overflow-auto el-scroll"><table className="w-full text-xs"><thead className="sticky top-0 bg-white dark:bg-slate-900"><tr className="text-left text-slate-500"><th className="px-4 py-3">Host</th><th>Type</th><th>Packets</th><th>Traffic</th><th>Ports</th></tr></thead><tbody>{nodes.slice().sort((a,b)=>Number(b.bytes||0)-Number(a.bytes||0)).map(n=><tr key={n.id} onClick={()=>onSelect(n)} className={`border-t border-slate-100 dark:border-slate-800 cursor-pointer ${selected?.id===n.id?"bg-blue-50 dark:bg-blue-950/20":"hover:bg-slate-50 dark:hover:bg-slate-800"}`}><td className="px-4 py-3 font-mono-code">{n.id}</td><td>{n.type||"—"}</td><td>{Number(n.packets||0).toLocaleString()}</td><td>{fmtBytes(n.bytes||0)}</td><td>{(n.ports||[]).slice(0,5).join(", ")||"—"}</td></tr>)}</tbody></table>{!nodes.length&&<Empty/>}</div>; }
function Stat({label,value}) { return <div className="rounded-lg bg-slate-50 dark:bg-slate-800 p-2"><div className="text-[9px] uppercase text-slate-500">{label}</div><div className="text-xs font-semibold mt-1">{value}</div></div>; }
function Legend({color,text}) { return <span className="inline-flex items-center gap-1"><span className="w-2 h-2 rounded-full" style={{background:color}}/>{text}</span>; }
function Empty() { return <div className="p-12 text-center text-sm text-slate-400">No hosts match the current topology filters.</div>; }

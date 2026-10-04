import { useEffect, useMemo, useRef, useState } from "react";
import { fmtBytes } from "./lib";

/**
 * Simple force-directed-ish layout: local hosts in a left cluster, external on the right,
 * animated with packet dots moving along edges.
 */
export default function TopologyMap({ topology }) {
  const { nodes = [], edges = [] } = topology;
  const svgRef = useRef(null);
  const [hovered, setHovered] = useState(null);

  const layout = useMemo(() => {
    const w = 1100, h = 560;
    const local = nodes.filter((n) => n.type === "local");
    const ext = nodes.filter((n) => n.type !== "local");
    const positions = {};
    const place = (list, cx) => {
      const r = Math.min(220, 60 + list.length * 12);
      list.forEach((n, i) => {
        const theta = (i / Math.max(1, list.length)) * Math.PI * 2;
        positions[n.id] = { x: cx + r * Math.cos(theta), y: h / 2 + r * Math.sin(theta), node: n };
      });
    };
    place(local, w * 0.3);
    place(ext, w * 0.72);
    return { positions, w, h };
  }, [nodes]);

  const maxEdge = Math.max(1, ...edges.map((e) => e.bytes));

  return (
    <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden" data-testid="topology-map">
      <div className="px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
        <div>
          <h3 className="font-display font-bold text-sm">Network Topology</h3>
          <p className="text-xs text-slate-500 dark:text-slate-400">{nodes.length} hosts · {edges.length} flows</p>
        </div>
        <div className="flex items-center gap-3 text-xs">
          <LegendDot color="#2563eb" label="Local host" />
          <LegendDot color="#f97316" label="External" />
          <LegendDot color="#10b981" label="Gateway" />
        </div>
      </div>
      <div className="relative" style={{ height: 560, background: "radial-gradient(ellipse at center, rgba(37,99,235,0.04), transparent 70%)" }}>
        <svg ref={svgRef} viewBox={`0 0 ${layout.w} ${layout.h}`} className="w-full h-full">
          {/* edges */}
          {edges.map((e, i) => {
            const a = layout.positions[e.source]; const b = layout.positions[e.target];
            if (!a || !b) return null;
            const w = 1 + (e.bytes / maxEdge) * 4;
            const dur = 1.2 + Math.random() * 1.5;
            return (
              <g key={i}>
                <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="rgba(37,99,235,0.35)" strokeWidth={w} />
                <circle r={2.5} fill="#2563eb">
                  <animateMotion dur={`${dur}s`} repeatCount="indefinite" path={`M${a.x},${a.y} L${b.x},${b.y}`} />
                </circle>
              </g>
            );
          })}
          {/* nodes */}
          {nodes.map((n) => {
            const p = layout.positions[n.id];
            if (!p) return null;
            const isLocal = n.type === "local";
            const isGateway = n.id.endsWith(".1");
            const color = isGateway ? "#10b981" : isLocal ? "#2563eb" : "#f97316";
            const r = 10 + Math.min(14, Math.log2((n.bytes || 1) + 1));
            return (
              <g key={n.id} className="topo-node" data-testid={`topology-node-${n.id.replace(/\./g, "-")}`}
                onMouseEnter={() => setHovered(n)} onMouseLeave={() => setHovered(null)}>
                <circle cx={p.x} cy={p.y} r={r + 4} fill={color} opacity={0.18} />
                <circle cx={p.x} cy={p.y} r={r} fill={color} stroke="white" strokeWidth={2} />
                <text x={p.x} y={p.y + r + 14} textAnchor="middle" fontSize="11" fill="currentColor" className="font-mono-code">{n.id}</text>
              </g>
            );
          })}
        </svg>

        {hovered && (
          <div className="absolute top-3 right-3 w-60 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg shadow-lg p-3 text-xs font-mono-code">
            <div className="font-semibold text-sm">{hovered.id}</div>
            <div className="text-slate-500">{hovered.type === "local" ? "Local host" : "External endpoint"}</div>
            <div className="mt-2 space-y-0.5">
              <div>Packets: <span className="font-semibold">{hovered.packets.toLocaleString()}</span></div>
              <div>Bytes: <span className="font-semibold">{fmtBytes(hovered.bytes)}</span></div>
              <div>Ports: {hovered.ports?.length ? hovered.ports.join(", ") : "—"}</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function LegendDot({ color, label }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-slate-600 dark:text-slate-300">
      <span className="w-2.5 h-2.5 rounded-full" style={{ background: color }} /> {label}
    </span>
  );
}

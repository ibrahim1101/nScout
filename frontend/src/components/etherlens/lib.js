import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || "";
export const API = `${BACKEND_URL}/api`;

export const api = axios.create({ baseURL: API, timeout: 15000 });

export function wsUrl() {
  // Same-origin by default (used by the PyInstaller bundle that serves UI + API together).
  const base = BACKEND_URL || window.location.origin;
  const u = new URL(base);
  const proto = u.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${u.host}/api/ws`;
}

export const PROTO_COLOR = {
  TCP: "#2563eb",
  UDP: "#059669",
  ICMP: "#dc2626",
  ARP: "#7c3aed",
  DNS: "#d97706",
  HTTP: "#8b5cf6",
  HTTPS: "#0891b2",
  TLS: "#0891b2",
  SSH: "#475569",
  FTP: "#b45309",
  IPv4: "#64748b",
  IPv6: "#64748b",
  SMTP: "#ea580c",
  MySQL: "#0ea5e9",
  PostgreSQL: "#0ea5e9",
  Redis: "#dc2626",
  MongoDB: "#16a34a",
};

export function fmtBytes(n) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}

export function fmtBps(bps) {
  if (!bps) return "0 bps";
  const units = ["bps", "Kbps", "Mbps", "Gbps"];
  let i = 0;
  while (bps >= 1000 && i < units.length - 1) { bps /= 1000; i++; }
  return `${bps.toFixed(i ? 2 : 0)} ${units[i]}`;
}

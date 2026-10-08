import { useEffect, useState } from "react";
import { FileDown, ShieldCheck } from "lucide-react";
import { api } from "./lib";
import { readPrefs } from "./SettingsDrawer";

const FORMATS = ["pdf", "html", "json", "csv", "xlsx", "xml"];

export default function ReportExports({ workspaceId = "", className = "", compact = false }) {
  const [redact, setRedact] = useState(() => !!readPrefs().redactReports);
  useEffect(() => {
    const update = (event) => setRedact(!!(event.detail || readPrefs()).redactReports);
    window.addEventListener("nscout:preferences", update);
    return () => window.removeEventListener("nscout:preferences", update);
  }, []);
  const url = (format) => {
    const params = new URLSearchParams();
    if (workspaceId) params.set("workspace_id", workspaceId);
    if (redact) params.set("redact", "true");
    const query = params.toString();
    return `${api.defaults.baseURL}/investigation/report.${format}${query ? `?${query}` : ""}`;
  };
  return (
    <section className={`${compact ? "" : "rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4"} ${className}`} data-testid="report-exports">
      {!compact && <div className="flex items-center gap-2"><FileDown size={15}/><h3 className="font-display font-bold text-sm">Investigation Report 2.0</h3>{redact && <span className="ml-auto inline-flex items-center gap-1 rounded-full bg-violet-100 dark:bg-violet-500/10 px-2 py-1 text-[10px] font-bold uppercase text-violet-700 dark:text-violet-300"><ShieldCheck size={11}/>Redacted</span>}</div>}
      {!compact && <p className="mt-2 text-xs text-slate-500">Exports current hosts, findings and timeline{workspaceId ? ", plus this case's evidence, notes and finding states" : ""}. Payloads and evidence snapshot bodies are excluded.</p>}
      <div className={`flex flex-wrap gap-2 ${compact ? "" : "mt-4"}`}>
        {FORMATS.map((format) => <a key={format} href={url(format)} data-testid={`report-${format}`} className={`rounded-md px-3 py-2 text-xs font-semibold uppercase ${format === "pdf" ? "bg-blue-600 text-white" : "bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200"}`}>{format}</a>)}
      </div>
    </section>
  );
}

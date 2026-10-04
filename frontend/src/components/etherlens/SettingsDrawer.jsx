import { useEffect, useState } from "react";
import { api } from "./lib";
import { X, Save, Check, AlertCircle, Zap } from "lucide-react";

const SEVERITIES = [
  { v: "low", label: "Low & above" },
  { v: "medium", label: "Medium & above" },
  { v: "high", label: "High & above" },
  { v: "critical", label: "Critical only" },
];

export default function SettingsDrawer({ open, onClose }) {
  const [slack, setSlack] = useState("");
  const [discord, setDiscord] = useState("");
  const [severity, setSeverity] = useState("high");
  const [saved, setSaved] = useState(false);
  const [testing, setTesting] = useState("");
  const [testResult, setTestResult] = useState(null);

  useEffect(() => {
    if (!open) return;
    api.get("/settings/webhooks").then((r) => {
      setSlack(r.data.slack_url || "");
      setDiscord(r.data.discord_url || "");
      setSeverity(r.data.min_severity || "high");
    });
  }, [open]);

  const save = async () => {
    await api.post("/settings/webhooks", { slack_url: slack, discord_url: discord, min_severity: severity });
    setSaved(true);
    setTimeout(() => setSaved(false), 1800);
  };

  const test = async (url, which) => {
    if (!url) return;
    setTesting(which); setTestResult(null);
    try {
      const r = await api.post("/settings/webhooks/test", { url });
      setTestResult({ which, ok: r.data.ok, msg: r.data.ok ? `OK (${r.data.status})` : (r.data.error || `HTTP ${r.data.status}`) });
    } catch (e) {
      setTestResult({ which, ok: false, msg: e.message });
    } finally {
      setTesting("");
    }
  };

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-end bg-slate-950/50 backdrop-blur-sm" onClick={onClose}>
      <div
        onClick={(e) => e.stopPropagation()}
        data-testid="settings-drawer"
        className="w-full max-w-md h-full bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-800 shadow-2xl flex flex-col"
      >
        <div className="px-5 py-3 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <h3 className="font-display font-bold">Alert Settings</h3>
          <button data-testid="settings-close" onClick={onClose} className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md"><X size={16} /></button>
        </div>

        <div className="flex-1 overflow-auto el-scroll p-5 space-y-6">
          <section>
            <h4 className="text-sm font-semibold mb-2 flex items-center gap-1.5"><Zap size={14} className="text-amber-500" /> Minimum severity</h4>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">Only forward threats at or above this severity to webhooks.</p>
            <select
              data-testid="settings-severity"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="w-full px-3 py-2 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 text-sm font-mono-code focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {SEVERITIES.map((s) => <option key={s.v} value={s.v}>{s.label}</option>)}
            </select>
          </section>

          <WebhookField
            label="Slack webhook URL"
            placeholder="https://hooks.slack.com/services/…"
            value={slack}
            onChange={setSlack}
            onTest={() => test(slack, "slack")}
            testing={testing === "slack"}
            testId="settings-slack-url"
            doc="https://api.slack.com/messaging/webhooks"
          />
          <WebhookField
            label="Discord webhook URL"
            placeholder="https://discord.com/api/webhooks/…"
            value={discord}
            onChange={setDiscord}
            onTest={() => test(discord, "discord")}
            testing={testing === "discord"}
            testId="settings-discord-url"
            doc="https://support.discord.com/hc/articles/228383668"
          />

          {testResult && (
            <div data-testid="settings-test-result" className={`rounded-md border px-3 py-2 text-sm flex items-center gap-2 ${testResult.ok ? "bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/30 text-emerald-700 dark:text-emerald-300" : "bg-rose-50 dark:bg-rose-500/10 border-rose-200 dark:border-rose-500/30 text-rose-700 dark:text-rose-300"}`}>
              {testResult.ok ? <Check size={14} /> : <AlertCircle size={14} />}
              <span className="capitalize">{testResult.which}</span>: {testResult.msg}
            </div>
          )}
        </div>

        <div className="px-5 py-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <span className="text-xs text-slate-500 dark:text-slate-400">Changes persist in MongoDB</span>
          <button
            data-testid="settings-save"
            onClick={save}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold"
          >
            {saved ? <Check size={14} /> : <Save size={14} />}
            {saved ? "Saved" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

function WebhookField({ label, placeholder, value, onChange, onTest, testing, testId, doc }) {
  return (
    <section>
      <h4 className="text-sm font-semibold mb-1">{label}</h4>
      <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">
        Paste your incoming webhook URL. <a className="text-blue-600 dark:text-blue-400 underline" href={doc} target="_blank" rel="noreferrer">How to create one</a>
      </p>
      <div className="flex gap-2">
        <input
          data-testid={testId}
          type="url"
          placeholder={placeholder}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="flex-1 px-3 py-2 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 text-sm font-mono-code focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <button
          data-testid={`${testId}-test`}
          onClick={onTest}
          disabled={!value || testing}
          className="px-3 py-2 rounded-md bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-sm font-semibold disabled:opacity-50"
        >
          {testing ? "Testing…" : "Test"}
        </button>
      </div>
    </section>
  );
}

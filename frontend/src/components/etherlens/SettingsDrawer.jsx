import { useEffect, useRef, useState } from "react";
import { api } from "./lib";
import {
  X,
  Save,
  Check,
  AlertCircle,
  Zap,
  BrainCircuit,
  Database,
  ShieldCheck,
  SlidersHorizontal,
  Keyboard,
  Search,
  UserRoundCog,
  Plus,
  Trash2,
  Play,
} from "lucide-react";
import { KEYBOARD_SHORTCUTS } from "./keyboardShortcuts";

const SEVERITIES = [
  { v: "low", label: "Low & above" },
  { v: "medium", label: "Medium & above" },
  { v: "high", label: "High & above" },
  { v: "critical", label: "Critical only" },
];
export const DEFAULTS = {
  aiEnabled: false,
  preservePackets: true,
  autoRestore: true,
  redactReports: false,
  packetLimit: 50000,
  detectionPreset: "balanced",
};
export const normalizePacketLimit = (value) =>
  Math.min(
    1000000,
    Math.max(1000, Math.round(Number(value) || DEFAULTS.packetLimit)),
  );
export const readPrefs = () => {
  try {
    const value = {
      ...DEFAULTS,
      ...JSON.parse(localStorage.getItem("nscout.preferences") || "{}"),
    };
    return { ...value, packetLimit: normalizePacketLimit(value.packetLimit) };
  } catch (_) {
    return DEFAULTS;
  }
};

export default function SettingsDrawer({
  open,
  onClose,
  initialSection = null,
}) {
  const [ai, setAI] = useState({
      enabled: false,
      provider: "ollama",
      base_url: "http://127.0.0.1:11434/v1",
      model: "",
      timeout_seconds: 60,
      max_tokens: 1024,
    }),
    [models, setModels] = useState([]),
    [aiResult, setAIResult] = useState(""),
    [aiTesting, setAITesting] = useState(false),
    [saveError, setSaveError] = useState(""),
    [aiLoaded, setAILoaded] = useState(false);
  const [slack, setSlack] = useState(""),
    [discord, setDiscord] = useState(""),
    [severity, setSeverity] = useState("high");
  const [prefs, setPrefs] = useState(readPrefs),
    [saved, setSaved] = useState(false),
    [testing, setTesting] = useState(""),
    [testResult, setTestResult] = useState(null);
  const [shortcutQuery, setShortcutQuery] = useState("");
  const [profiles, setProfiles] = useState([]),
    [profileName, setProfileName] = useState(""),
    [profileStatus, setProfileStatus] = useState("");
  const shortcutsRef = useRef(null);
  useEffect(() => {
    if (!open) return;
    setPrefs(readPrefs());
    setAILoaded(false);
    setProfileStatus("");
    api
      .get("/settings/ai")
      .then((r) => {
        setAI(r.data);
        setAILoaded(true);
        patch("aiEnabled", r.data.enabled);
      })
      .catch(() =>
        setSaveError("Could not load AI settings. Reopen Settings to retry."),
      );
    api
      .get("/settings/webhooks")
      .then((r) => {
        setSlack(r.data.slack_url || "");
        setDiscord(r.data.discord_url || "");
        setSeverity(r.data.min_severity || "high");
      })
      .catch(() => {});
    api
      .get("/settings/profiles")
      .then((r) => setProfiles(r.data.profiles || []))
      .catch(() => setProfileStatus("Could not load local profiles."));
  }, [open]);
  useEffect(() => {
    if (open && initialSection === "shortcuts")
      requestAnimationFrame(() =>
        shortcutsRef.current?.scrollIntoView({
          behavior: "smooth",
          block: "start",
        }),
      );
  }, [open, initialSection]);
  const patch = (key, value) => setPrefs((p) => ({ ...p, [key]: value }));
  const save = async () => {
    setSaveError("");
    try {
      const next = {
        ...prefs,
        aiEnabled: ai.enabled,
        packetLimit: normalizePacketLimit(prefs.packetLimit),
      };
      await api.post("/settings/ai", ai);
      await api.post("/settings/webhooks", {
        slack_url: slack,
        discord_url: discord,
        min_severity: severity,
      });
      await api.post("/capture/configuration", {
        packet_limit: next.packetLimit,
      });
      localStorage.setItem("nscout.preferences", JSON.stringify(next));
      window.dispatchEvent(
        new CustomEvent("nscout:preferences", { detail: next }),
      );
      setPrefs(next);
      setSaved(true);
      setTimeout(() => setSaved(false), 1800);
    } catch (e) {
      setSaveError(
        e.response?.data?.detail
          ? JSON.stringify(e.response.data.detail)
          : "Could not save settings.",
      );
    }
  };
  const testAI = async () => {
    setAITesting(true);
    setAIResult("");
    try {
      const r = await api.post("/settings/ai/test", ai);
      setModels(r.data.models || []);
      setAIResult(r.data.message);
      if (r.data.ok && !ai.model && r.data.models?.length)
        setAI((a) => ({ ...a, model: r.data.models[0] }));
    } catch (e) {
      setAIResult("Could not test connection. Check the address.");
    } finally {
      setAITesting(false);
    }
  };
  const provider = (value) => {
    setModels([]);
    setAIResult("");
    setAI((a) => ({
      ...a,
      provider: value,
      model: "",
      base_url:
        value === "ollama"
          ? "http://127.0.0.1:11434/v1"
          : "http://127.0.0.1:1234/v1",
    }));
  };
  const test = async (url, which) => {
    if (!url) return;
    setTesting(which);
    setTestResult(null);
    try {
      const r = await api.post("/settings/webhooks/test", { url });
      setTestResult({
        which,
        ok: r.data.ok,
        msg: r.data.ok
          ? `OK (${r.data.status})`
          : r.data.error || `HTTP ${r.data.status}`,
      });
    } catch (e) {
      setTestResult({ which, ok: false, msg: e.message });
    } finally {
      setTesting("");
    }
  };
  const createProfile = async () => {
    if (!profileName.trim()) return;
    setProfileStatus("");
    try {
      const r = await api.post("/settings/profiles", {
        name: profileName.trim(),
        preferences: {
          ...prefs,
          packetLimit: normalizePacketLimit(prefs.packetLimit),
          alertSeverity: severity,
        },
      });
      setProfiles((items) => [r.data.profile, ...items]);
      setProfileName("");
      setProfileStatus("Profile saved locally.");
    } catch (e) {
      setProfileStatus(
        e.response?.data?.detail || "Could not save this profile.",
      );
    }
  };
  const applyProfile = (profile) => {
    setPrefs((p) => ({
      ...p,
      ...profile.preferences,
      packetLimit: normalizePacketLimit(profile.preferences.packetLimit),
    }));
    setSeverity(profile.preferences.alertSeverity || "high");
    setProfileStatus(`Loaded ${profile.name}. Select Save to apply it.`);
  };
  const deleteProfile = async (profile) => {
    setProfileStatus("");
    try {
      await api.delete(`/settings/profiles/${profile.id}`);
      setProfiles((items) => items.filter((item) => item.id !== profile.id));
      setProfileStatus(`Deleted ${profile.name}.`);
    } catch (e) {
      setProfileStatus(
        e.response?.data?.detail || "Could not delete this profile.",
      );
    }
  };
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-end bg-slate-950/50 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        data-testid="settings-drawer"
        className="w-full max-w-lg h-full bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-800 shadow-2xl flex flex-col"
      >
        <div className="px-5 py-3 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="font-display font-bold">nScout Settings</h3>
            <p className="text-[11px] text-slate-500">
              Capture, investigation, privacy and alert preferences
            </p>
          </div>
          <button
            data-testid="settings-close"
            onClick={onClose}
            className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md"
          >
            <X size={16} />
          </button>
        </div>
        <div className="flex-1 overflow-auto el-scroll p-5 space-y-6">
          <Group icon={BrainCircuit} title="AI integration">
            <Toggle
              label="Enable AI features"
              description="Optional explanations; disabled by default. Core analysis works without AI."
              value={ai.enabled}
              onChange={(enabled) => setAI((a) => ({ ...a, enabled }))}
            />
            {ai.enabled && (
              <div className="space-y-3">
                <label className="block text-xs font-semibold">
                  Provider
                  <select
                    value={ai.provider}
                    onChange={(e) => provider(e.target.value)}
                    className="mt-1 w-full border rounded-md p-2 bg-white dark:bg-slate-950"
                  >
                    <option value="ollama">Ollama (local)</option>
                    <option value="lmstudio">LM Studio (local)</option>
                    <option value="openai_compatible">
                      Custom local OpenAI-compatible server
                    </option>
                    <option value="emergent">Cloud (existing AI key)</option>
                  </select>
                </label>
                {ai.provider !== "emergent" ? (
                  <>
                    <p className="text-xs text-slate-500">
                      Run the model server on the same computer as nScout. Only
                      loopback endpoints are supported. nScout sends selected
                      evidence to this server; check your server uses a local
                      model.
                    </p>
                    <label className="block text-xs font-semibold">
                      API base URL
                      <input
                        type="url"
                        value={ai.base_url}
                        onChange={(e) =>
                          setAI((a) => ({ ...a, base_url: e.target.value }))
                        }
                        className="mt-1 w-full border rounded-md p-2 bg-transparent"
                      />
                    </label>
                    <label className="block text-xs font-semibold">
                      Model ID
                      <input
                        list="nscout-ai-models"
                        value={ai.model}
                        onChange={(e) =>
                          setAI((a) => ({ ...a, model: e.target.value }))
                        }
                        placeholder="Test connection or enter model ID"
                        className="mt-1 w-full border rounded-md p-2 bg-transparent"
                      />
                      <datalist id="nscout-ai-models">
                        {models.map((m) => (
                          <option key={m} value={m} />
                        ))}
                      </datalist>
                    </label>
                    <label className="block text-xs font-semibold">
                      Timeout (seconds)
                      <input
                        type="number"
                        min="5"
                        max="180"
                        value={ai.timeout_seconds}
                        onChange={(e) =>
                          setAI((a) => ({
                            ...a,
                            timeout_seconds: Number(e.target.value),
                          }))
                        }
                        className="mt-1 w-full border rounded-md p-2 bg-transparent"
                      />
                    </label>
                    <label className="block text-xs font-semibold">
                      Maximum output tokens
                      <input
                        type="number"
                        min="64"
                        max="4096"
                        value={ai.max_tokens}
                        onChange={(e) =>
                          setAI((a) => ({
                            ...a,
                            max_tokens: Number(e.target.value),
                          }))
                        }
                        className="mt-1 w-full border rounded-md p-2 bg-transparent"
                      />
                    </label>
                  </>
                ) : (
                  <p className="text-xs text-slate-500">
                    Uses EMERGENT_LLM_KEY configured on the nScout backend.
                    Selected evidence will be sent to the cloud provider.
                  </p>
                )}
                <button
                  onClick={testAI}
                  disabled={aiTesting}
                  className="px-3 py-2 rounded-md bg-slate-100 dark:bg-slate-800 text-sm"
                >
                  {aiTesting ? "Testing…" : "Test connection / discover models"}
                </button>
                {aiResult && (
                  <p role="status" className="text-xs">
                    {aiResult}
                  </p>
                )}
                <p className="text-xs text-slate-500">
                  Save to apply. Connection testing discovers models without
                  sending capture evidence.
                </p>
              </div>
            )}
          </Group>
          {saveError && (
            <p role="alert" className="text-sm text-rose-600">
              {saveError}
            </p>
          )}
          <Group icon={Database} title="Capture & workspace">
            <Toggle
              label="Preserve packets when switching interfaces"
              description="Keep the current packet history while capture moves to another interface."
              value={prefs.preservePackets}
              onChange={(v) => patch("preservePackets", v)}
            />
            <Toggle
              label="Restore previous workspace"
              description="Offer recovery of investigation state after restart or an unexpected close."
              value={prefs.autoRestore}
              onChange={(v) => patch("autoRestore", v)}
            />
            <label className="block text-xs font-semibold mt-3">
              Packet retention limit
              <input
                type="number"
                min="1000"
                max="1000000"
                step="1000"
                value={prefs.packetLimit}
                onChange={(e) =>
                  patch("packetLimit", normalizePacketLimit(e.target.value))
                }
                className="mt-1 w-full px-3 py-2 rounded-md border border-slate-200 dark:border-slate-700 bg-transparent font-mono-code"
              />
              <span className="block mt-1 text-[11px] font-normal text-slate-500">
                Oldest packets are evicted first; packet detail lookup is pruned
                with the buffer.
              </span>
            </label>
          </Group>
          <Group icon={ShieldCheck} title="Investigation & privacy">
            <Toggle
              label="Redact exported reports"
              description="Prepare reports for sharing by requesting anonymization of sensitive network identifiers."
              value={prefs.redactReports}
              onChange={(v) => patch("redactReports", v)}
            />
            <label className="block text-xs font-semibold mt-3">
              Detection sensitivity
              <select
                value={prefs.detectionPreset}
                onChange={(e) => patch("detectionPreset", e.target.value)}
                className="mt-1 w-full px-3 py-2 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950"
              >
                <option value="conservative">Conservative</option>
                <option value="balanced">Balanced</option>
                <option value="sensitive">Sensitive</option>
              </select>
            </label>
          </Group>
          <Group icon={UserRoundCog} title="Local profiles">
            <p className="text-xs text-slate-500">
              Save reusable non-secret preference bundles on this computer.
              Webhook URLs, AI server details and captured evidence are
              excluded.
            </p>
            <div className="flex gap-2">
              <input
                data-testid="profile-name"
                value={profileName}
                onChange={(e) => setProfileName(e.target.value)}
                maxLength={80}
                placeholder="Profile name"
                className="flex-1 px-3 py-2 rounded-md border border-slate-200 dark:border-slate-700 bg-transparent text-sm"
              />
              <button
                data-testid="profile-create"
                onClick={createProfile}
                disabled={!profileName.trim()}
                className="inline-flex items-center gap-1 px-3 py-2 rounded-md bg-blue-600 text-white text-xs font-semibold disabled:opacity-40"
              >
                <Plus size={13} />
                Save profile
              </button>
            </div>
            {profileStatus && (
              <p role="status" className="text-xs text-slate-500">
                {profileStatus}
              </p>
            )}
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {profiles.map((profile) => (
                <div key={profile.id} className="flex items-center gap-2 py-2">
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-semibold truncate">
                      {profile.name}
                    </div>
                    <div className="text-[10px] text-slate-500">
                      {Number(
                        profile.preferences?.packetLimit || 0,
                      ).toLocaleString()}{" "}
                      packets ·{" "}
                      {profile.preferences?.detectionPreset || "balanced"}{" "}
                      detection
                    </div>
                  </div>
                  <button
                    onClick={() => applyProfile(profile)}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-200 dark:border-slate-700 text-xs"
                  >
                    <Play size={11} />
                    Load
                  </button>
                  <button
                    onClick={() => deleteProfile(profile)}
                    aria-label={`Delete ${profile.name}`}
                    className="p-1.5 text-slate-400 hover:text-red-500"
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              ))}
              {!profiles.length && (
                <p className="py-3 text-center text-xs text-slate-400">
                  No local profiles saved yet.
                </p>
              )}
            </div>
          </Group>
          <div ref={shortcutsRef}>
            <Group icon={Keyboard} title="Keyboard shortcuts">
              <p className="text-xs text-slate-500">
                This list is generated from the same registry used by nScout's
                global keyboard handler.
              </p>
              <div className="relative">
                <Search
                  size={13}
                  className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400"
                />
                <input
                  data-testid="shortcut-search"
                  value={shortcutQuery}
                  onChange={(e) => setShortcutQuery(e.target.value)}
                  placeholder="Search shortcuts…"
                  className="w-full pl-8 pr-3 py-2 rounded-md border border-slate-200 dark:border-slate-700 bg-transparent text-sm"
                />
              </div>
              <ShortcutList query={shortcutQuery} />
            </Group>
          </div>
          <Group icon={SlidersHorizontal} title="Alert delivery">
            <h4 className="text-sm font-semibold mb-2 flex items-center gap-1.5">
              <Zap size={14} className="text-amber-500" /> Minimum severity
            </h4>
            <select
              data-testid="settings-severity"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="w-full px-3 py-2 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 text-sm"
            >
              {SEVERITIES.map((s) => (
                <option key={s.v} value={s.v}>
                  {s.label}
                </option>
              ))}
            </select>
            <WebhookField
              label="Slack webhook URL"
              value={slack}
              onChange={setSlack}
              onTest={() => test(slack, "slack")}
              testing={testing === "slack"}
              testId="settings-slack-url"
            />
            <WebhookField
              label="Discord webhook URL"
              value={discord}
              onChange={setDiscord}
              onTest={() => test(discord, "discord")}
              testing={testing === "discord"}
              testId="settings-discord-url"
            />
          </Group>
          {testResult && (
            <div
              data-testid="settings-test-result"
              className={`rounded-md border px-3 py-2 text-sm flex items-center gap-2 ${testResult.ok ? "bg-emerald-50 border-emerald-200 text-emerald-700" : "bg-rose-50 border-rose-200 text-rose-700"}`}
            >
              {testResult.ok ? <Check size={14} /> : <AlertCircle size={14} />}
              <span className="capitalize">{testResult.which}</span>:{" "}
              {testResult.msg}
            </div>
          )}
        </div>
        <div className="px-5 py-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <span className="text-xs text-slate-500">
            App preferences stay local; webhook settings persist in nScout.
          </span>
          <button
            data-testid="settings-save"
            disabled={!aiLoaded}
            onClick={save}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold"
          >
            {saved ? <Check size={14} /> : <Save size={14} />}{" "}
            {saved ? "Saved" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}
function Group({ icon: Icon, title, children }) {
  return (
    <section className="rounded-xl border border-slate-200 dark:border-slate-800 p-4 space-y-3">
      <h4 className="font-display font-bold text-sm flex items-center gap-2">
        <Icon size={15} />
        {title}
      </h4>
      {children}
    </section>
  );
}
function Toggle({ label, description, value, onChange }) {
  return (
    <label className="flex items-start justify-between gap-4 cursor-pointer">
      <span>
        <span className="block text-sm font-semibold">{label}</span>
        <span className="block text-xs text-slate-500 mt-0.5">
          {description}
        </span>
      </span>
      <input
        type="checkbox"
        checked={!!value}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-1 h-4 w-4 accent-blue-600"
      />
    </label>
  );
}
function WebhookField({ label, value, onChange, onTest, testing, testId }) {
  return (
    <div className="pt-2">
      <h4 className="text-xs font-semibold mb-1">{label}</h4>
      <div className="flex gap-2">
        <input
          data-testid={testId}
          type="url"
          placeholder="https://…"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="flex-1 px-3 py-2 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 text-sm font-mono-code"
        />
        <button
          data-testid={`${testId}-test`}
          onClick={onTest}
          disabled={!value || testing}
          className="px-3 py-2 rounded-md bg-slate-100 dark:bg-slate-800 text-sm font-semibold disabled:opacity-50"
        >
          {testing ? "Testing…" : "Test"}
        </button>
      </div>
    </div>
  );
}
function ShortcutList({ query }) {
  const normalized = query.trim().toLowerCase(),
    visible = KEYBOARD_SHORTCUTS.filter(
      (item) =>
        !normalized ||
        [item.category, item.description, ...item.keys]
          .join(" ")
          .toLowerCase()
          .includes(normalized),
    ),
    categories = [...new Set(visible.map((item) => item.category))];
  if (!visible.length)
    return (
      <p className="py-4 text-center text-xs text-slate-400">
        No implemented shortcuts match that search.
      </p>
    );
  return (
    <div className="space-y-3">
      {categories.map((category) => (
        <div key={category}>
          <div className="text-[10px] uppercase tracking-wider text-slate-400 mb-1">
            {category}
          </div>
          <div className="divide-y divide-slate-100 dark:divide-slate-800">
            {visible
              .filter((item) => item.category === category)
              .map((item) => (
                <div
                  key={item.id}
                  className="flex items-center justify-between gap-3 py-2"
                >
                  <span className="text-xs">{item.description}</span>
                  <span className="flex items-center gap-1 shrink-0">
                    {item.keys.map((key) => (
                      <kbd
                        key={key}
                        className="min-w-6 px-1.5 py-0.5 rounded border border-slate-300 dark:border-slate-600 bg-slate-50 dark:bg-slate-800 text-[10px] text-center font-mono-code shadow-sm"
                      >
                        {key}
                      </kbd>
                    ))}
                  </span>
                </div>
              ))}
          </div>
        </div>
      ))}
    </div>
  );
}

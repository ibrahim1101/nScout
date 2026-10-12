import { useCallback, useEffect, useMemo, useState } from "react";
import {
  BookmarkPlus,
  BriefcaseBusiness,
  FileText,
  Plus,
  RefreshCw,
  Server,
  ShieldCheck,
  StickyNote,
  Trash2,
  X,
} from "lucide-react";
import { api } from "./lib";
import ReportExports from "./ReportExports";
import { ACTIVE_INVESTIGATION_KEY as ACTIVE_CASE_KEY } from "./investigationBookmarks";
import { mergeInvestigationSummary } from "./investigationSummary";
import { describeInvestigationWorkspaceState } from "./investigationWorkspaceState";

const FINDING_STATES = [
  "new",
  "investigating",
  "benign",
  "suspicious",
  "confirmed",
  "resolved",
];

export default function InvestigationWorkspace({
  selectedPacket,
  hosts = [],
  findings = [],
  onOpenPacket,
  targetInvestigationId = "",
}) {
  const [cases, setCases] = useState([]);
  const [activeId, setActiveId] = useState("");
  const [workspace, setWorkspace] = useState(null);
  const [caseName, setCaseName] = useState("");
  const [note, setNote] = useState("");
  const [hostId, setHostId] = useState("");
  const [findingId, setFindingId] = useState("");
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [actionError, setActionError] = useState("");

  const loadWorkspace = useCallback(async (id) => {
    if (!id) return null;
    const response = await api.get(`/investigations/${id}`);
    return response.data.investigation;
  }, []);

  const refreshCases = useCallback(
    async (preferredId = "") => {
      setLoading(true);
      setLoadError("");
      try {
        const response = await api.get("/investigations");
        const nextCases = response.data.investigations || [];
        const remembered = window.localStorage.getItem(ACTIVE_CASE_KEY) || "";
        const nextId =
          [preferredId, remembered, nextCases[0]?.id].find(
            (id) => id && nextCases.some((item) => item.id === id),
          ) || "";
        const nextWorkspace = nextId ? await loadWorkspace(nextId) : null;
        setCases(nextCases);
        setActiveId(nextId);
        setWorkspace(nextWorkspace);
        if (nextId) {
          window.localStorage.setItem(ACTIVE_CASE_KEY, nextId);
        } else {
          window.localStorage.removeItem(ACTIVE_CASE_KEY);
        }
        setLoaded(true);
        setLoadError("");
      } catch (err) {
        setLoadError(message(err, "Could not load investigations."));
      } finally {
        setLoading(false);
      }
    },
    [loadWorkspace],
  );

  useEffect(() => {
    refreshCases();
  }, [refreshCases]);

  const selectCase = async (id) => {
    setActionError("");
    try {
      const nextWorkspace = await loadWorkspace(id);
      setActiveId(id);
      setWorkspace(nextWorkspace);
      window.localStorage.setItem(ACTIVE_CASE_KEY, id);
    } catch (err) {
      setActionError(message(err, "Could not open the investigation."));
    }
  };

  useEffect(() => {
    if (
      targetInvestigationId &&
      targetInvestigationId !== activeId &&
      cases.some((item) => item.id === targetInvestigationId)
    )
      selectCase(targetInvestigationId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetInvestigationId, activeId, cases]);

  const createCase = async (event) => {
    event.preventDefault();
    if (!caseName.trim()) return;
    setSaving(true);
    setActionError("");
    try {
      const response = await api.post("/investigations", {
        name: caseName.trim(),
      });
      const created = response.data.investigation;
      setCaseName("");
      await refreshCases(created.id);
    } catch (err) {
      setActionError(message(err, "Could not create the investigation."));
    } finally {
      setSaving(false);
    }
  };

  const mutate = async (request, fallback) => {
    if (!activeId) return;
    setSaving(true);
    setActionError("");
    try {
      const response = await request();
      const nextWorkspace = response.data.investigation;
      if (!nextWorkspace)
        throw new Error("Investigation update returned no workspace.");
      setWorkspace(nextWorkspace);
      setCases((current) =>
        mergeInvestigationSummary(current, nextWorkspace),
      );
      return true;
    } catch (err) {
      setActionError(message(err, fallback));
      return false;
    } finally {
      setSaving(false);
    }
  };

  const deleteCase = async () => {
    if (
      !workspace ||
      !window.confirm(`Delete investigation "${workspace.name}"?`)
    )
      return;
    setSaving(true);
    setActionError("");
    try {
      await api.delete(`/investigations/${activeId}`);
      window.localStorage.removeItem(ACTIVE_CASE_KEY);
      setCases((current) => current.filter((item) => item.id !== activeId));
      setActiveId("");
      setWorkspace(null);
      await refreshCases();
    } catch (err) {
      setActionError(message(err, "Could not delete the investigation."));
    } finally {
      setSaving(false);
    }
  };

  const addEvidence = (type, refId, title, snapshot) =>
    mutate(
      () =>
        api.post(`/investigations/${activeId}/evidence`, {
          type,
          ref_id: String(refId),
          title,
          snapshot,
        }),
      "Could not add evidence.",
    );

  const selectedHost = hosts.find((host) => String(host.ip) === hostId);
  const selectedFinding = findings.find(
    (finding, index) => findingRef(finding, index) === findingId,
  );
  const evidenceCounts = useMemo(() => {
    const counts = {};
    for (const item of workspace?.evidence || [])
      counts[item.type] = (counts[item.type] || 0) + 1;
    return counts;
  }, [workspace]);
  const workspaceState = describeInvestigationWorkspaceState({
    loading,
    loaded,
    error: loadError,
    caseCount: cases.length,
  });

  if (workspaceState?.tone === "loading")
    return (
      <WorkspaceEmpty
        icon={RefreshCw}
        title={workspaceState.title}
        text={workspaceState.message}
        spinning
      />
    );

  if (workspaceState?.tone === "error")
    return (
      <WorkspaceEmpty
        icon={BriefcaseBusiness}
        title={workspaceState.title}
        text={workspaceState.message}
        actionLabel="Retry"
        onAction={refreshCases}
      />
    );

  return (
    <div className="space-y-5" data-testid="investigation-workspace">
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2 mr-auto">
            <BriefcaseBusiness size={18} />
            <div>
              <h2 className="font-display font-bold">
                Investigation Workspace
              </h2>
              <p className="text-xs text-slate-500">
                Local cases, bookmarks, analyst notes and finding decisions
              </p>
            </div>
          </div>
          {cases.length > 0 && (
            <select
              value={activeId}
              onChange={(event) => selectCase(event.target.value)}
              disabled={saving || loading}
              className="filter-control min-w-[220px]"
              aria-label="Active investigation"
            >
              {cases.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </select>
          )}
          <form onSubmit={createCase} className="flex gap-2">
            <input
              value={caseName}
              onChange={(event) => setCaseName(event.target.value)}
              maxLength={160}
              placeholder="New investigation name"
              className="filter-control min-w-[230px] bg-white text-slate-900 placeholder:text-slate-500 caret-blue-600 border-slate-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/25 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-400 dark:caret-blue-400 dark:border-slate-600"
              aria-label="New investigation name"
            />
            <button
              disabled={saving || !caseName.trim()}
              className="inline-flex items-center gap-1 rounded-md bg-blue-600 px-3 py-2 text-xs font-semibold text-white disabled:opacity-50"
            >
              <Plus size={13} />
              Create
            </button>
          </form>
          {workspace && (
            <button
              onClick={deleteCase}
              disabled={saving}
              className="rounded-md border border-red-200 dark:border-red-900 p-2 text-red-500 disabled:opacity-50"
              aria-label="Delete investigation"
            >
              <Trash2 size={15} />
            </button>
          )}
        </div>
        {loadError && loaded && (
          <div className="mt-3 flex flex-wrap items-center gap-2 rounded-lg border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/30 px-3 py-2 text-xs text-red-600 dark:text-red-300">
            <span className="flex-1">
              {loadError} Keeping previously loaded case data where available.
            </span>
            <button
              type="button"
              onClick={() => refreshCases(activeId)}
              className="font-semibold underline"
            >
              Retry
            </button>
          </div>
        )}
        {actionError && (
          <div className="mt-3 rounded-lg border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/30 px-3 py-2 text-xs text-red-600 dark:text-red-300">
            {actionError}
          </div>
        )}
      </section>

      {!workspace ? (
        <WorkspaceEmpty
          icon={BriefcaseBusiness}
          title={workspaceState?.title || "No investigation selected"}
          text={
            workspaceState?.message ||
            "Select an available local investigation to continue."
          }
        />
      ) : (
        <>
          <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Metric label="Evidence" value={workspace.evidence?.length} />
            <Metric label="Notes" value={workspace.notes?.length} />
            <Metric
              label="Findings tracked"
              value={Object.keys(workspace.finding_states || {}).length}
            />
            <Metric
              label="Last updated"
              value={formatTime(workspace.updated_at)}
              text
            />
          </section>

          <ReportExports workspaceId={workspace.id} />

          <section className="grid grid-cols-1 2xl:grid-cols-3 gap-5 items-start">
            <Panel
              title="Add observed evidence"
              icon={BookmarkPlus}
              className="xl:col-span-2"
            >
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
                <EvidencePicker
                  title="Selected packet"
                  icon={FileText}
                  description={
                    selectedPacket
                      ? `#${selectedPacket.number || selectedPacket.id} · ${selectedPacket.protocol || "packet"} · ${selectedPacket.src_ip || "?"} → ${selectedPacket.dst_ip || "?"}`
                      : "Select a packet in Packet Stream first."
                  }
                  disabled={!selectedPacket || saving}
                  onAdd={() =>
                    addEvidence(
                      "packet",
                      selectedPacket.id,
                      `Packet #${selectedPacket.number || selectedPacket.id}`,
                      selectedPacket,
                    )
                  }
                />
                <EvidencePicker
                  title="Observed host"
                  icon={Server}
                  description={
                    selectedHost
                      ? `${selectedHost.ip} · ${selectedHost.hostname || selectedHost.mac || "observed host"}`
                      : "Choose a host from current intelligence."
                  }
                  disabled={!selectedHost || saving}
                  onAdd={() =>
                    addEvidence(
                      "host",
                      selectedHost.ip,
                      selectedHost.hostname || selectedHost.ip,
                      selectedHost,
                    )
                  }
                >
                  <select
                    value={hostId}
                    onChange={(event) => setHostId(event.target.value)}
                    className="filter-control w-full"
                  >
                    <option value="">Choose host</option>
                    {hosts.map((host) => (
                      <option key={host.ip} value={host.ip}>
                        {host.ip}
                        {host.hostname ? ` · ${host.hostname}` : ""}
                      </option>
                    ))}
                  </select>
                </EvidencePicker>
                <EvidencePicker
                  title="Security finding"
                  icon={ShieldCheck}
                  description={
                    selectedFinding
                      ? selectedFinding.title || selectedFinding.type
                      : "Choose a current defensive finding."
                  }
                  disabled={!selectedFinding || saving}
                  onAdd={() =>
                    addEvidence(
                      "finding",
                      findingId,
                      selectedFinding.title ||
                        selectedFinding.type ||
                        "Security finding",
                      selectedFinding,
                    )
                  }
                >
                  <select
                    value={findingId}
                    onChange={(event) => setFindingId(event.target.value)}
                    className="filter-control w-full"
                  >
                    <option value="">Choose finding</option>
                    {findings.map((finding, index) => (
                      <option
                        key={findingRef(finding, index)}
                        value={findingRef(finding, index)}
                      >
                        {finding.severity || "info"} ·{" "}
                        {finding.title || finding.type || "Finding"}
                      </option>
                    ))}
                  </select>
                </EvidencePicker>
              </div>
            </Panel>

            <Panel title="Analyst note" icon={StickyNote}>
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  if (!note.trim()) return;
                  mutate(
                    () =>
                      api.post(`/investigations/${activeId}/notes`, {
                        text: note.trim(),
                      }),
                    "Could not save the note.",
                  ).then((saved) => {
                    if (saved) setNote("");
                  });
                }}
              >
                <textarea
                  value={note}
                  onChange={(event) => setNote(event.target.value)}
                  maxLength={10000}
                  rows={5}
                  placeholder="Record an observation, hypothesis or next step…"
                  className="filter-control w-full resize-y"
                />
                <button
                  disabled={saving || !note.trim()}
                  className="mt-2 w-full rounded-md bg-slate-900 dark:bg-blue-600 px-3 py-2 text-xs font-semibold text-white disabled:opacity-50"
                >
                  Add note
                </button>
              </form>
            </Panel>
          </section>

          <section className="grid grid-cols-1 2xl:grid-cols-3 gap-5 items-start">
            <Panel
              title="Evidence locker"
              icon={BookmarkPlus}
              className="xl:col-span-2"
              badge={`${workspace.evidence?.length || 0} items`}
            >
              <div className="flex flex-wrap gap-1 mb-3">
                {Object.entries(evidenceCounts).map(([type, count]) => (
                  <span
                    key={type}
                    className="rounded-full bg-slate-100 dark:bg-slate-800 px-2 py-1 text-[10px] uppercase"
                  >
                    {type} {count}
                  </span>
                ))}
              </div>
              <div className="max-h-[430px] overflow-auto el-scroll divide-y divide-slate-100 dark:divide-slate-800">
                {(workspace.evidence || []).map((item) => (
                  <div key={item.id} className="py-3 flex gap-3 items-start">
                    <span className="rounded bg-blue-50 dark:bg-blue-500/10 px-2 py-1 text-[10px] font-bold uppercase text-blue-600">
                      {item.type}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-semibold truncate">
                        {item.title || item.ref_id}
                      </div>
                      <div className="text-[11px] text-slate-500 font-mono-code truncate">
                        {item.ref_id}
                      </div>
                      {item.note && (
                        <div className="text-xs text-slate-500 mt-1">
                          {item.note}
                        </div>
                      )}
                    </div>
                    {item.type === "packet" && (
                      <button
                        onClick={() =>
                          onOpenPacket?.(item.snapshot?.id || item.ref_id)
                        }
                        className="text-xs text-blue-600"
                      >
                        open
                      </button>
                    )}
                    <button
                      onClick={() =>
                        mutate(
                          () =>
                            api.delete(
                              `/investigations/${activeId}/evidence/${item.id}`,
                            ),
                          "Could not remove evidence.",
                        )
                      }
                      disabled={saving}
                      className="text-slate-400 hover:text-red-500"
                      aria-label={`Remove ${item.title || item.ref_id}`}
                    >
                      <X size={14} />
                    </button>
                  </div>
                ))}
                {!workspace.evidence?.length && (
                  <Empty text="No evidence bookmarked yet." />
                )}
              </div>
            </Panel>

            <div className="space-y-4">
              <Panel title="Finding lifecycle" icon={ShieldCheck}>
                <div className="space-y-3 max-h-64 overflow-auto el-scroll">
                  {(workspace.evidence || [])
                    .filter((item) => item.type === "finding")
                    .map((item) => {
                      const current =
                        workspace.finding_states?.[item.ref_id]?.state || "new";
                      return (
                        <div key={item.id}>
                          <div className="text-xs font-semibold truncate">
                            {item.title || item.ref_id}
                          </div>
                          <select
                            value={current}
                            onChange={(event) =>
                              mutate(
                                () =>
                                  api.put(
                                    `/investigations/${activeId}/findings/${encodeURIComponent(item.ref_id)}/state`,
                                    { state: event.target.value },
                                  ),
                                "Could not update finding state.",
                              )
                            }
                            disabled={saving}
                            className="filter-control w-full mt-1"
                          >
                            {FINDING_STATES.map((state) => (
                              <option key={state} value={state}>
                                {stateLabel(state)}
                              </option>
                            ))}
                          </select>
                        </div>
                      );
                    })}
                  {!(workspace.evidence || []).some(
                    (item) => item.type === "finding",
                  ) && (
                    <Empty text="Add a finding to track its investigation state." />
                  )}
                </div>
              </Panel>
              <Panel
                title="Case notes"
                icon={StickyNote}
                badge={`${workspace.notes?.length || 0}`}
              >
                <div className="space-y-2 max-h-64 overflow-auto el-scroll">
                  {(workspace.notes || [])
                    .slice()
                    .reverse()
                    .map((item) => (
                      <div
                        key={item.id}
                        className="rounded-lg bg-slate-50 dark:bg-slate-800 p-3"
                      >
                        <div className="text-xs whitespace-pre-wrap">
                          {item.text}
                        </div>
                        <div className="text-[10px] text-slate-500 mt-2">
                          {item.author} · {formatTime(item.created_at)}
                        </div>
                      </div>
                    ))}
                  {!workspace.notes?.length && (
                    <Empty text="No analyst notes yet." />
                  )}
                </div>
              </Panel>
            </div>
          </section>
        </>
      )}
    </div>
  );
}

function Panel({ title, icon: Icon, badge, className = "", children }) {
  return (
    <div
      className={`rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 ${className}`}
    >
      <div className="flex items-center gap-2 mb-3">
        <Icon size={15} />
        <h3 className="font-display font-bold text-sm">{title}</h3>
        {badge && (
          <span className="ml-auto text-[10px] text-slate-500">{badge}</span>
        )}
      </div>
      {children}
    </div>
  );
}
function EvidencePicker({
  title,
  icon: Icon,
  description,
  disabled,
  onAdd,
  children,
}) {
  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-3">
      <div className="flex items-center gap-2 text-xs font-semibold">
        <Icon size={14} />
        {title}
      </div>
      {children && <div className="mt-2">{children}</div>}
      <p className="text-[11px] text-slate-500 mt-2 min-h-[32px]">
        {description}
      </p>
      <button
        type="button"
        onClick={onAdd}
        disabled={disabled}
        className="mt-2 w-full rounded-md bg-blue-600 px-2 py-1.5 text-xs font-semibold text-white disabled:opacity-40"
      >
        Add to case
      </button>
    </div>
  );
}
function Metric({ label, value, text }) {
  return (
    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
      <div className="text-[10px] uppercase tracking-wider text-slate-500">
        {label}
      </div>
      <div className={`${text ? "text-sm" : "text-2xl"} font-bold mt-1`}>
        {text ? value : Number(value || 0).toLocaleString()}
      </div>
    </div>
  );
}
function WorkspaceEmpty({
  icon: Icon,
  title,
  text,
  spinning,
  actionLabel,
  onAction,
}) {
  return (
    <div className="rounded-xl border border-dashed border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 p-12 text-center">
      <Icon
        size={32}
        className={`mx-auto text-slate-400 ${spinning ? "animate-spin" : ""}`}
      />
      <h2 className="font-display font-bold mt-3">{title}</h2>
      <p className="text-sm text-slate-500 mt-2">{text}</p>
      {actionLabel && onAction && (
        <button
          type="button"
          onClick={() => onAction()}
          className="mt-4 rounded-md bg-blue-600 px-3 py-2 text-xs font-semibold text-white"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}
function Empty({ text }) {
  return <div className="py-8 text-center text-xs text-slate-400">{text}</div>;
}
function findingRef(finding, index) {
  return String(
    finding.id || finding.packet_id || `${finding.type || "finding"}-${index}`,
  );
}
function stateLabel(value) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}
function message(error, fallback) {
  return error?.response?.data?.detail || error?.message || fallback;
}

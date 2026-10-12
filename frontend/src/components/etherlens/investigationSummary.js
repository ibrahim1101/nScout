export function mergeInvestigationSummary(cases = [], workspace) {
  if (!workspace?.id) return cases;

  const existing = cases.find((item) => item.id === workspace.id) || {};
  const evidence = Object.fromEntries(
    Object.keys(existing.evidence || {})
      .filter((key) => key !== "total")
      .map((key) => [key, 0]),
  );
  evidence.total = 0;

  for (const item of workspace.evidence || []) {
    const type = item?.type || "unknown";
    evidence[type] = (evidence[type] || 0) + 1;
    evidence.total += 1;
  }

  const summary = {
    ...existing,
    id: workspace.id,
    name: workspace.name,
    description: workspace.description || "",
    created_at: workspace.created_at,
    updated_at: workspace.updated_at,
    evidence,
    note_count: (workspace.notes || []).length,
    finding_count: Object.keys(workspace.finding_states || {}).length,
  };

  return [summary, ...cases.filter((item) => item.id !== workspace.id)].sort(
    (left, right) =>
      String(right.updated_at || "").localeCompare(
        String(left.updated_at || ""),
      ),
  );
}

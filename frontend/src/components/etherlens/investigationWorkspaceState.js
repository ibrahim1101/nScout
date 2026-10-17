export function describeInvestigationWorkspaceState({
  loading = false,
  loaded = false,
  error = "",
  caseCount = 0,
} = {}) {
  if (!loaded && error) {
    return {
      tone: "error",
      title: "Investigations unavailable",
      message: error,
    };
  }

  if (!loaded) {
    return {
      tone: "loading",
      title: loading ? "Loading investigations…" : "Waiting for investigations",
      message: "Restoring local case metadata and evidence.",
    };
  }

  if (caseCount === 0) {
    return {
      tone: "empty",
      title: "Create your first investigation",
      message: "Cases are stored locally and remain available without MongoDB.",
    };
  }

  return null;
}

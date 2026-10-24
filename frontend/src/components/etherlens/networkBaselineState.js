export function describeNetworkBaselineState({
  loading = false,
  loaded = false,
  error = "",
  baselineCount = 0,
} = {}) {
  if (!loaded && error) {
    return {
      tone: "error",
      title: "Network baselines unavailable",
      message: error,
    };
  }

  if (!loaded) {
    return {
      tone: "loading",
      title: loading ? "Loading network baselines…" : "Waiting for baselines",
      message: "nScout is requesting saved baseline metadata from local storage.",
    };
  }

  if (error) {
    return {
      tone: "warning",
      title:
        baselineCount > 0
          ? "Showing the last loaded baselines"
          : "Baseline refresh failed",
      message: error,
    };
  }

  if (baselineCount === 0) {
    return {
      tone: "empty",
      title: "No saved network baselines",
      message:
        "Capture or import traffic, then save its metadata as a comparison baseline.",
    };
  }

  return null;
}

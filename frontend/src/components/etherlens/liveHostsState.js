export function describeLiveHostsState({
  hostCount = 0,
  visibleCount = 0,
  loading = false,
  loaded = false,
  error = "",
  filtersActive = false,
} = {}) {
  if (!loaded && error) {
    return {
      tone: "error",
      title: "Live Hosts unavailable",
      message: error,
    };
  }

  if (!loaded) {
    return {
      tone: "loading",
      title: loading ? "Loading observed hosts" : "Waiting for host inventory",
      message:
        "nScout is requesting observed host metadata from the local backend.",
    };
  }

  if (hostCount > 0 && visibleCount === 0 && filtersActive) {
    return {
      tone: "filtered",
      title: "No hosts match these filters",
      message: `${hostCount.toLocaleString()} observed host${hostCount === 1 ? " is" : "s are"} loaded, but the current search, activity or watchlist filters exclude ${hostCount === 1 ? "it" : "them"}.`,
    };
  }

  return {
    tone: "empty",
    title: "No hosts observed",
    message:
      "The current capture evidence has not identified any hosts yet. Passive capture cannot prove that a silent host is offline.",
  };
}

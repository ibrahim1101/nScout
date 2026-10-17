const PANEL_EMPTY_COPY = {
  connections: {
    title: "No reconstructed connections",
    message:
      "No bidirectional connections are available from the current capture evidence.",
  },
  hosts: {
    title: "No observed hosts",
    message: "No hosts have been identified in the current capture evidence.",
  },
  timeline: {
    title: "No correlated timeline events",
    message:
      "No DNS, connection, HTTP, TLS or finding events are available to correlate.",
  },
  dns: {
    title: "No DNS traffic observed",
    message:
      "The current capture contains no decoded DNS queries or responses.",
  },
  http: {
    title: "No visible HTTP traffic",
    message:
      "No unencrypted HTTP metadata was observed. Encrypted HTTPS payload remains unavailable here.",
  },
  tls: {
    title: "No TLS metadata observed",
    message:
      "The current capture contains no observable TLS handshake or record metadata.",
  },
  security: {
    title: "No defensive findings",
    message:
      "No investigation leads were generated from the currently loaded evidence.",
  },
};

export function describeIntelligenceEmptyState({
  panel,
  loading = false,
  loaded = false,
  error = "",
  filtered = false,
} = {}) {
  if (!loaded && error) {
    return {
      tone: "error",
      title: "Intelligence data unavailable",
      message: error,
    };
  }

  if (!loaded) {
    return {
      tone: "loading",
      title: loading ? "Loading intelligence" : "Waiting for intelligence",
      message:
        "nScout is requesting the current capture intelligence from the local backend.",
    };
  }

  if (filtered) {
    return {
      tone: "filtered",
      title: "No intelligence matches these filters",
      message:
        "Evidence is loaded, but the current panel filters exclude every matching record.",
    };
  }

  return {
    tone: "empty",
    ...(PANEL_EMPTY_COPY[panel] || {
      title: "No intelligence available",
      message: "No records are available from the current capture evidence.",
    }),
  };
}

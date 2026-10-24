export function describeCaptureSessionsState({
  loading = false,
  loaded = false,
  error = "",
  sessionCount = 0,
} = {}) {
  if (!loaded && error) {
    return {
      tone: "error",
      title: "Saved sessions unavailable",
      message: error,
    };
  }

  if (!loaded) {
    return {
      tone: "loading",
      title: loading ? "Loading saved sessions…" : "Waiting for saved sessions",
      message: "nScout is requesting local capture-session metadata.",
    };
  }

  if (error) {
    return {
      tone: "warning",
      title: "Showing the last loaded sessions",
      message: error,
    };
  }

  if (sessionCount === 0) {
    return {
      tone: "empty",
      title: "No saved sessions yet",
      message: 'Capture or import traffic, then choose "Save current".',
    };
  }

  return null;
}

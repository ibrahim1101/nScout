export function describePcapComparisonState({
  baselineSelected = false,
  currentSelected = false,
  loading = false,
  error = "",
  hasResult = false,
} = {}) {
  if (loading) {
    return {
      tone: "loading",
      title: "Comparing captures…",
      message: "nScout is analyzing both files in isolated comparison contexts.",
    };
  }

  if (error) {
    return {
      tone: hasResult ? "warning" : "error",
      title: hasResult
        ? "Showing the last successful comparison"
        : "PCAP comparison failed",
      message: error,
    };
  }

  if (hasResult) return null;

  if (!baselineSelected && !currentSelected) {
    return {
      tone: "empty",
      title: "Select two captures to compare",
      message: "Choose a baseline capture and a current capture. The active nScout session will not be replaced.",
    };
  }

  if (!baselineSelected || !currentSelected) {
    return {
      tone: "empty",
      title: baselineSelected
        ? "Select a current capture"
        : "Select a baseline capture",
      message: "Both files are required before comparison can begin.",
    };
  }

  return {
    tone: "ready",
    title: "Ready to compare",
    message: "Both captures are selected. Start the bounded, side-effect-free comparison when ready.",
  };
}

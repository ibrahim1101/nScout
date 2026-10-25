export function describePacketEmptyState(status = {}) {
  const health = status.capture_health || {};
  const totalPackets = Number(status.total_packets || 0);

  if (health.state === "error") {
    return {
      tone: "error",
      title: "Live capture unavailable",
      message:
        health.reason ||
        "The selected interface could not start. Check capture permissions and backend availability.",
    };
  }

  if (totalPackets > 0) {
    return {
      tone: "filtered",
      title: "No packets match the current filters",
      message: `${totalPackets.toLocaleString()} captured packet${totalPackets === 1 ? " exists" : "s exist"}, but none match the current search and protocol filters.`,
    };
  }

  if (status.running) {
    const warning = health.state === "warning" ? health.reason : "";
    return {
      tone: warning ? "warning" : "waiting",
      title: "Capture is running",
      message:
        warning ||
        (status.mode === "simulated"
          ? "Explicit simulation is running; waiting for the first generated packet."
          : "No packets have arrived yet. This can be normal on a quiet interface."),
    };
  }

  if (["pcap", "replay"].includes(status.mode)) {
    return {
      tone: "empty",
      title: "No packets in this capture",
      message:
        "The imported or replayed capture contains no readable packets. The source file remains unchanged.",
    };
  }

  return {
    tone: "idle",
    title: "No capture evidence loaded",
    message: "Start a live capture or import a PCAP/PCAPNG file to begin.",
  };
}

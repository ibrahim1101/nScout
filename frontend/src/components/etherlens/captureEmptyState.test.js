import { describePacketEmptyState } from "./captureEmptyState";

test("shows the backend reason for an honest capture error", () => {
  expect(
    describePacketEmptyState({
      running: false,
      mode: "error",
      capture_health: { state: "error", reason: "Capture permission denied." },
    }),
  ).toEqual({
    tone: "error",
    title: "Live capture unavailable",
    message: "Capture permission denied.",
  });
});

test("distinguishes filtered results from an empty capture", () => {
  const state = describePacketEmptyState({
    running: true,
    mode: "live",
    total_packets: 42,
    capture_health: { state: "healthy" },
  });

  expect(state.tone).toBe("filtered");
  expect(state.message).toContain("42 captured packets exist");
});

test("describes a quiet running interface without claiming failure", () => {
  expect(
    describePacketEmptyState({
      running: true,
      mode: "live",
      total_packets: 0,
      capture_health: { state: "healthy" },
    }),
  ).toMatchObject({
    tone: "waiting",
    title: "Capture is running",
  });
});

test("preserves a no-packet warning from capture diagnostics", () => {
  const state = describePacketEmptyState({
    running: true,
    mode: "live",
    capture_health: {
      state: "warning",
      reason: "Capture is running but no packets have arrived yet.",
    },
  });

  expect(state).toMatchObject({
    tone: "warning",
    message: "Capture is running but no packets have arrived yet.",
  });
});

test("distinguishes an empty imported capture from the idle workspace", () => {
  expect(describePacketEmptyState({ mode: "pcap" }).title).toBe(
    "No packets in this capture",
  );
  expect(describePacketEmptyState({ mode: "idle" }).title).toBe(
    "No capture evidence loaded",
  );
});

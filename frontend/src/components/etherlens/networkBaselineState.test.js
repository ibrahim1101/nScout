import { describeNetworkBaselineState } from "./networkBaselineState";

test("describes the initial baseline request as loading", () => {
  expect(describeNetworkBaselineState({ loading: true })).toMatchObject({
    tone: "loading",
    title: "Loading network baselines…",
  });
});

test("does not present a first-load store failure as no saved baselines", () => {
  expect(
    describeNetworkBaselineState({ error: "Baseline store did not respond." }),
  ).toEqual({
    tone: "error",
    title: "Network baselines unavailable",
    message: "Baseline store did not respond.",
  });
});

test("describes a successfully loaded empty baseline store", () => {
  expect(describeNetworkBaselineState({ loaded: true })).toMatchObject({
    tone: "empty",
    title: "No saved network baselines",
  });
});

test("labels retained baselines after a transient refresh failure", () => {
  expect(
    describeNetworkBaselineState({
      loaded: true,
      error: "Refresh failed.",
      baselineCount: 2,
    }),
  ).toEqual({
    tone: "warning",
    title: "Showing the last loaded baselines",
    message: "Refresh failed.",
  });
});

test("returns no status panel for a current non-empty list", () => {
  expect(
    describeNetworkBaselineState({ loaded: true, baselineCount: 1 }),
  ).toBeNull();
});

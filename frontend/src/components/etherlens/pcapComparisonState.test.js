import { describePcapComparisonState } from "./pcapComparisonState";

test("asks for both captures before comparison", () => {
  expect(describePcapComparisonState()).toMatchObject({
    tone: "empty",
    title: "Select two captures to compare",
  });
});

test("identifies the missing current capture", () => {
  expect(
    describePcapComparisonState({ baselineSelected: true }),
  ).toMatchObject({
    tone: "empty",
    title: "Select a current capture",
  });
});

test("identifies the missing baseline capture", () => {
  expect(
    describePcapComparisonState({ currentSelected: true }),
  ).toMatchObject({
    tone: "empty",
    title: "Select a baseline capture",
  });
});

test("describes a complete selection as ready", () => {
  expect(
    describePcapComparisonState({
      baselineSelected: true,
      currentSelected: true,
    }),
  ).toMatchObject({ tone: "ready", title: "Ready to compare" });
});

test("describes an in-flight comparison as loading", () => {
  expect(describePcapComparisonState({ loading: true })).toMatchObject({
    tone: "loading",
    title: "Comparing captures…",
  });
});

test("does not present a failed first comparison as an empty result", () => {
  expect(describePcapComparisonState({ error: "Parser unavailable." })).toEqual({
    tone: "error",
    title: "PCAP comparison failed",
    message: "Parser unavailable.",
  });
});

test("labels retained results after a failed retry", () => {
  expect(
    describePcapComparisonState({
      error: "Retry timed out.",
      hasResult: true,
    }),
  ).toEqual({
    tone: "warning",
    title: "Showing the last successful comparison",
    message: "Retry timed out.",
  });
});

test("returns no status panel for a current result", () => {
  expect(describePcapComparisonState({ hasResult: true })).toBeNull();
});

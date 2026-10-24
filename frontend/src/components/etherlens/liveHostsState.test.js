import { describeLiveHostsState } from "./liveHostsState";

test("describes the initial host request as loading", () => {
  expect(describeLiveHostsState({ loading: true })).toMatchObject({
    tone: "loading",
    title: "Loading observed hosts",
  });
});

test("does not present a backend failure as an empty host inventory", () => {
  expect(
    describeLiveHostsState({ error: "Host service did not respond." }),
  ).toEqual({
    tone: "error",
    title: "Live Hosts unavailable",
    message: "Host service did not respond.",
  });
});

test("describes a successfully loaded capture with no observed hosts", () => {
  const state = describeLiveHostsState({ loaded: true });

  expect(state.tone).toBe("empty");
  expect(state.title).toBe("No hosts observed");
  expect(state.message).toContain("cannot prove that a silent host is offline");
});

test("distinguishes filters that hide loaded hosts", () => {
  expect(
    describeLiveHostsState({
      hostCount: 3,
      visibleCount: 0,
      loaded: true,
      filtersActive: true,
    }),
  ).toEqual({
    tone: "filtered",
    title: "No hosts match these filters",
    message:
      "3 observed hosts are loaded, but the current search, activity or watchlist filters exclude them.",
  });
});

test("uses singular grammar for one filtered host", () => {
  expect(
    describeLiveHostsState({
      hostCount: 1,
      visibleCount: 0,
      loaded: true,
      filtersActive: true,
    }).message,
  ).toContain("1 observed host is loaded");
});

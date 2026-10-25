import { describeIntelligenceEmptyState } from "./intelligenceEmptyState";

test("distinguishes initial loading from a genuine empty result", () => {
  expect(
    describeIntelligenceEmptyState({ panel: "connections", loading: true }),
  ).toMatchObject({ tone: "loading", title: "Loading intelligence" });

  expect(
    describeIntelligenceEmptyState({ panel: "connections", loaded: true }),
  ).toMatchObject({ tone: "empty", title: "No reconstructed connections" });
});

test("preserves a backend load failure instead of claiming there is no data", () => {
  expect(
    describeIntelligenceEmptyState({
      panel: "dns",
      error: "Local backend did not respond.",
    }),
  ).toEqual({
    tone: "error",
    title: "Intelligence data unavailable",
    message: "Local backend did not respond.",
  });
});

test("explains HTTP visibility limits without claiming encrypted payload access", () => {
  const state = describeIntelligenceEmptyState({ panel: "http", loaded: true });

  expect(state.tone).toBe("empty");
  expect(state.message).toContain("unencrypted HTTP metadata");
  expect(state.message).toContain(
    "Encrypted HTTPS payload remains unavailable",
  );
});

test("distinguishes filter-zero results from absent TLS evidence", () => {
  expect(
    describeIntelligenceEmptyState({
      panel: "tls",
      loaded: true,
      filtered: true,
    }),
  ).toMatchObject({
    tone: "filtered",
    title: "No intelligence matches these filters",
  });

  expect(
    describeIntelligenceEmptyState({ panel: "tls", loaded: true }),
  ).toMatchObject({ tone: "empty", title: "No TLS metadata observed" });
});

test("uses evidence-specific copy for clean security results", () => {
  expect(
    describeIntelligenceEmptyState({ panel: "security", loaded: true }),
  ).toMatchObject({
    tone: "empty",
    title: "No defensive findings",
  });
});

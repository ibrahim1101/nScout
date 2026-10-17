import { describeInvestigationWorkspaceState } from "./investigationWorkspaceState";

test("describes the initial case request as loading", () => {
  expect(describeInvestigationWorkspaceState({ loading: true })).toEqual({
    tone: "loading",
    title: "Loading investigations…",
    message: "Restoring local case metadata and evidence.",
  });
});

test("does not present a first-load backend failure as an empty case store", () => {
  expect(
    describeInvestigationWorkspaceState({
      error: "Local case store did not respond.",
    }),
  ).toEqual({
    tone: "error",
    title: "Investigations unavailable",
    message: "Local case store did not respond.",
  });
});

test("describes a successfully loaded empty case store", () => {
  expect(describeInvestigationWorkspaceState({ loaded: true })).toEqual({
    tone: "empty",
    title: "Create your first investigation",
    message: "Cases are stored locally and remain available without MongoDB.",
  });
});

test("returns no blocking state when a loaded case exists", () => {
  expect(
    describeInvestigationWorkspaceState({ loaded: true, caseCount: 2 }),
  ).toBeNull();
});

test("keeps loaded data non-blocking during a transient refresh failure", () => {
  expect(
    describeInvestigationWorkspaceState({
      loaded: true,
      caseCount: 1,
      error: "Refresh failed.",
    }),
  ).toBeNull();
});

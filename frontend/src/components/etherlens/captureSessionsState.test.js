import { describeCaptureSessionsState } from "./captureSessionsState";

test("describes the initial session request as loading", () => {
  expect(describeCaptureSessionsState({ loading: true })).toMatchObject({
    tone: "loading",
    title: "Loading saved sessions…",
  });
});

test("does not present a first-load backend failure as an empty session store", () => {
  expect(
    describeCaptureSessionsState({ error: "Session service did not respond." }),
  ).toEqual({
    tone: "error",
    title: "Saved sessions unavailable",
    message: "Session service did not respond.",
  });
});

test("describes a successfully loaded empty session store", () => {
  expect(describeCaptureSessionsState({ loaded: true })).toMatchObject({
    tone: "empty",
    title: "No saved sessions yet",
  });
});

test("labels retained sessions after a transient refresh failure", () => {
  expect(
    describeCaptureSessionsState({
      loaded: true,
      error: "Refresh failed.",
      sessionCount: 2,
    }),
  ).toEqual({
    tone: "warning",
    title: "Showing the last loaded sessions",
    message: "Refresh failed.",
  });
});

test("returns no empty-state panel for a current non-empty list", () => {
  expect(
    describeCaptureSessionsState({ loaded: true, sessionCount: 1 }),
  ).toBeNull();
});

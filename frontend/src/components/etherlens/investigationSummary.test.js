import { mergeInvestigationSummary } from "./investigationSummary";

const workspace = {
  id: "case-1",
  name: "DNS review",
  description: "Investigate resolver activity",
  created_at: "2026-10-12T10:00:00Z",
  updated_at: "2026-10-12T12:00:00Z",
  evidence: [
    { type: "packet" },
    { type: "finding" },
    { type: "finding" },
  ],
  notes: [{ id: "note-1" }],
  finding_states: {
    "finding-1": { state: "investigating" },
    "finding-2": { state: "resolved" },
  },
};

test("updates a case summary from a confirmed workspace mutation", () => {
  const result = mergeInvestigationSummary(
    [
      {
        id: "case-1",
        name: "Old name",
        evidence: { total: 1, packet: 0, host: 1 },
        note_count: 0,
        finding_count: 0,
      },
    ],
    workspace,
  );

  expect(result[0]).toMatchObject({
    id: "case-1",
    name: "DNS review",
    updated_at: "2026-10-12T12:00:00Z",
    evidence: { total: 3, packet: 1, host: 0, finding: 2 },
    note_count: 1,
    finding_count: 2,
  });
});

test("moves the most recently updated case to the front", () => {
  const result = mergeInvestigationSummary(
    [
      { id: "case-2", updated_at: "2026-10-12T11:00:00Z" },
      { id: "case-1", updated_at: "2026-10-12T10:00:00Z" },
    ],
    workspace,
  );

  expect(result.map((item) => item.id)).toEqual(["case-1", "case-2"]);
});

test("adds a summary when a confirmed workspace is not in the current list", () => {
  expect(mergeInvestigationSummary([], workspace)).toHaveLength(1);
});

test("preserves summary fields unknown to the client", () => {
  const [result] = mergeInvestigationSummary(
    [{ id: "case-1", server_extension: "preserve-me" }],
    workspace,
  );

  expect(result.server_extension).toBe("preserve-me");
});

test("leaves the list unchanged without a valid confirmed workspace", () => {
  const cases = [{ id: "case-1" }];
  expect(mergeInvestigationSummary(cases, null)).toBe(cases);
  expect(mergeInvestigationSummary(cases, {})).toBe(cases);
});

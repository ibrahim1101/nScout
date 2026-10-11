import {
  ACTIVE_INVESTIGATION_KEY,
  BookmarkError,
  bookmarkActiveInvestigation,
  findingBookmark,
  hostBookmark,
  normalizeEvidenceBookmark,
  readActiveInvestigation,
} from "./investigationBookmarks";

function memoryStorage(value = "") {
  return {
    getItem: (key) => (key === ACTIVE_INVESTIGATION_KEY ? value : null),
  };
}

test("posts bounded evidence to the active investigation", async () => {
  const post = jest.fn().mockResolvedValue({
    data: { investigation: { id: "case/with space" } },
  });
  const result = await bookmarkActiveInvestigation(
    { post },
    {
      type: "host",
      ref_id: `  ${"x".repeat(550)}  `,
      title: `  ${"t".repeat(550)}  `,
      snapshot: { ip: "192.0.2.10" },
    },
    memoryStorage("case/with space"),
  );

  expect(post).toHaveBeenCalledWith(
    "/investigations/case%2Fwith%20space/evidence",
    expect.objectContaining({
      type: "host",
      snapshot: { ip: "192.0.2.10" },
    }),
  );
  expect(result.payload.ref_id).toHaveLength(500);
  expect(result.payload.title).toHaveLength(500);
});

test("requires an active investigation before posting", async () => {
  const post = jest.fn();

  await expect(
    bookmarkActiveInvestigation(
      { post },
      { type: "host", ref_id: "192.0.2.10" },
      memoryStorage(),
    ),
  ).rejects.toMatchObject({ code: "no_active_investigation" });
  expect(post).not.toHaveBeenCalled();
});

test("builds stable host and finding evidence", () => {
  expect(hostBookmark({ ip: "192.0.2.10", alias: "Gateway" })).toMatchObject({
    type: "host",
    ref_id: "192.0.2.10",
    title: "Gateway",
  });
  expect(
    findingBookmark(
      { type: "network.port_scan", packet_id: "packet-7", src_ip: "10.0.0.2" },
      3,
    ),
  ).toMatchObject({
    type: "finding",
    ref_id: "network.port_scan:packet-7:10.0.0.2:3",
  });
});

test("rejects unsupported or empty evidence references", () => {
  expect(() =>
    normalizeEvidenceBookmark({ type: "http", ref_id: "1" }),
  ).toThrow(BookmarkError);
  expect(() =>
    normalizeEvidenceBookmark({ type: "host", ref_id: " " }),
  ).toThrow(BookmarkError);
});

test("treats unavailable browser storage as no active investigation", () => {
  expect(
    readActiveInvestigation({
      getItem: () => {
        throw new Error("blocked");
      },
    }),
  ).toBe("");
});

import {
  ACTIVE_INVESTIGATION_KEY,
  BookmarkError,
  bookmarkActiveInvestigation,
  connectionBookmark,
  dnsBookmark,
  findingBookmark,
  hostBookmark,
  httpBookmark,
  normalizeEvidenceBookmark,
  readActiveInvestigation,
  timelineBookmark,
  tlsBookmark,
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

test("builds deterministic connection evidence independent of endpoint order", () => {
  const forward = connectionBookmark({
    transport: "TCP",
    a_ip: "192.0.2.20",
    a_port: 443,
    b_ip: "192.0.2.10",
    b_port: 51515,
  });
  const reverse = connectionBookmark({
    transport: "TCP",
    a_ip: "192.0.2.10",
    a_port: 51515,
    b_ip: "192.0.2.20",
    b_port: 443,
  });

  expect(forward).toMatchObject({
    type: "connection",
    ref_id: "tcp:192.0.2.10:51515<->192.0.2.20:443",
  });
  expect(reverse.ref_id).toBe(forward.ref_id);
});

test("builds bounded timeline evidence from event identity", () => {
  const evidence = timelineBookmark(
    {
      event_type: "dns_query",
      packet_id: "packet-12",
      timestamp: 1720000000.25,
      src_ip: "192.0.2.10",
      dst_ip: "198.51.100.53",
      title: "DNS query observed",
    },
    4,
  );

  expect(evidence).toMatchObject({
    type: "timeline",
    ref_id: "dns_query:packet-12:1720000000.25:192.0.2.10:198.51.100.53",
    title: "DNS query observed",
  });
});

test("builds DNS, HTTP, and TLS evidence from packet identities", () => {
  expect(
    dnsBookmark({ packet_id: "dns-1", query: "example.test", response: false }),
  ).toMatchObject({
    type: "dns",
    ref_id: "dns-1",
    title: "DNS query: example.test",
  });
  expect(
    httpBookmark({
      packet_id: "http-1",
      method: "GET",
      host: "example.test",
      path: "/health",
    }),
  ).toMatchObject({
    type: "http",
    ref_id: "http-1",
    title: "GET example.test /health",
  });
  expect(
    tlsBookmark({ packet_id: "tls-1", sni: "secure.example.test" }),
  ).toMatchObject({
    type: "tls",
    ref_id: "tls-1",
    title: "TLS: secure.example.test",
  });
});

test("rejects unsupported or empty evidence references", () => {
  expect(() =>
    normalizeEvidenceBookmark({ type: "unsupported", ref_id: "1" }),
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

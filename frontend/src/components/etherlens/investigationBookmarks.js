export const ACTIVE_INVESTIGATION_KEY = "nscout.activeInvestigation";
const EVIDENCE_TYPES = new Set([
  "packet",
  "host",
  "connection",
  "dns",
  "finding",
  "timeline",
]);

export class BookmarkError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "BookmarkError";
    this.code = code;
  }
}

export function readActiveInvestigation(storage = globalThis.localStorage) {
  try {
    return String(storage?.getItem(ACTIVE_INVESTIGATION_KEY) || "").trim();
  } catch (_) {
    return "";
  }
}

export function normalizeEvidenceBookmark(evidence) {
  const type = String(evidence?.type || "").trim();
  const refId = String(evidence?.ref_id ?? "")
    .trim()
    .slice(0, 500);
  if (!EVIDENCE_TYPES.has(type))
    throw new BookmarkError("invalid_type", "Unsupported evidence type.");
  if (!refId)
    throw new BookmarkError(
      "invalid_reference",
      "Evidence reference is required.",
    );
  return {
    type,
    ref_id: refId,
    title: String(evidence?.title || "")
      .trim()
      .slice(0, 500),
    snapshot:
      evidence?.snapshot && typeof evidence.snapshot === "object"
        ? evidence.snapshot
        : {},
  };
}

export async function bookmarkActiveInvestigation(
  apiClient,
  evidence,
  storage = globalThis.localStorage,
) {
  const investigationId = readActiveInvestigation(storage);
  if (!investigationId)
    throw new BookmarkError(
      "no_active_investigation",
      "Create or select an investigation before bookmarking evidence.",
    );
  const payload = normalizeEvidenceBookmark(evidence);
  const response = await apiClient.post(
    `/investigations/${encodeURIComponent(investigationId)}/evidence`,
    payload,
  );
  return {
    investigationId,
    investigation: response.data?.investigation || null,
    payload,
  };
}

export function findingBookmark(finding, index = 0) {
  const refId =
    finding?.id ||
    [
      finding?.type || "finding",
      finding?.packet_id,
      finding?.src || finding?.src_ip,
      finding?.dst || finding?.dst_ip,
      index,
    ]
      .filter((value) => value !== undefined && value !== null && value !== "")
      .join(":");
  return normalizeEvidenceBookmark({
    type: "finding",
    ref_id: refId,
    title: finding?.title || finding?.type || "Security finding",
    snapshot: finding,
  });
}

export function hostBookmark(host) {
  return normalizeEvidenceBookmark({
    type: "host",
    ref_id: host?.ip,
    title: host?.alias || host?.hostname || host?.ip || "Observed host",
    snapshot: host,
  });
}

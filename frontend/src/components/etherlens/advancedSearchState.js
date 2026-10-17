export const ADVANCED_SEARCH_DRAFT_KEY = "nscout.advancedSearchDraft";
export const MAX_ADVANCED_SEARCH_LENGTH = 2048;

export function normalizeAdvancedSearchDraft(value) {
  return String(value ?? "").slice(0, MAX_ADVANCED_SEARCH_LENGTH);
}

export function readAdvancedSearchDraft(storage = globalThis.sessionStorage) {
  try {
    return normalizeAdvancedSearchDraft(
      storage?.getItem(ADVANCED_SEARCH_DRAFT_KEY) || "",
    );
  } catch (_) {
    return "";
  }
}

export function writeAdvancedSearchDraft(
  value,
  storage = globalThis.sessionStorage,
) {
  const normalized = normalizeAdvancedSearchDraft(value);
  try {
    if (normalized) storage?.setItem(ADVANCED_SEARCH_DRAFT_KEY, normalized);
    else storage?.removeItem(ADVANCED_SEARCH_DRAFT_KEY);
  } catch (_) {
    // Search remains usable when browser storage is blocked or full.
  }
  return normalized;
}

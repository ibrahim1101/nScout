const STORAGE_KEY = "nscout.workspace-recovery.v1";
const MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_FILTER_LENGTH = 512;

export const RECOVERABLE_TABS = new Set([
  "analyzer",
  "intelligence",
  "hosts",
  "investigations",
  "pcap",
  "analytics",
  "flows",
  "topology",
  "threats",
]);

const browserStorage = () =>
  typeof window === "undefined" ? null : window.localStorage;

const boundedText = (value) =>
  String(value || "")
    .trim()
    .slice(0, MAX_FILTER_LENGTH);

export function saveWorkspaceRecovery(
  state,
  enabled,
  storage = browserStorage(),
  now = Date.now(),
) {
  if (!storage) return;
  if (!enabled) {
    storage.removeItem(STORAGE_KEY);
    return;
  }
  const tab = RECOVERABLE_TABS.has(state?.tab) ? state.tab : "analyzer";
  storage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      version: 1,
      savedAt: now,
      tab,
      filter: boundedText(state?.filter),
      protocolFilter: boundedText(state?.protocolFilter),
    }),
  );
}

export function readWorkspaceRecovery(
  enabled,
  storage = browserStorage(),
  now = Date.now(),
) {
  if (!storage || !enabled) return null;
  try {
    const value = JSON.parse(storage.getItem(STORAGE_KEY) || "null");
    if (
      !value ||
      value.version !== 1 ||
      !Number.isFinite(value.savedAt) ||
      now - value.savedAt < 0 ||
      now - value.savedAt > MAX_AGE_MS ||
      !RECOVERABLE_TABS.has(value.tab)
    ) {
      storage.removeItem(STORAGE_KEY);
      return null;
    }
    return {
      tab: value.tab,
      filter: boundedText(value.filter),
      protocolFilter: boundedText(value.protocolFilter),
    };
  } catch (_) {
    storage.removeItem(STORAGE_KEY);
    return null;
  }
}

export function clearWorkspaceRecovery(storage = browserStorage()) {
  storage?.removeItem(STORAGE_KEY);
}

export { MAX_AGE_MS, MAX_FILTER_LENGTH, STORAGE_KEY };

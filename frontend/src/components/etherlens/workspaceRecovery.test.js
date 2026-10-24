import {
  MAX_AGE_MS,
  MAX_FILTER_LENGTH,
  STORAGE_KEY,
  readWorkspaceRecovery,
  saveWorkspaceRecovery,
} from "./workspaceRecovery";

function memoryStorage() {
  const values = new Map();
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  };
}

test("persists only bounded workspace navigation metadata", () => {
  const storage = memoryStorage();
  saveWorkspaceRecovery(
    {
      tab: "investigations",
      filter: ` host ${"x".repeat(700)} `,
      protocolFilter: "TLS",
      packets: [{ payload: "secret" }],
      evidence: { snapshot: "secret" },
    },
    true,
    storage,
    1000,
  );
  const raw = JSON.parse(storage.getItem(STORAGE_KEY));
  expect(Object.keys(raw).sort()).toEqual(
    ["filter", "protocolFilter", "savedAt", "tab", "version"].sort(),
  );
  expect(raw.filter.length).toBe(MAX_FILTER_LENGTH);
  expect(readWorkspaceRecovery(true, storage, 1001)).toEqual({
    tab: "investigations",
    filter: raw.filter,
    protocolFilter: "TLS",
  });
  expect(JSON.stringify(raw)).not.toContain("secret");
});

test("rejects expired, future, corrupt and unknown workspace records", () => {
  const storage = memoryStorage();
  storage.setItem(
    STORAGE_KEY,
    JSON.stringify({ version: 1, savedAt: 1, tab: "analyzer" }),
  );
  expect(readWorkspaceRecovery(true, storage, MAX_AGE_MS + 2)).toBeNull();
  storage.setItem(
    STORAGE_KEY,
    JSON.stringify({ version: 1, savedAt: 200, tab: "unknown" }),
  );
  expect(readWorkspaceRecovery(true, storage, 201)).toBeNull();
  storage.setItem(
    STORAGE_KEY,
    JSON.stringify({ version: 1, savedAt: 300, tab: "analyzer" }),
  );
  expect(readWorkspaceRecovery(true, storage, 299)).toBeNull();
  storage.setItem(STORAGE_KEY, "not-json");
  expect(readWorkspaceRecovery(true, storage, 400)).toBeNull();
});

test("disabling recovery removes the saved record", () => {
  const storage = memoryStorage();
  saveWorkspaceRecovery({ tab: "hosts" }, true, storage, 1000);
  saveWorkspaceRecovery({ tab: "hosts" }, false, storage, 1001);
  expect(storage.getItem(STORAGE_KEY)).toBeNull();
  expect(readWorkspaceRecovery(false, storage, 1002)).toBeNull();
});

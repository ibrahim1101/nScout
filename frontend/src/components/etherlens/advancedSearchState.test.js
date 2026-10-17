import {
  ADVANCED_SEARCH_DRAFT_KEY,
  MAX_ADVANCED_SEARCH_LENGTH,
  readAdvancedSearchDraft,
  writeAdvancedSearchDraft,
} from "./advancedSearchState";

function memoryStorage(initial = {}) {
  const values = new Map(Object.entries(initial));
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  };
}

test("restores the current search draft without changing spaces or case", () => {
  const storage = memoryStorage();
  const expression = "  Protocol == TLS AND domain contains Example.COM  ";

  writeAdvancedSearchDraft(expression, storage);

  expect(readAdvancedSearchDraft(storage)).toBe(expression);
});

test("bounds restored drafts", () => {
  const storage = memoryStorage({
    [ADVANCED_SEARCH_DRAFT_KEY]: "x".repeat(MAX_ADVANCED_SEARCH_LENGTH + 50),
  });

  expect(readAdvancedSearchDraft(storage)).toHaveLength(
    MAX_ADVANCED_SEARCH_LENGTH,
  );
});

test("clears the draft when the search field is emptied", () => {
  const storage = memoryStorage({ [ADVANCED_SEARCH_DRAFT_KEY]: "port == 443" });

  expect(writeAdvancedSearchDraft("", storage)).toBe("");
  expect(readAdvancedSearchDraft(storage)).toBe("");
});

test("fails closed when session storage is unavailable", () => {
  const unavailable = {
    getItem: () => {
      throw new Error("blocked");
    },
    setItem: () => {
      throw new Error("blocked");
    },
  };

  expect(readAdvancedSearchDraft(unavailable)).toBe("");
  expect(writeAdvancedSearchDraft("protocol == DNS", unavailable)).toBe(
    "protocol == DNS",
  );
});

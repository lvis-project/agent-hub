import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { clearStoredKey, getStoredKey, setStoredKey } from "../src/lib/auth";

const originalSessionStorage = Object.getOwnPropertyDescriptor(globalThis, "sessionStorage");

beforeEach(() => {
  const values = new Map<string, string>();
  Object.defineProperty(globalThis, "sessionStorage", {
    configurable: true,
    value: {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
      removeItem: (key: string) => values.delete(key),
    },
  });
});

afterEach(() => {
  clearStoredKey();
  if (originalSessionStorage) {
    Object.defineProperty(globalThis, "sessionStorage", originalSessionStorage);
  } else {
    Reflect.deleteProperty(globalThis, "sessionStorage");
  }
});

describe("browser token session", () => {
  it("keeps the API token only in the current browser session", () => {
    setStoredKey("agh_example");
    expect(getStoredKey()).toBe("agh_example");

    clearStoredKey();
    expect(getStoredKey()).toBeNull();
  });
});

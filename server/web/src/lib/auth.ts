/** Session-scoped bearer token. It is cleared when the browser tab closes. */
const STORAGE_KEY = "agent-hub-key";

export function getStoredKey(): string | null {
  if (typeof sessionStorage === "undefined") return null;
  return sessionStorage.getItem(STORAGE_KEY);
}

export function setStoredKey(key: string): void {
  if (typeof sessionStorage === "undefined") return;
  sessionStorage.setItem(STORAGE_KEY, key);
}

export function clearStoredKey(): void {
  if (typeof sessionStorage === "undefined") return;
  sessionStorage.removeItem(STORAGE_KEY);
}

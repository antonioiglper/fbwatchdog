const DEFAULT_TIMEOUT_MS = 10_000;

// Node's fetch sends no browser-like UA by default, which many storefronts
// block outright. A desktop UA mirrors what Python's `requests` gets away with.
export const DEFAULT_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

export async function fetchWithTimeout(
  url: string,
  { timeoutMs = DEFAULT_TIMEOUT_MS, headers, ...init }: RequestInit & { timeoutMs?: number } = {}
): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
      headers: { "User-Agent": DEFAULT_USER_AGENT, ...headers },
    });
  } finally {
    clearTimeout(timeout);
  }
}

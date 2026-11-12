/**
 * Fetching a JWK Set from a URL, the one network call jwtpeek makes, and
 * only for --jwks. HTTPS is required (plain HTTP only for localhost), the
 * response is capped, and nothing about the token is sent.
 */

export const JWKS_TIMEOUT_MS = 10_000;
export const JWKS_MAX_BYTES = 1024 * 1024;

/** Whether a URL may be fetched: https, or http to the local machine. */
export function allowedJwksUrl(url: string): boolean {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (u.protocol === "https:") return true;
  return u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
}

/** Download a JWK Set and return its text. Throws with a short reason. */
export async function fetchJwks(url: string, fetchFn: typeof fetch = fetch): Promise<string> {
  if (!allowedJwksUrl(url)) {
    throw new Error("a JWKS URL must be https:// (http:// only for localhost)");
  }
  let res: Response;
  try {
    res = await fetchFn(url, {
      headers: { accept: "application/jwk-set+json, application/json" },
      signal: AbortSignal.timeout(JWKS_TIMEOUT_MS),
    });
  } catch (err) {
    const why = (err as Error).name === "TimeoutError" ? "timed out" : (err as Error).message;
    throw new Error(`cannot fetch the JWKS: ${why}`, { cause: err });
  }
  if (!res.ok) throw new Error(`cannot fetch the JWKS: HTTP ${res.status}`);
  const text = await res.text();
  if (Buffer.byteLength(text) > JWKS_MAX_BYTES) throw new Error("the JWKS response is larger than 1 MiB");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("the JWKS response is not JSON");
  }
  if (typeof parsed !== "object" || parsed === null || !Array.isArray((parsed as { keys?: unknown }).keys)) {
    throw new Error('the JWKS response has no "keys" array');
  }
  return text;
}

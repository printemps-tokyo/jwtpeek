/**
 * Decode the structure of a JSON Web Token (JWT / JWS compact form).
 *
 * A compact JWT is `base64url(header).base64url(payload).base64url(signature)`.
 * This module only decodes — it never contacts a server — so a token can be
 * inspected without leaking it to an online decoder. Parsing is pure.
 */

/** A decoded JWT. */
export interface Jwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  /** The `header.payload` string that the signature is computed over. */
  signingInput: string;
  /** The signature segment, still base64url-encoded (may be empty). */
  signature: string;
}

/** Decode a base64url string to bytes (tolerating missing padding). */
export function base64UrlDecode(input: string): Buffer {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + pad, "base64");
}

function decodeJsonSegment(segment: string, what: string): Record<string, unknown> {
  let text: string;
  try {
    text = base64UrlDecode(segment).toString("utf8");
  } catch {
    throw new Error(`${what} is not valid base64url`);
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`${what} is not valid JSON`);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${what} is not a JSON object`);
  }
  return value as Record<string, unknown>;
}

/** Parse a compact JWT string into its decoded parts. Throws on malformed input. */
export function parseJwt(token: string): Jwt {
  const parts = token.trim().split(".");
  if (parts.length !== 3) {
    throw new Error(`a compact JWT has 3 dot-separated parts (got ${parts.length})`);
  }
  const [h, p, signature] = parts as [string, string, string];
  return {
    header: decodeJsonSegment(h, "header"),
    payload: decodeJsonSegment(p, "payload"),
    signingInput: `${h}.${p}`,
    signature,
  };
}

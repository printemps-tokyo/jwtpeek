/**
 * Optional signature verification, built on Node's `crypto` (no dependencies).
 *
 * Supports the JWS algorithm families: HMAC (`HS*`) with a shared secret, and
 * RSA (`RS*`), RSA-PSS (`PS*`), ECDSA (`ES*`), and `EdDSA` (Ed25519) with a
 * public key. ECDSA uses the IEEE-P1363 signature encoding that JWS mandates.
 */

import {
  constants,
  createHmac,
  createPublicKey,
  timingSafeEqual,
  verify as cryptoVerify,
  type JsonWebKey,
  type KeyObject,
} from "node:crypto";
import { base64UrlDecode, type Jwt } from "./decode.js";

export interface VerifyResult {
  alg: string;
  verified: boolean;
  /** Why verification could not be performed or failed, when applicable. */
  note?: string;
}

function hashFor(alg: string): string {
  return `sha${alg.slice(2)}`; // HS256 -> sha256
}

/** Verify a JWT's signature with a secret (HS) or a public key (RS, PS, ES, EdDSA). */
export function verifyJwt(jwt: Jwt, opts: { secret?: string; key?: KeyObject }): VerifyResult {
  const alg = typeof jwt.header.alg === "string" ? jwt.header.alg : "";
  const family = alg.slice(0, 2);
  const signature = base64UrlDecode(jwt.signature);
  const data = Buffer.from(jwt.signingInput, "utf8");

  if (alg === "none" || alg === "") {
    return { alg: alg || "(none)", verified: false, note: "algorithm 'none' is unsigned and insecure" };
  }

  if (family === "HS") {
    if (opts.secret === undefined) {
      return { alg, verified: false, note: "HMAC algorithms need --secret" };
    }
    const expected = createHmac(hashFor(alg), opts.secret).update(jwt.signingInput).digest();
    const verified = expected.length === signature.length && timingSafeEqual(expected, signature);
    return { alg, verified };
  }

  if (family === "RS" || family === "PS" || family === "ES") {
    if (opts.key === undefined) {
      return { alg, verified: false, note: "asymmetric algorithms need a public key (--key)" };
    }
    const hash = hashFor(alg);
    let verified: boolean;
    if (family === "PS") {
      verified = cryptoVerify(
        hash,
        data,
        { key: opts.key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST },
        signature,
      );
    } else if (family === "ES") {
      verified = cryptoVerify(hash, data, { key: opts.key, dsaEncoding: "ieee-p1363" }, signature);
    } else {
      verified = cryptoVerify(hash, data, opts.key, signature);
    }
    return { alg, verified };
  }

  if (alg === "EdDSA") {
    if (opts.key === undefined) {
      return { alg, verified: false, note: "asymmetric algorithms need a public key (--key)" };
    }
    // Ed25519 hashes internally, so the digest algorithm is null.
    return { alg, verified: cryptoVerify(null, data, opts.key, signature) };
  }

  return { alg, verified: false, note: `unsupported algorithm "${alg}"` };
}

/**
 * Parse public key material into a KeyObject. Accepts PEM text, or a JWK JSON
 * document (an object with a "kty" field) as produced by JWKS endpoints.
 */
export function parsePublicKey(material: string, header?: Record<string, unknown>): KeyObject {
  const trimmed = material.trim();
  if (trimmed.startsWith("{")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      throw new Error("invalid JWK: not valid JSON");
    }
    // A JWK Set ({"keys": [...]}), as a JWKS endpoint serves it.
    if (typeof parsed === "object" && parsed !== null && Array.isArray((parsed as { keys?: unknown }).keys)) {
      return createPublicKey({ key: selectJwk(parsed as { keys: unknown[] }, header ?? {}), format: "jwk" });
    }
  }
  if (trimmed.startsWith("{")) {
    // Anything that looks like JSON is treated as a JWK; never fall back to
    // PEM, which would surface a misleading PEM-parse error instead.
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      throw new Error("invalid JWK: not valid JSON");
    }
    if (typeof parsed !== "object" || parsed === null || typeof (parsed as { kty?: unknown }).kty !== "string") {
      throw new Error("invalid JWK: missing kty");
    }
    return createPublicKey({ key: parsed as JsonWebKey, format: "jwk" });
  }
  return createPublicKey(material);
}

/** Key types each JWS algorithm family uses (RFC 7518). */
function ktyFor(alg: string): string | undefined {
  if (/^(RS|PS)\d{3}$/.test(alg)) return "RSA";
  if (/^ES\d{3}K?$/.test(alg)) return "EC";
  if (alg === "EdDSA" || alg === "Ed25519" || alg === "Ed448") return "OKP";
  return undefined;
}

/**
 * Pick the key for a token from a JWK Set: the one whose `kid` is the
 * header's `kid`; without a `kid`, the only key that suits the algorithm
 * (right `kty`, an `alg` that is absent or equal, `use` absent or "sig").
 * Anything ambiguous is an error rather than a guess.
 */
export function selectJwk(jwks: { keys: unknown[] }, header: Record<string, unknown>): JsonWebKey {
  const keys = jwks.keys.filter((k): k is Record<string, unknown> => typeof k === "object" && k !== null);
  const kid = typeof header.kid === "string" ? header.kid : undefined;
  const alg = typeof header.alg === "string" ? header.alg : "";
  if (kid !== undefined) {
    const found = keys.filter((k) => k.kid === kid);
    if (found.length === 1) return found[0] as JsonWebKey;
    if (found.length > 1) throw new Error(`the JWK Set has ${found.length} keys with kid "${kid}"`);
    const kids = keys.map((k) => (typeof k.kid === "string" ? k.kid : "(none)")).join(", ");
    throw new Error(`no key with kid "${kid}" in the JWK Set (it has: ${kids || "no keys"})`);
  }
  const kty = ktyFor(alg);
  const fit = keys.filter(
    (k) =>
      (kty === undefined || k.kty === kty) &&
      (k.alg === undefined || k.alg === alg) &&
      (k.use === undefined || k.use === "sig"),
  );
  if (fit.length === 1) return fit[0] as JsonWebKey;
  throw new Error(
    fit.length === 0
      ? `no key in the JWK Set suits ${alg || "the token"}`
      : `the token has no kid and ${fit.length} keys in the JWK Set suit ${alg}; pick one with --key`,
  );
}

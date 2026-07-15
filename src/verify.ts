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
export function parsePublicKey(material: string): KeyObject {
  const trimmed = material.trim();
  if (trimmed.startsWith("{")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      parsed = undefined;
    }
    if (typeof parsed === "object" && parsed !== null && typeof (parsed as { kty?: unknown }).kty === "string") {
      return createPublicKey({ key: parsed as JsonWebKey, format: "jwk" });
    }
  }
  return createPublicKey(material);
}

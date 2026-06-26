/**
 * Optional signature verification, built on Node's `crypto` (no dependencies).
 *
 * Supports the JWS algorithm families: HMAC (`HS*`) with a shared secret, and
 * RSA (`RS*`), RSA-PSS (`PS*`), and ECDSA (`ES*`) with a public key. ECDSA uses
 * the IEEE-P1363 signature encoding that JWS mandates.
 */

import { constants, createHmac, timingSafeEqual, verify as cryptoVerify, type KeyObject } from "node:crypto";
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

/** Verify a JWT's signature with a secret (HS) or a public key (RS, PS, ES). */
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

  return { alg, verified: false, note: `unsupported algorithm "${alg}"` };
}

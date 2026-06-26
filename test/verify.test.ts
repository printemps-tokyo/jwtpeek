import { describe, expect, it } from "vitest";
import { createHmac, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { parseJwt } from "../src/decode.js";
import { verifyJwt } from "../src/verify.js";

const enc = (o: object): string => Buffer.from(JSON.stringify(o)).toString("base64url");

function hsToken(secret: string, alg = "HS256"): string {
  const signingInput = `${enc({ alg, typ: "JWT" })}.${enc({ sub: "1" })}`;
  const hash = `sha${alg.slice(2)}`;
  const sig = createHmac(hash, secret).update(signingInput).digest("base64url");
  return `${signingInput}.${sig}`;
}

describe("verifyJwt — HMAC", () => {
  it("verifies a correct HS256 signature and rejects a wrong secret", () => {
    const token = hsToken("s3cret");
    expect(verifyJwt(parseJwt(token), { secret: "s3cret" }).verified).toBe(true);
    expect(verifyJwt(parseJwt(token), { secret: "wrong" }).verified).toBe(false);
  });

  it("notes when the secret is missing", () => {
    const r = verifyJwt(parseJwt(hsToken("x")), {});
    expect(r.verified).toBe(false);
    expect(r.note).toMatch(/secret/);
  });
});

describe("verifyJwt — ECDSA", () => {
  it("verifies an ES256 signature with a public key (IEEE-P1363)", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const signingInput = `${enc({ alg: "ES256" })}.${enc({ sub: "1" })}`;
    const sig = cryptoSign("sha256", Buffer.from(signingInput), {
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    }).toString("base64url");
    const token = `${signingInput}.${sig}`;
    expect(verifyJwt(parseJwt(token), { key: publicKey }).verified).toBe(true);
  });
});

describe("verifyJwt — none", () => {
  it("reports the unsigned 'none' algorithm as not verified", () => {
    const token = `${enc({ alg: "none" })}.${enc({ sub: "1" })}.`;
    const r = verifyJwt(parseJwt(token), {});
    expect(r.verified).toBe(false);
    expect(r.note).toMatch(/none/);
  });
});

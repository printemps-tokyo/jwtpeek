import { describe, expect, it } from "vitest";
import { createHmac, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { parseJwt } from "../src/decode.js";
import { parsePublicKey, verifyJwt } from "../src/verify.js";

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

function edToken(privateKey: Parameters<typeof cryptoSign>[2]): string {
  const signingInput = `${enc({ alg: "EdDSA", typ: "JWT" })}.${enc({ sub: "1" })}`;
  const sig = cryptoSign(null, Buffer.from(signingInput), privateKey).toString("base64url");
  return `${signingInput}.${sig}`;
}

describe("verifyJwt — EdDSA", () => {
  it("verifies an Ed25519 signature with the matching public key", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const r = verifyJwt(parseJwt(edToken(privateKey)), { key: publicKey });
    expect(r.alg).toBe("EdDSA");
    expect(r.verified).toBe(true);
  });

  it("rejects a signature from a different key and a tampered payload", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const other = generateKeyPairSync("ed25519");
    expect(verifyJwt(parseJwt(edToken(privateKey)), { key: other.publicKey }).verified).toBe(false);

    const { publicKey, privateKey: pk2 } = generateKeyPairSync("ed25519");
    const [header, , sig] = edToken(pk2).split(".");
    const tampered = `${header}.${enc({ sub: "2" })}.${sig}`;
    expect(verifyJwt(parseJwt(tampered), { key: publicKey }).verified).toBe(false);
  });

  it("notes when the public key is missing", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const r = verifyJwt(parseJwt(edToken(privateKey)), {});
    expect(r.verified).toBe(false);
    expect(r.note).toMatch(/--key/);
  });
});

describe("parsePublicKey", () => {
  it("loads a JWK JSON document (object with kty)", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const jwk = JSON.stringify(publicKey.export({ format: "jwk" }));
    const key = parsePublicKey(jwk);
    expect(key.asymmetricKeyType).toBe("ed25519");
    expect(verifyJwt(parseJwt(edToken(privateKey)), { key }).verified).toBe(true);
  });

  it("still loads PEM text", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(parsePublicKey(pem).asymmetricKeyType).toBe("ec");
  });

  it("rejects JSON without a string kty field", () => {
    expect(() => parsePublicKey('{"foo":"bar"}')).toThrow(/invalid JWK: missing kty/);
    expect(() => parsePublicKey('{"kty":123}')).toThrow(/invalid JWK: missing kty/);
  });

  it("rejects malformed JSON without falling back to PEM", () => {
    expect(() => parsePublicKey('{"kty":"OKP"')).toThrow(/invalid JWK: not valid JSON/);
    expect(() => parsePublicKey("{not json}")).toThrow(/invalid JWK: not valid JSON/);
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

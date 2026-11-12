import { describe, expect, it } from "vitest";
import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import {
  allowedJwksUrl,
  fetchJwks,
  isJwe,
  parseJwe,
  parseJwt,
  parsePublicKey,
  selectJwk,
  verifyJwt,
} from "../src/index.js";

const b64u = (b: Buffer | string): string => Buffer.from(b).toString("base64url");

function rsToken(privateKey: KeyObject, header: Record<string, unknown>, payload: Record<string, unknown>): string {
  const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  return `${input}.${b64u(cryptoSign("sha256", Buffer.from(input), privateKey))}`;
}

const a = generateKeyPairSync("rsa", { modulusLength: 2048 });
const b = generateKeyPairSync("rsa", { modulusLength: 2048 });
const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwks = {
  keys: [
    { ...a.publicKey.export({ format: "jwk" }), kid: "a", use: "sig", alg: "RS256" },
    { ...b.publicKey.export({ format: "jwk" }), kid: "b", use: "sig", alg: "RS256" },
    { ...ec.publicKey.export({ format: "jwk" }), kid: "e" },
  ],
};

describe("JWK Sets", () => {
  it("verify with the key the token's kid names", () => {
    const token = rsToken(b.privateKey, { alg: "RS256", kid: "b" }, { sub: "1" });
    const jwt = parseJwt(token);
    const key = parsePublicKey(JSON.stringify(jwks), jwt.header);
    expect(verifyJwt(jwt, { key }).verified).toBe(true);
    // The wrong kid's key does not verify it.
    const other = parsePublicKey(JSON.stringify(jwks), { alg: "RS256", kid: "a" });
    expect(verifyJwt(jwt, { key: other }).verified).toBe(false);
  });

  it("refuses to guess", () => {
    expect(() => selectJwk(jwks, { alg: "RS256", kid: "zzz" })).toThrow(/no key with kid "zzz".*a, b, e/);
    expect(() => selectJwk(jwks, { alg: "RS256" })).toThrow(/2 keys in the JWK Set suit RS256/);
    expect(selectJwk(jwks, { alg: "ES256" }).kty).toBe("EC");
    expect(() => selectJwk({ keys: [] }, { alg: "RS256" })).toThrow(/no key/);
  });

  it("are fetched over https only, but localhost may use http", async () => {
    expect(allowedJwksUrl("https://example.com/jwks.json")).toBe(true);
    expect(allowedJwksUrl("http://127.0.0.1:8080/jwks")).toBe(true);
    expect(allowedJwksUrl("http://example.com/jwks.json")).toBe(false);
    expect(allowedJwksUrl("file:///etc/passwd")).toBe(false);
    await expect(fetchJwks("http://example.com/x")).rejects.toThrow(/https/);
    const ok = (async () => new Response(JSON.stringify(jwks))) as unknown as typeof fetch;
    expect(JSON.parse(await fetchJwks("https://idp.example/jwks", ok)).keys).toHaveLength(3);
    const notJwks = (async () => new Response('{"issuer":"x"}')) as unknown as typeof fetch;
    await expect(fetchJwks("https://idp.example/jwks", notJwks)).rejects.toThrow(/"keys"/);
    const down = (async () => new Response("no", { status: 503 })) as unknown as typeof fetch;
    await expect(fetchJwks("https://idp.example/jwks", down)).rejects.toThrow(/HTTP 503/);
  });
});

describe("JWE", () => {
  // The protected header of the JWE in RFC 7516, appendix A.1.
  const header = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ";
  const token = `${header}.${b64u(Buffer.alloc(256))}.${b64u(Buffer.alloc(12))}.${b64u(Buffer.alloc(100))}.${b64u(Buffer.alloc(16))}`;

  it("shows the header and the sizes of the other parts", () => {
    expect(isJwe(token)).toBe(true);
    expect(isJwe("a.b.c")).toBe(false);
    const jwe = parseJwe(token);
    expect(jwe.header).toEqual({ alg: "RSA-OAEP", enc: "A256GCM" });
    expect(jwe.sizes).toEqual({ encryptedKey: 256, iv: 12, ciphertext: 100, tag: 16 });
    expect(() => parseJwe(`${b64u('{"alg":"dir"}')}.a.b.c.d`)).toThrow(/"enc"/);
  });

});

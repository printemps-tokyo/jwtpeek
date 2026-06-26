import { describe, expect, it } from "vitest";
import { base64UrlDecode, parseJwt } from "../src/decode.js";

/** Build a compact JWT (unsigned-ish) from header/payload objects. */
function makeToken(header: object, payload: object, sig = "sig"): string {
  const enc = (o: object): string => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${enc(header)}.${enc(payload)}.${sig}`;
}

describe("base64UrlDecode", () => {
  it("decodes without padding and with url-safe chars", () => {
    expect(base64UrlDecode(Buffer.from("Hello").toString("base64url")).toString()).toBe("Hello");
    expect(base64UrlDecode("YQ").toString()).toBe("a"); // unpadded
  });
});

describe("parseJwt", () => {
  it("decodes header and payload and keeps the signing input", () => {
    const token = makeToken({ alg: "HS256", typ: "JWT" }, { sub: "123", admin: true });
    const jwt = parseJwt(token);
    expect(jwt.header).toEqual({ alg: "HS256", typ: "JWT" });
    expect(jwt.payload).toEqual({ sub: "123", admin: true });
    expect(jwt.signingInput).toBe(token.split(".").slice(0, 2).join("."));
    expect(jwt.signature).toBe("sig");
  });

  it("rejects malformed tokens", () => {
    expect(() => parseJwt("only.two")).toThrow();
    expect(() => parseJwt("not-base64!.x.y")).toThrow();
    // A JSON array payload is not a claims object.
    const badPayload = `${Buffer.from('{"a":1}').toString("base64url")}.${Buffer.from("[1,2]").toString("base64url")}.s`;
    expect(() => parseJwt(badPayload)).toThrow();
  });
});

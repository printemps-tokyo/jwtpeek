import { describe, expect, it } from "vitest";
import { humanizeRelative, formatTime, tokenStatus, passesCheck } from "../src/claims.js";

describe("humanizeRelative", () => {
  it("formats future and past in the largest unit", () => {
    expect(humanizeRelative(0)).toBe("just now");
    expect(humanizeRelative(90)).toBe("in 1 minute");
    expect(humanizeRelative(-3600)).toBe("1 hour ago");
    expect(humanizeRelative(2 * 86_400)).toBe("in 2 days");
  });
});

describe("formatTime", () => {
  it("renders ISO and a relative description", () => {
    const t = formatTime(1_700_000_000, 1_700_000_000 - 3600);
    expect(t.iso).toBe("2023-11-14T22:13:20.000Z");
    expect(t.relative).toBe("in 1 hour");
  });
});

describe("tokenStatus", () => {
  const now = 1_700_000_000;
  it("detects expired, not-yet-valid, valid, and missing claims", () => {
    expect(tokenStatus({ exp: now - 10 }, now).status).toBe("expired");
    expect(tokenStatus({ nbf: now + 10 }, now).status).toBe("not-yet-valid");
    expect(tokenStatus({ exp: now + 100 }, now).status).toBe("valid");
    expect(tokenStatus({ sub: "x" }, now).status).toBe("no-time-claims");
  });
});

describe("passesCheck", () => {
  it("fails only for tokens outside their time window", () => {
    expect(passesCheck("valid")).toBe(true);
    expect(passesCheck("no-time-claims")).toBe(true);
    expect(passesCheck("expired")).toBe(false);
    expect(passesCheck("not-yet-valid")).toBe(false);
  });
});

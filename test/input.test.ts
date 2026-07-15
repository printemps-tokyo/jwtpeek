import { describe, expect, it } from "vitest";
import { resolveTokenSource } from "../src/input.js";

describe("resolveTokenSource", () => {
  it("uses the positional argument when one is given, regardless of TTY", () => {
    expect(resolveTokenSource("a.b.c", true)).toEqual({ kind: "arg", token: "a.b.c" });
    expect(resolveTokenSource("a.b.c", false)).toEqual({ kind: "arg", token: "a.b.c" });
  });

  it("falls back to stdin when stdin is piped or redirected", () => {
    expect(resolveTokenSource(undefined, false)).toEqual({ kind: "stdin" });
  });

  it("reports no token instead of blocking when stdin is an interactive TTY", () => {
    expect(resolveTokenSource(undefined, true)).toEqual({ kind: "none" });
  });
});

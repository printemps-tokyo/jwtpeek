/**
 * End-to-end check of the argument-parsing error path.
 *
 * When parseArgs rejects an unknown/invalid option, the CLI should print a
 * clean `error:` line and a hint pointing at `--help`, then exit 1 - rather
 * than surfacing a bare parser stack trace.
 *
 * Runs the built CLI (dist/cli.js); the test self-builds if dist is missing.
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { beforeAll, describe, expect, it } from "vitest";

const pexecFile = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const cliPath = join(root, "dist", "cli.js");

beforeAll(async () => {
  if (!existsSync(cliPath)) {
    await pexecFile("npm", ["run", "build"], { cwd: root });
  }
});

describe("cli argument parsing", () => {
  it("rejects an unknown flag with an error and a --help hint, exit 1", async () => {
    const err = (await pexecFile("node", [cliPath, "--definitely-not-a-real-flag"]).catch(
      (e: unknown) => e,
    )) as { code?: number; stderr?: string };
    expect(err.code).toBe(1);
    expect(err.stderr ?? "").toContain("error:");
    expect(err.stderr ?? "").toContain("--help");
  });
});

// The CLI end to end for JWE and --jwks (built above, before these run).
import { createServer } from "node:http";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";

describe("cli: JWE and --jwks", () => {
  const b64u = (b: Buffer | string): string => Buffer.from(b).toString("base64url");
  const header = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ";
  const token = `${header}.${b64u(Buffer.alloc(256))}.${b64u(Buffer.alloc(12))}.${b64u(Buffer.alloc(100))}.${b64u(Buffer.alloc(16))}`;

  it("shows a JWE and refuses to check it", async () => {
    const out = await pexecFile("node", [cliPath, "--no-color", token]);
    expect(out.stdout).toContain("JWE (encrypted token)");
    expect(out.stdout).toContain("enc: A256GCM");
    const err = await pexecFile("node", [cliPath, "--check", token]).catch((e: { code: number; stderr: string }) => e);
    expect((err as { code: number }).code).toBe(1);
    expect((err as { stderr: string }).stderr).toContain("encrypted JWE");
  });

  it("fetches a JWK Set over HTTP and verifies by kid", async () => {
    const k = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwks = { keys: [{ ...k.publicKey.export({ format: "jwk" }), kid: "a", alg: "RS256" }] };
    const input = `${b64u(JSON.stringify({ alg: "RS256", kid: "a" }))}.${b64u(JSON.stringify({ sub: "1" }))}`;
    const jwt = `${input}.${b64u(cryptoSign("sha256", Buffer.from(input), k.privateKey))}`;
    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(jwks));
    });
    await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
    try {
      const port = (server.address() as { port: number }).port;
      const out = await pexecFile("node", [cliPath, "--json", "--jwks", `http://127.0.0.1:${port}/jwks`, jwt]);
      expect(JSON.parse(out.stdout).signature.verified).toBe(true);
    } finally {
      await new Promise((done) => server.close(done));
    }
  });
});

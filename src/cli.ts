#!/usr/bin/env node
import { parseArgs } from "node:util";
import { readFile } from "node:fs/promises";
import { createPublicKey, type KeyObject } from "node:crypto";

import { parseJwt } from "./decode.js";
import { resolveTokenSource } from "./input.js";
import { tokenStatus, passesCheck } from "./claims.js";
import { verifyJwt, type VerifyResult } from "./verify.js";
import { renderJson, renderText } from "./render.js";

const HELP = `jwtpeek - decode and inspect a JWT offline

Usage:
  jwtpeek [options] [token]

Decodes a compact JWT's header and payload, explains the time claims and
validity, and can optionally verify the signature. The token is read from the
argument or from stdin. Nothing is sent over the network.

Options:
  --verify            Verify the signature (needs --secret or --key)
  --secret <string>   Shared secret for HS256/384/512
  --key <file>        Public key (PEM) for RS*/PS*/ES*
  --now <when>        Evaluate validity at this time (epoch seconds or ISO)
  --check             Exit non-zero if the token is expired or not yet valid
  --json              Output JSON instead of text
  --no-color          Disable ANSI colors
  -h, --help          Show this help
  -v, --version       Show version

Exit codes:
  0  ok           1  usage / decode error
  2  --verify failed                3  --check failed (expired / not yet valid)

Examples:
  jwtpeek eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.xxxx
  echo "$TOKEN" | jwtpeek --verify --secret s3cret
  jwtpeek --verify --key public.pem "$TOKEN" --json
  jwtpeek --check "$TOKEN"   # gate a token's freshness in CI / cron
`;

async function readVersion(): Promise<string> {
  const { fileURLToPath } = await import("node:url");
  const { dirname, join } = await import("node:path");
  const here = dirname(fileURLToPath(import.meta.url));
  try {
    const raw = await readFile(join(here, "..", "package.json"), "utf8");
    return (JSON.parse(raw) as { version: string }).version;
  } catch {
    return "0.0.0";
  }
}

function parseNow(value: string): number {
  if (/^\d+$/.test(value)) {
    return Number(value);
  }
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) {
    throw new Error(`--now must be epoch seconds or an ISO datetime (got "${value}")`);
  }
  return Math.floor(ms / 1000);
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  if (argv.includes("-h") || argv.includes("--help")) {
    process.stdout.write(HELP);
    return 0;
  }
  if (argv.includes("-v") || argv.includes("--version")) {
    process.stdout.write((await readVersion()) + "\n");
    return 0;
  }

  let values;
  let positionals;
  try {
    const parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        verify: { type: "boolean", default: false },
        secret: { type: "string" },
        key: { type: "string" },
        now: { type: "string" },
        check: { type: "boolean", default: false },
        json: { type: "boolean", default: false },
        "no-color": { type: "boolean", default: false },
      },
    });
    values = parsed.values;
    positionals = parsed.positionals;
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 1;
  }

  const source = resolveTokenSource(positionals[0], process.stdin.isTTY === true);
  if (source.kind === "none") {
    process.stderr.write("error: no token given (pass it as an argument or pipe it on stdin)\n");
    process.stderr.write("usage: jwtpeek [options] [token]   (see jwtpeek --help)\n");
    return 1;
  }
  const token = (source.kind === "arg" ? source.token : await readStdin()).trim();
  if (token === "") {
    process.stderr.write("error: no token given (pass it as an argument or on stdin)\n");
    return 1;
  }

  let nowSec: number;
  try {
    nowSec = values.now ? parseNow(values.now) : Math.floor(Date.now() / 1000);
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 1;
  }

  let jwt;
  try {
    jwt = parseJwt(token);
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 1;
  }

  let verify: VerifyResult | undefined;
  if (values.verify || values.secret !== undefined || values.key !== undefined) {
    let key: KeyObject | undefined;
    if (values.key !== undefined) {
      try {
        key = createPublicKey(await readFile(values.key, "utf8"));
      } catch (err) {
        process.stderr.write(`error: cannot read public key "${values.key}": ${(err as Error).message}\n`);
        return 1;
      }
    }
    try {
      verify = verifyJwt(jwt, { secret: values.secret, key });
    } catch (err) {
      verify = { alg: String(jwt.header.alg ?? "?"), verified: false, note: (err as Error).message };
    }
  }

  const color = !values["no-color"] && !process.env.NO_COLOR && process.stdout.isTTY === true;
  process.stdout.write(values.json ? renderJson(jwt, nowSec, verify) : renderText(jwt, nowSec, verify, color));

  // Exit non-zero if verification was requested and failed (2), then if a
  // requested --check freshness gate failed (3); otherwise success.
  if (verify && !verify.verified) {
    return 2;
  }
  if (values.check && !passesCheck(tokenStatus(jwt.payload, nowSec).status)) {
    return 3;
  }
  return 0;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    process.exitCode = 1;
  });

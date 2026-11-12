import type { Jwe, Jwt } from "./decode.js";
import { CLAIM_LABELS, TIME_CLAIMS, formatTime, tokenStatus, type Status } from "./claims.js";
import type { VerifyResult } from "./verify.js";

const COLORS = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  dim: "\x1b[2m",
};

function paint(text: string, code: string, on: boolean): string {
  return on ? `${code}${text}${COLORS.reset}` : text;
}

const STATUS_TEXT: Record<Status, string> = {
  valid: "VALID",
  expired: "EXPIRED",
  "not-yet-valid": "NOT YET VALID",
  "no-time-claims": "no exp/nbf claims",
};

/** Render the decoded token (and optional verification) as text. */
export function renderText(jwt: Jwt, nowSec: number, verify: VerifyResult | undefined, color: boolean): string {
  const lines: string[] = [];
  const alg = String(jwt.header.alg ?? "?");
  const typ = jwt.header.typ ? ` typ: ${String(jwt.header.typ)}` : "";
  lines.push(paint("JWT", COLORS.bold, color) + `  alg: ${alg}${typ}`);
  lines.push("");

  lines.push(paint("Header", COLORS.bold, color));
  lines.push(indent(JSON.stringify(jwt.header, null, 2)));
  lines.push("");

  lines.push(paint("Payload", COLORS.bold, color));
  lines.push(indent(JSON.stringify(jwt.payload, null, 2)));

  const timeLines: string[] = [];
  for (const claim of TIME_CLAIMS) {
    const value = jwt.payload[claim];
    if (typeof value === "number") {
      const t = formatTime(value, nowSec);
      timeLines.push(`  ${CLAIM_LABELS[claim]} (${claim}): ${t.iso} (${t.relative})`);
    }
  }
  if (timeLines.length > 0) {
    lines.push("", paint("Times", COLORS.bold, color), ...timeLines);
  }

  const { status, detail } = tokenStatus(jwt.payload, nowSec);
  const statusColor = status === "valid" ? COLORS.green : status === "no-time-claims" ? COLORS.dim : COLORS.red;
  lines.push("", `Status: ${paint(STATUS_TEXT[status], statusColor, color)}${detail ? ` (${detail})` : ""}`);

  if (verify) {
    const ok = verify.verified;
    const label = ok ? "verified" : verify.note ? `not verified — ${verify.note}` : "NOT verified";
    lines.push(`Signature: ${paint(label, ok ? COLORS.green : COLORS.red, color)}`);
  } else {
    lines.push(`Signature: ${jwt.signature ? "present (not checked)" : "absent"}`);
  }

  return lines.join("\n") + "\n";
}

function indent(text: string): string {
  return text
    .split("\n")
    .map((l) => `  ${l}`)
    .join("\n");
}

/** Render the decoded token (and optional verification) as JSON. */
export function renderJson(jwt: Jwt, nowSec: number, verify: VerifyResult | undefined): string {
  const times: Record<string, unknown> = {};
  for (const claim of TIME_CLAIMS) {
    const value = jwt.payload[claim];
    if (typeof value === "number") {
      times[claim] = formatTime(value, nowSec);
    }
  }
  const { status, detail } = tokenStatus(jwt.payload, nowSec);
  return (
    JSON.stringify(
      {
        header: jwt.header,
        payload: jwt.payload,
        times,
        status,
        statusDetail: detail,
        signature: verify
          ? { algorithm: verify.alg, verified: verify.verified, note: verify.note }
          : { present: jwt.signature.length > 0, checked: false },
      },
      null,
      2,
    ) + "\n"
  );
}

/** A JWE as text: its header and part sizes; the payload stays encrypted. */
export function renderJweText(jwe: Jwe): string {
  const h = jwe.header;
  const lines = [
    "JWE (encrypted token)",
    "",
    "Header:",
    JSON.stringify(h, null, 2),
    "",
    `alg: ${String(h.alg ?? "?")}  (how the content key is encrypted or agreed)`,
    `enc: ${String(h.enc ?? "?")}  (how the content is encrypted)`,
  ];
  if (h.kid !== undefined) lines.push(`kid: ${String(h.kid)}`);
  if (h.zip !== undefined) lines.push(`zip: ${String(h.zip)}  (the plaintext was compressed before encryption)`);
  if (h.cty !== undefined) lines.push(`cty: ${String(h.cty)}${String(h.cty).toUpperCase() === "JWT" ? "  (a nested JWT is inside)" : ""}`);
  const s = jwe.sizes;
  lines.push(
    `parts: encrypted key ${s.encryptedKey} bytes, IV ${s.iv}, ciphertext ${s.ciphertext}, tag ${s.tag}`,
    "",
    "The payload is encrypted; jwtpeek shows the header only and does not decrypt.",
  );
  return lines.join("\n") + "\n";
}

/** A JWE as JSON. */
export function renderJweJson(jwe: Jwe): string {
  return JSON.stringify({ type: "JWE", header: jwe.header, sizes: jwe.sizes }, null, 2) + "\n";
}

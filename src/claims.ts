/** Interpretation of the registered JWT claims (RFC 7519): times and validity. */

/** Friendly names for the registered claims. */
export const CLAIM_LABELS: Record<string, string> = {
  iss: "Issuer",
  sub: "Subject",
  aud: "Audience",
  exp: "Expires",
  nbf: "Not before",
  iat: "Issued at",
  jti: "JWT ID",
};

/** The time-valued registered claims (NumericDate, seconds since the epoch). */
export const TIME_CLAIMS = ["exp", "nbf", "iat"] as const;

/** A human-readable relative time, e.g. "in 2 hours" or "3 days ago". */
export function humanizeRelative(deltaSec: number): string {
  if (Math.abs(deltaSec) < 1) {
    return "just now";
  }
  const units: [string, number][] = [
    ["year", 31_536_000],
    ["month", 2_592_000],
    ["day", 86_400],
    ["hour", 3_600],
    ["minute", 60],
    ["second", 1],
  ];
  const abs = Math.abs(deltaSec);
  for (const [name, secs] of units) {
    if (abs >= secs || name === "second") {
      const value = Math.floor(abs / secs);
      const unit = `${name}${value === 1 ? "" : "s"}`;
      return deltaSec >= 0 ? `in ${value} ${unit}` : `${value} ${unit} ago`;
    }
  }
  return "just now";
}

/** A formatted view of a NumericDate claim. */
export interface TimeView {
  epoch: number;
  iso: string;
  relative: string;
}

/** Format a NumericDate claim relative to `nowSec`. */
export function formatTime(epochSec: number, nowSec: number): TimeView {
  return {
    epoch: epochSec,
    iso: new Date(epochSec * 1000).toISOString(),
    relative: humanizeRelative(epochSec - nowSec),
  };
}

export type Status = "valid" | "expired" | "not-yet-valid" | "no-time-claims";

/** Evaluate a token's temporal validity from its `exp` / `nbf` claims. */
export function tokenStatus(payload: Record<string, unknown>, nowSec: number): { status: Status; detail?: string } {
  const exp = typeof payload.exp === "number" ? payload.exp : undefined;
  const nbf = typeof payload.nbf === "number" ? payload.nbf : undefined;
  if (exp !== undefined && nowSec >= exp) {
    return { status: "expired", detail: `expired ${humanizeRelative(exp - nowSec)}` };
  }
  if (nbf !== undefined && nowSec < nbf) {
    return { status: "not-yet-valid", detail: `valid ${humanizeRelative(nbf - nowSec)}` };
  }
  if (exp !== undefined) {
    return { status: "valid", detail: `expires ${humanizeRelative(exp - nowSec)}` };
  }
  if (nbf !== undefined) {
    return { status: "valid" };
  }
  return { status: "no-time-claims" };
}

/**
 * Whether a token passes a `--check` validity gate. Only a token that is
 * actively outside its time window fails: `expired` and `not-yet-valid` are
 * failures, while `valid` and `no-time-claims` (a token nothing constrains)
 * pass. This keeps the gate from rejecting tokens that legitimately omit `exp`.
 */
export function passesCheck(status: Status): boolean {
  return status !== "expired" && status !== "not-yet-valid";
}

/**
 * Public API for jwtpeek.
 *
 * `jwtpeek` decodes and inspects a JSON Web Token entirely offline, and can
 * optionally verify its signature. Decoding and claim interpretation are pure
 * functions; verification is built on Node's `crypto`. Nothing is ever sent
 * over the network.
 */

export type { Jwt } from "./decode.js";
export { parseJwt, base64UrlDecode } from "./decode.js";

export {
  CLAIM_LABELS,
  TIME_CLAIMS,
  humanizeRelative,
  formatTime,
  tokenStatus,
  passesCheck,
} from "./claims.js";
export type { TimeView, Status } from "./claims.js";

export { verifyJwt } from "./verify.js";
export type { VerifyResult } from "./verify.js";

export { renderText, renderJson } from "./render.js";

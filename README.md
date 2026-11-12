# jwtpeek

> Decode and inspect a JWT offline, with optional signature verification. Zero-dependency CLI.

[![CI](https://github.com/printemps-tokyo/jwtpeek/actions/workflows/ci.yml/badge.svg)](https://github.com/printemps-tokyo/jwtpeek/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

`jwtpeek` shows you what's inside a JSON Web Token — header, claims, expiry —
right in your terminal, so you never paste a token into an online decoder.

```console
$ jwtpeek "$TOKEN"
JWT  alg: HS256 typ: JWT

Header
  { "alg": "HS256", "typ": "JWT" }

Payload
  { "sub": "1234567890", "name": "Sakata", "iat": 1700000000, "exp": 1700003600 }

Times
  Expires (exp): 2023-11-14T23:13:20.000Z (in 43 minutes)
  Issued at (iat): 2023-11-14T22:13:20.000Z (16 minutes ago)

Status: VALID (expires in 43 minutes)
Signature: present (not checked)
```

It is fully offline, has no runtime dependencies, and can verify the signature
when you provide the secret or public key.

## Requirements

- Node.js >= 22

## Install

Not published to npm yet — install from source:

```bash
git clone https://github.com/printemps-tokyo/jwtpeek
cd jwtpeek
npm install && npm run build
npm link   # optional: puts the `jwtpeek` command on your PATH
```

Then run `jwtpeek …` (after `npm link`), or `node dist/cli.js …` from the clone.

## Usage

```bash
jwtpeek "$TOKEN"                         # decode and inspect
echo "$TOKEN" | jwtpeek                  # read from stdin
jwtpeek --verify --secret s3cret "$TOKEN"   # verify an HS256 token
jwtpeek --verify --key public.pem "$TOKEN"  # verify RS*/PS*/ES*/EdDSA
jwtpeek --verify --key key.jwk.json "$TOKEN"  # public key as a JWK document
jwtpeek --jwks https://idp.example/.well-known/jwks.json "$TOKEN"  # key by kid
jwtpeek "$JWE"                           # an encrypted JWE: its header
jwtpeek --now 2026-01-01T00:00Z "$TOKEN"    # evaluate validity at a given time
jwtpeek --check "$TOKEN"                 # exit non-zero if expired / not yet valid
jwtpeek --json "$TOKEN"                  # machine-readable
```

| Option | Description |
| --- | --- |
| `[token]` | The JWT (or read it from stdin) |
| `--verify` | Verify the signature (needs `--secret` or `--key`) |
| `--secret <string>` | Shared secret for `HS256`/`HS384`/`HS512` |
| `--key <file>` | Public key (PEM, a JWK, or a JWK Set) for `RS*` / `PS*` / `ES*` / `EdDSA` |
| `--jwks <url\|file>` | A JWK Set to take the key from by the token's `kid` (https only) |
| `--now <when>` | Evaluate validity at this time (epoch seconds or ISO) |
| `--check` | Exit non-zero if the token is expired or not yet valid |
| `--json` | Output JSON instead of text |
| `--no-color` | Disable ANSI colors |

The exit code fits scripts and CI: `0` on success, `1` for a usage or decode
error, `2` when `--verify` is given and the signature does not verify, and `3`
when `--check` is given and the token is expired or not yet valid. `--check`
fails only when the token is actively outside its time window; a token with no
`exp` / `nbf` claims passes (there is nothing to expire).

## What it shows

- The decoded header and payload.
- The registered time claims (`exp`, `nbf`, `iat`) as ISO timestamps with a
  relative description, and the token's validity (`VALID` / `EXPIRED` /
  `NOT YET VALID`).
- Signature verification across the JWS families: `HS*` (HMAC), `RS*` (RSA),
  `PS*` (RSA-PSS), `ES*` (ECDSA, IEEE-P1363), and `EdDSA` (Ed25519). `alg:
  none` is reported as unsigned and insecure.

### JWK Sets (JWKS)

`--jwks` takes the public key from a JWK Set, a URL such as an identity
provider's `jwks_uri` or a saved file (`--key` also accepts a JWK Set). The key
is the one whose `kid` is the token's `kid`; a token without a `kid` uses the
only key of the right type (`kty`, `alg`, `use: sig`), and anything ambiguous
is an error rather than a guess. A URL must be `https://` (`http://` only for
localhost); the response is limited to 1 MiB and 10 seconds, and nothing about
the token is sent. This is the only network access jwtpeek makes.

jwtpeek does not find the JWKS from the token's own `iss` claim on purpose:
keys fetched from an address the token names prove nothing about the token.
Give the URL of the issuer you trust.

### JWE (encrypted tokens)

A compact JWE (five parts, RFC 7516) is recognized and its protected header
shown: `alg` (how the content key is encrypted or agreed), `enc` (how the
content is encrypted), `kid`, `zip`, `cty` (`JWT` for a nested token), and the
sizes of the encrypted key, IV, ciphertext and tag. The payload stays
encrypted: jwtpeek does not decrypt, and `--verify` / `--check` refuse a JWE.

## Security

- Decoding does not reveal the signing secret, but the token itself is a
  credential. jwtpeek runs entirely locally and never transmits it (`--jwks` fetches
  only the key set) — which is
  exactly why it beats pasting tokens into a web page.
- Verification is best done against a known secret or public key; treat an
  unverified payload as untrusted.

## Programmatic API

```ts
import { parseJwt, tokenStatus, verifyJwt } from "@printemps-tokyo/jwtpeek";

const jwt = parseJwt(token);
const { status } = tokenStatus(jwt.payload, Math.floor(Date.now() / 1000));
const result = verifyJwt(jwt, { secret: "s3cret" });
```

`parseJwt` and the claim helpers are pure functions; `verifyJwt` uses Node's
built-in `crypto`.

## License

[MIT](./LICENSE) (c) printemps.tokyo

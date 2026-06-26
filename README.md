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

- Node.js >= 20

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
jwtpeek --verify --key public.pem "$TOKEN"  # verify RS*/PS*/ES*
jwtpeek --now 2026-01-01T00:00Z "$TOKEN"    # evaluate validity at a given time
jwtpeek --json "$TOKEN"                  # machine-readable
```

| Option | Description |
| --- | --- |
| `[token]` | The JWT (or read it from stdin) |
| `--verify` | Verify the signature (needs `--secret` or `--key`) |
| `--secret <string>` | Shared secret for `HS256`/`HS384`/`HS512` |
| `--key <file>` | Public key (PEM) for `RS*` / `PS*` / `ES*` |
| `--now <when>` | Evaluate validity at this time (epoch seconds or ISO) |
| `--json` | Output JSON instead of text |
| `--no-color` | Disable ANSI colors |

When `--verify` is used and the signature does not verify, the exit code is `2`,
so it fits in scripts and CI.

## What it shows

- The decoded header and payload.
- The registered time claims (`exp`, `nbf`, `iat`) as ISO timestamps with a
  relative description, and the token's validity (`VALID` / `EXPIRED` /
  `NOT YET VALID`).
- Signature verification across the JWS families: `HS*` (HMAC), `RS*` (RSA),
  `PS*` (RSA-PSS), and `ES*` (ECDSA, IEEE-P1363). `alg: none` is reported as
  unsigned and insecure.

## Security

- Decoding does not reveal the signing secret, but the token itself is a
  credential. jwtpeek runs entirely locally and never transmits it — which is
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

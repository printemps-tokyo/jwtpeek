/**
 * Token input resolution for the CLI.
 *
 * Decides where the JWT should come from, so the CLI never blocks waiting on
 * an interactive terminal that will not deliver a token.
 */

export type TokenSource = { kind: "arg"; token: string } | { kind: "stdin" } | { kind: "none" };

/**
 * Resolve the token source from the first positional argument and whether
 * stdin is an interactive TTY. A missing positional falls back to stdin only
 * when stdin is piped or redirected; on an interactive TTY there is nothing
 * queued to read, so the caller should fail fast instead of hanging forever.
 */
export function resolveTokenSource(positional: string | undefined, stdinIsTTY: boolean): TokenSource {
  if (positional !== undefined) {
    return { kind: "arg", token: positional };
  }
  return stdinIsTTY ? { kind: "none" } : { kind: "stdin" };
}

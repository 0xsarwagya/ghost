import { GhostError } from "../errors.js";
import {
  GHOST_ID_HASH_BYTES,
  GHOST_ID_PATTERN,
  GHOST_ID_PREFIX,
  ID_CONTEXT,
} from "./constants.js";
import { encodeBase32, utf8Bytes } from "./encoding.js";

function resolveSubtle(subtle: SubtleCrypto | undefined): SubtleCrypto {
  const resolved = subtle ?? globalThis.crypto?.subtle;
  if (resolved === undefined) {
    throw new GhostError({
      code: "UNSUPPORTED",
      message: "Web Crypto (crypto.subtle) is not available in this runtime.",
      operation: "deriveGhostId",
    });
  }
  return resolved;
}

/**
 * ghost ID = "ghost_1_" + base32( SHA-256( "ghost-id-v1:" || publicKeyRaw )[0..20) )
 *
 * The ID is a fingerprint of the raw public key under a fixed domain
 * separation prefix. It is deterministic, URL-safe, case-safe, and carries
 * the protocol version.
 */
export async function deriveGhostId(
  publicKeyRaw: Uint8Array,
  subtle?: SubtleCrypto,
): Promise<string> {
  const context = utf8Bytes(ID_CONTEXT);
  const input = new Uint8Array(context.length + publicKeyRaw.length);
  input.set(context, 0);
  input.set(publicKeyRaw, context.length);
  const digest = await resolveSubtle(subtle).digest("SHA-256", input);
  const truncated = new Uint8Array(digest).slice(0, GHOST_ID_HASH_BYTES);
  return GHOST_ID_PREFIX + encodeBase32(truncated);
}

export function isGhostId(value: string): boolean {
  return GHOST_ID_PATTERN.test(value);
}

/**
 * Parses any ghost identifier shape and reports its protocol version, or
 * null when the string is not a ghost ID at all. Version 1 additionally
 * requires the exact v1 grammar.
 */
export function parseGhostId(value: string): { version: number } | null {
  const match = /^ghost_([1-9][0-9]*)_[a-z2-7]+$/.exec(value);
  if (match === null || match[1] === undefined) {
    return null;
  }
  const version = Number.parseInt(match[1], 10);
  if (version === 1 && !GHOST_ID_PATTERN.test(value)) {
    return null;
  }
  return { version };
}

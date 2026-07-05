import { GhostError, type GhostOperation } from "../errors.js";
import { GHOST_ID_PATTERN, PROOF_CONTEXT, PROTOCOL_VERSION } from "./constants.js";
import { lengthPrefixedConcat, utf8Bytes } from "./encoding.js";

/**
 * A one-time server-issued challenge. `expiresAt` is Unix epoch
 * milliseconds — a number, never a formatted date string.
 */
export interface GhostChallenge {
  version: 1;
  nonce: string;
  audience: string;
  action: string;
  expiresAt: number;
  ghostId?: string;
}

function fail(operation: GhostOperation, message: string): never {
  throw new GhostError({ code: "INVALID_CHALLENGE", message, operation });
}

export function assertChallengeShape(
  value: unknown,
  operation: GhostOperation,
): asserts value is GhostChallenge {
  if (typeof value !== "object" || value === null) {
    fail(operation, "challenge must be an object");
  }
  const challenge = value as Record<string, unknown>;
  if (typeof challenge.version !== "number") {
    fail(operation, "challenge.version must be a number");
  }
  if (challenge.version !== PROTOCOL_VERSION) {
    throw new GhostError({
      code: "UNSUPPORTED_VERSION",
      message: `unsupported challenge version: ${String(challenge.version)}`,
      operation,
    });
  }
  for (const field of ["nonce", "audience", "action"] as const) {
    if (typeof challenge[field] !== "string" || challenge[field].length === 0) {
      fail(operation, `challenge.${field} must be a non-empty string`);
    }
  }
  if (
    typeof challenge.expiresAt !== "number" ||
    !Number.isSafeInteger(challenge.expiresAt) ||
    challenge.expiresAt <= 0
  ) {
    fail(operation, "challenge.expiresAt must be a positive integer (epoch ms)");
  }
  if (challenge.ghostId !== undefined) {
    if (
      typeof challenge.ghostId !== "string" ||
      !GHOST_ID_PATTERN.test(challenge.ghostId)
    ) {
      fail(operation, "challenge.ghostId must be a well-formed ghost ID");
    }
  }
}

/**
 * The exact bytes a ghost signs. Fixed field order, each field
 * length-prefixed (uint32 big-endian) — deterministic without any JSON
 * canonicalization rules. An absent `ghostId` encodes as the empty field;
 * a present one can never be empty, so the two are unambiguous.
 */
export function canonicalChallengeBytes(
  challenge: GhostChallenge,
): Uint8Array<ArrayBuffer> {
  assertChallengeShape(challenge, "canonicalChallengeBytes");
  return lengthPrefixedConcat([
    utf8Bytes(PROOF_CONTEXT),
    utf8Bytes(challenge.nonce),
    utf8Bytes(challenge.audience),
    utf8Bytes(challenge.action),
    utf8Bytes(String(challenge.expiresAt)),
    utf8Bytes(challenge.ghostId ?? ""),
  ]);
}

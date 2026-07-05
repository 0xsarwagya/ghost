import { GhostError } from "../errors.js";
import type { GhostChallenge } from "../protocol/challenge.js";
import { GHOST_ID_PATTERN, PROTOCOL_VERSION } from "../protocol/constants.js";
import { encodeBase64Url } from "../protocol/encoding.js";

export interface CreateChallengeInput {
  audience: string;
  action: string;
  /** Challenge lifetime in milliseconds. Default: 120 000 (two minutes). */
  ttlMs?: number;
  /** Bind the challenge to one identity — only that ghost can answer it. */
  ghostId?: string;
  now?: () => number;
  crypto?: Crypto;
}

const NONCE_BYTES = 32;

export function createChallenge(input: CreateChallengeInput): GhostChallenge {
  const cryptoApi = input.crypto ?? globalThis.crypto;
  if (cryptoApi === undefined) {
    throw new GhostError({
      code: "UNSUPPORTED",
      message: "Web Crypto (globalThis.crypto) is not available in this runtime.",
      operation: "createChallenge",
    });
  }
  if (typeof input.audience !== "string" || input.audience.length === 0) {
    throw new GhostError({
      code: "INVALID_CHALLENGE",
      message: "audience must be a non-empty string",
      operation: "createChallenge",
    });
  }
  if (typeof input.action !== "string" || input.action.length === 0) {
    throw new GhostError({
      code: "INVALID_CHALLENGE",
      message: "action must be a non-empty string",
      operation: "createChallenge",
    });
  }
  if (input.ghostId !== undefined && !GHOST_ID_PATTERN.test(input.ghostId)) {
    throw new GhostError({
      code: "INVALID_CHALLENGE",
      message: "ghostId must be a well-formed ghost ID",
      operation: "createChallenge",
    });
  }
  const ttlMs = input.ttlMs ?? 120_000;
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) {
    throw new GhostError({
      code: "INVALID_CHALLENGE",
      message: "ttlMs must be a positive integer",
      operation: "createChallenge",
    });
  }

  const nonceBytes = cryptoApi.getRandomValues(new Uint8Array(NONCE_BYTES));
  const challenge: GhostChallenge = {
    version: PROTOCOL_VERSION,
    nonce: encodeBase64Url(nonceBytes),
    audience: input.audience,
    action: input.action,
    expiresAt: (input.now ?? Date.now)() + ttlMs,
  };
  if (input.ghostId !== undefined) {
    challenge.ghostId = input.ghostId;
  }
  return challenge;
}

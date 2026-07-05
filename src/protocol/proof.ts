import { GhostError, type GhostOperation } from "../errors.js";
import { assertChallengeShape, type GhostChallenge } from "./challenge.js";
import { ALGORITHM, GHOST_ID_PATTERN, PROTOCOL_VERSION } from "./constants.js";

/**
 * A self-contained proof of possession. The public key travels with the
 * proof; verifiers recompute the ghost ID from it, so `ghostId` is
 * self-authenticating rather than trusted.
 */
export interface GhostProof {
  version: 1;
  algorithm: "ed25519";
  ghostId: string;
  publicKey: string;
  challenge: GhostChallenge;
  signature: string;
}

function fail(operation: GhostOperation, message: string): never {
  throw new GhostError({ code: "INVALID_CHALLENGE", message, operation });
}

export function assertProofShape(
  value: unknown,
  operation: GhostOperation,
): asserts value is GhostProof {
  if (typeof value !== "object" || value === null) {
    fail(operation, "proof must be an object");
  }
  const proof = value as Record<string, unknown>;
  if (typeof proof.version !== "number") {
    fail(operation, "proof.version must be a number");
  }
  if (proof.version !== PROTOCOL_VERSION) {
    throw new GhostError({
      code: "UNSUPPORTED_VERSION",
      message: `unsupported proof version: ${String(proof.version)}`,
      operation,
    });
  }
  if (typeof proof.algorithm !== "string") {
    fail(operation, "proof.algorithm must be a string");
  }
  if (proof.algorithm !== ALGORITHM) {
    throw new GhostError({
      code: "UNSUPPORTED_VERSION",
      message: `unsupported proof algorithm: ${String(proof.algorithm)}`,
      operation,
    });
  }
  if (typeof proof.ghostId !== "string" || !GHOST_ID_PATTERN.test(proof.ghostId)) {
    fail(operation, "proof.ghostId must be a well-formed ghost ID");
  }
  for (const field of ["publicKey", "signature"] as const) {
    if (typeof proof[field] !== "string" || proof[field].length === 0) {
      fail(operation, `proof.${field} must be a non-empty string`);
    }
  }
  assertChallengeShape(proof.challenge, operation);
}

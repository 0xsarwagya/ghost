export type GhostErrorCode =
  | "UNSUPPORTED"
  | "STORAGE_UNAVAILABLE"
  | "KEY_GENERATION_FAILED"
  | "KEY_NOT_FOUND"
  | "IDENTITY_CORRUPTED"
  | "RECOVERY_FAILED"
  | "SIGNING_FAILED"
  | "INVALID_CHALLENGE"
  | "CHALLENGE_EXPIRED"
  | "CHALLENGE_REUSED"
  | "AUDIENCE_MISMATCH"
  | "INVALID_SIGNATURE"
  | "UNSUPPORTED_VERSION";

export type GhostOperation =
  | "createGhost"
  | "enableRecovery"
  | "recoverGhost"
  | "capabilities"
  | "sign"
  | "reset"
  | "deriveGhostId"
  | "canonicalChallengeBytes"
  | "createChallenge"
  | "verifyGhostProof";

export class GhostError extends Error {
  readonly code: GhostErrorCode;
  readonly operation: GhostOperation;

  constructor(options: {
    code: GhostErrorCode;
    message: string;
    operation: GhostOperation;
    cause?: unknown;
  }) {
    super(options.message, { cause: options.cause });
    this.name = "GhostError";
    this.code = options.code;
    this.operation = options.operation;
  }
}

export function isGhostError(value: unknown): value is GhostError {
  return value instanceof GhostError;
}

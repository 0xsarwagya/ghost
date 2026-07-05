export { createChallenge } from "./server/challenge.js";
export type { CreateChallengeInput } from "./server/challenge.js";
export { InMemoryChallengeStore } from "./server/store.js";
export type { ChallengeStore } from "./server/store.js";
export { verifyGhostProof } from "./server/verify.js";
export type { GhostVerification, VerifyGhostProofOptions } from "./server/verify.js";

export { GhostError, isGhostError } from "./errors.js";
export type { GhostErrorCode, GhostOperation } from "./errors.js";
export { canonicalChallengeBytes } from "./protocol/challenge.js";
export type { GhostChallenge } from "./protocol/challenge.js";
export { deriveGhostId, isGhostId, parseGhostId } from "./protocol/identity.js";
export type { GhostProof } from "./protocol/proof.js";

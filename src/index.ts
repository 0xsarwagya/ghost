export { capabilities } from "./browser/capabilities.js";
export type { GhostCapabilities } from "./browser/capabilities.js";
export { createGhost, recoverGhost } from "./browser/ghost.js";
export type { CreateGhostOptions, Ghost, RecoverGhostInput } from "./browser/ghost.js";

export { GhostError, isGhostError } from "./errors.js";
export type { GhostErrorCode, GhostOperation } from "./errors.js";
export { canonicalChallengeBytes } from "./protocol/challenge.js";
export type { GhostChallenge } from "./protocol/challenge.js";
export {
  createGhostId,
  deriveCredentialId,
  deriveGhostId,
  isCredentialId,
  isGhostId,
  parseGhostId,
} from "./protocol/identity.js";
export type {
  GhostRecoveryRecord,
  GhostRecoverySetup,
} from "./protocol/identity.js";
export type { GhostProof } from "./protocol/proof.js";

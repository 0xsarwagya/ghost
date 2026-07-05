export { capabilities } from "./browser/capabilities.js";
export type { GhostCapabilities } from "./browser/capabilities.js";
export { createGhost } from "./browser/ghost.js";
export type { CreateGhostOptions, Ghost } from "./browser/ghost.js";

export { GhostError, isGhostError } from "./errors.js";
export type { GhostErrorCode, GhostOperation } from "./errors.js";
export { canonicalChallengeBytes } from "./protocol/challenge.js";
export type { GhostChallenge } from "./protocol/challenge.js";
export { deriveGhostId, isGhostId, parseGhostId } from "./protocol/identity.js";
export type { GhostProof } from "./protocol/proof.js";

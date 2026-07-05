import { GhostError, isGhostError, type GhostErrorCode } from "../errors.js";
import { canonicalChallengeBytes } from "../protocol/challenge.js";
import { PUBLIC_KEY_BYTES, SIGNATURE_BYTES } from "../protocol/constants.js";
import { decodeBase64Url } from "../protocol/encoding.js";
import { deriveGhostId } from "../protocol/identity.js";
import { assertProofShape } from "../protocol/proof.js";
import type { ChallengeStore } from "./store.js";

export interface VerifyGhostProofOptions {
  /** The audience value this server issues challenges for. */
  expectedAudience: string;
  /** Replay protection — a nonce verifies successfully exactly once. */
  challengeStore: ChallengeStore;
  /** Require the challenge to carry this exact action. */
  expectedAction?: string;
  /** Require the proof to come from this exact identity. */
  expectedGhostId?: string;
  now?: () => number;
  crypto?: Crypto;
}

export type GhostVerification =
  | { ok: true; ghostId: string; publicKey: string; action: string }
  | { ok: false; code: GhostErrorCode; message: string };

function reject(code: GhostErrorCode, message: string): GhostVerification {
  return { ok: false, code, message };
}

/**
 * Verifies a proof of possession. Protocol failures come back as
 * `{ ok: false, code }` — this sits on request paths, so bad input is a
 * result, not an exception. Only caller misconfiguration throws.
 *
 * A cryptographically valid signature is not enough: expiry, audience,
 * action, identity binding, and one-time nonce consumption are all
 * enforced here. The nonce is consumed last, so a failed proof never
 * burns a challenge.
 */
export async function verifyGhostProof(
  proof: unknown,
  options: VerifyGhostProofOptions,
): Promise<GhostVerification> {
  if (
    typeof options?.expectedAudience !== "string" ||
    options.expectedAudience.length === 0
  ) {
    throw new GhostError({
      code: "INVALID_CHALLENGE",
      message: "options.expectedAudience must be a non-empty string",
      operation: "verifyGhostProof",
    });
  }
  if (typeof options.challengeStore?.consume !== "function") {
    throw new GhostError({
      code: "INVALID_CHALLENGE",
      message: "options.challengeStore must implement consume()",
      operation: "verifyGhostProof",
    });
  }
  const cryptoApi = options.crypto ?? globalThis.crypto;
  if (cryptoApi?.subtle === undefined) {
    throw new GhostError({
      code: "UNSUPPORTED",
      message: "Web Crypto (crypto.subtle) is not available in this runtime.",
      operation: "verifyGhostProof",
    });
  }

  try {
    assertProofShape(proof, "verifyGhostProof");
  } catch (error) {
    if (isGhostError(error)) {
      return reject(error.code, error.message);
    }
    throw error;
  }

  const { challenge } = proof;
  const now = (options.now ?? Date.now)();
  if (now > challenge.expiresAt) {
    return reject("CHALLENGE_EXPIRED", "challenge has expired");
  }
  if (challenge.audience !== options.expectedAudience) {
    return reject(
      "AUDIENCE_MISMATCH",
      `challenge audience ${JSON.stringify(challenge.audience)} does not match this server`,
    );
  }
  if (options.expectedAction !== undefined && challenge.action !== options.expectedAction) {
    return reject(
      "INVALID_CHALLENGE",
      `challenge action ${JSON.stringify(challenge.action)} does not match the expected action`,
    );
  }
  if (challenge.ghostId !== undefined && challenge.ghostId !== proof.ghostId) {
    return reject(
      "INVALID_CHALLENGE",
      "challenge is bound to a different ghost identity",
    );
  }
  if (options.expectedGhostId !== undefined && proof.ghostId !== options.expectedGhostId) {
    return reject("INVALID_CHALLENGE", "proof is from an unexpected ghost identity");
  }

  let publicKeyRaw: Uint8Array<ArrayBuffer>;
  let signature: Uint8Array<ArrayBuffer>;
  try {
    publicKeyRaw = decodeBase64Url(proof.publicKey);
    signature = decodeBase64Url(proof.signature);
  } catch {
    return reject("INVALID_SIGNATURE", "public key or signature is not valid base64url");
  }
  if (publicKeyRaw.length !== PUBLIC_KEY_BYTES) {
    return reject("INVALID_SIGNATURE", "public key has the wrong length");
  }
  if (signature.length !== SIGNATURE_BYTES) {
    return reject("INVALID_SIGNATURE", "signature has the wrong length");
  }

  // The ghost ID is a claim; the public key is the evidence. Recompute.
  const derivedId = await deriveGhostId(publicKeyRaw, cryptoApi.subtle);
  if (derivedId !== proof.ghostId) {
    return reject("INVALID_SIGNATURE", "ghost ID does not match the public key");
  }

  let verified: boolean;
  try {
    const publicKey = await cryptoApi.subtle.importKey(
      "raw",
      publicKeyRaw,
      "Ed25519",
      false,
      ["verify"],
    );
    verified = await cryptoApi.subtle.verify(
      "Ed25519",
      publicKey,
      signature,
      canonicalChallengeBytes(challenge),
    );
  } catch {
    return reject("INVALID_SIGNATURE", "signature verification failed");
  }
  if (!verified) {
    return reject("INVALID_SIGNATURE", "signature does not verify");
  }

  const consumed = await options.challengeStore.consume(
    challenge.nonce,
    challenge.expiresAt,
  );
  if (!consumed) {
    return reject("CHALLENGE_REUSED", "challenge nonce has already been used");
  }

  return {
    ok: true,
    ghostId: proof.ghostId,
    publicKey: proof.publicKey,
    action: challenge.action,
  };
}

import { GhostError } from "../errors.js";
import {
  assertChallengeShape,
  canonicalChallengeBytes,
  type GhostChallenge,
} from "../protocol/challenge.js";
import { ALGORITHM, PROTOCOL_VERSION } from "../protocol/constants.js";
import { encodeBase64Url } from "../protocol/encoding.js";
import { deriveGhostId } from "../protocol/identity.js";
import type { GhostProof } from "../protocol/proof.js";
import {
  deleteIdentity,
  loadIdentity,
  saveIdentityIfAbsent,
  type IdentityRecord,
} from "./storage.js";

export interface CreateGhostOptions {
  /** Injectable for tests. Defaults to globalThis.crypto. */
  crypto?: Crypto;
}

export interface Ghost {
  /** The public identifier — ghost_1_… */
  readonly id: string;
  /** base64url of the raw public key. */
  readonly publicKey: string;
  /** Signs a server-issued challenge and returns the proof envelope. */
  sign(challenge: GhostChallenge): Promise<GhostProof>;
  /**
   * Destroys the local identity. Deliberately not called "logout": there is
   * no account to log out of. The old identity becomes permanently
   * inaccessible; the next createGhost() produces a new one.
   */
  reset(): Promise<void>;
}

function isIdentityRecord(value: unknown): value is IdentityRecord {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    record.id === "default" &&
    record.version === PROTOCOL_VERSION &&
    record.algorithm === ALGORITHM &&
    record.privateKey instanceof CryptoKey &&
    record.privateKey.type === "private" &&
    record.publicKeyRaw instanceof ArrayBuffer &&
    typeof record.createdAt === "number"
  );
}

async function loadOrCreateRecord(cryptoApi: Crypto): Promise<IdentityRecord> {
  const existing = await loadIdentity("createGhost");
  if (existing !== undefined) {
    if (!isIdentityRecord(existing)) {
      throw new GhostError({
        code: "IDENTITY_CORRUPTED",
        message:
          "the stored identity record is unreadable — reset() discards it and starts over",
        operation: "createGhost",
      });
    }
    return existing;
  }

  let keyPair: CryptoKeyPair;
  let publicKeyRaw: ArrayBuffer;
  try {
    keyPair = (await cryptoApi.subtle.generateKey("Ed25519", false, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    publicKeyRaw = await cryptoApi.subtle.exportKey("raw", keyPair.publicKey);
  } catch (error) {
    throw new GhostError({
      code: "KEY_GENERATION_FAILED",
      message: "the runtime failed to generate an Ed25519 keypair",
      operation: "createGhost",
      cause: error,
    });
  }

  const fresh: IdentityRecord = {
    id: "default",
    version: PROTOCOL_VERSION,
    algorithm: ALGORITHM,
    privateKey: keyPair.privateKey,
    publicKeyRaw,
    createdAt: Date.now(),
  };
  const winner = await saveIdentityIfAbsent(fresh, "createGhost");
  if (!isIdentityRecord(winner)) {
    throw new GhostError({
      code: "IDENTITY_CORRUPTED",
      message:
        "the stored identity record is unreadable — reset() discards it and starts over",
      operation: "createGhost",
    });
  }
  return winner;
}

let inFlight: Promise<Ghost> | undefined;

/**
 * Loads the origin's ghost identity, creating it on first use. The private
 * key is generated non-extractable and never crosses this API boundary.
 * Requires no network and no user gesture.
 */
export function createGhost(options: CreateGhostOptions = {}): Promise<Ghost> {
  if (inFlight !== undefined) {
    return inFlight;
  }
  const pending = instantiate(options).finally(() => {
    inFlight = undefined;
  });
  inFlight = pending;
  return pending;
}

async function instantiate(options: CreateGhostOptions): Promise<Ghost> {
  const cryptoApi = options.crypto ?? globalThis.crypto;
  if (cryptoApi?.subtle === undefined) {
    throw new GhostError({
      code: "UNSUPPORTED",
      message: "Web Crypto (crypto.subtle) is not available in this runtime.",
      operation: "createGhost",
    });
  }

  const record = await loadOrCreateRecord(cryptoApi);
  const publicKeyRaw = new Uint8Array(record.publicKeyRaw);
  const id = await deriveGhostId(publicKeyRaw, cryptoApi.subtle);
  const publicKey = encodeBase64Url(publicKeyRaw);
  let destroyed = false;

  return {
    id,
    publicKey,
    async sign(challenge: GhostChallenge): Promise<GhostProof> {
      if (destroyed) {
        throw new GhostError({
          code: "KEY_NOT_FOUND",
          message: "this identity has been reset",
          operation: "sign",
        });
      }
      assertChallengeShape(challenge, "sign");
      if (Date.now() > challenge.expiresAt) {
        throw new GhostError({
          code: "CHALLENGE_EXPIRED",
          message: "challenge has already expired",
          operation: "sign",
        });
      }
      if (challenge.ghostId !== undefined && challenge.ghostId !== id) {
        throw new GhostError({
          code: "INVALID_CHALLENGE",
          message: "challenge is bound to a different ghost identity",
          operation: "sign",
        });
      }
      let signature: ArrayBuffer;
      try {
        signature = await cryptoApi.subtle.sign(
          "Ed25519",
          record.privateKey,
          canonicalChallengeBytes(challenge),
        );
      } catch (error) {
        throw new GhostError({
          code: "SIGNING_FAILED",
          message: "the runtime failed to sign the challenge",
          operation: "sign",
          cause: error,
        });
      }
      return {
        version: PROTOCOL_VERSION,
        algorithm: ALGORITHM,
        ghostId: id,
        publicKey,
        challenge: { ...challenge },
        signature: encodeBase64Url(new Uint8Array(signature)),
      };
    },
    async reset(): Promise<void> {
      await deleteIdentity("reset");
      destroyed = true;
    },
  };
}

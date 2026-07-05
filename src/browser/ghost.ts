import { GhostError } from "../errors.js";
import {
  assertChallengeShape,
  canonicalChallengeBytes,
  type GhostChallenge,
} from "../protocol/challenge.js";
import { ALGORITHM, PROTOCOL_VERSION } from "../protocol/constants.js";
import { encodeBase64Url } from "../protocol/encoding.js";
import {
  assertRecoveryRecord,
  createGhostId,
  createRecoverySecret,
  deriveCredentialId,
  deriveGhostId,
  deriveRecoveryAuthorityId,
  isGhostId,
  type GhostRecoveryRecord,
  type GhostRecoverySetup,
} from "../protocol/identity.js";
import type { GhostProof } from "../protocol/proof.js";
import {
  deleteIdentity,
  loadIdentity,
  saveIdentity,
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
  /** Identifier for the active browser-held credential. */
  readonly credentialId: string;
  /** base64url of the raw public key. */
  readonly publicKey: string;
  /** The configured recovery method, when this Ghost has opted in. */
  readonly recovery?: GhostRecoveryRecord;
  /**
   * Creates a user-held recovery secret and an app-storable recovery record.
   * Calling it again mints a fresh secret and record; a record your app
   * stored earlier keeps verifying against its own secret until your app
   * replaces it — rotation is the application's storage decision.
   */
  enableRecovery(): Promise<GhostRecoverySetup>;
  /** Signs a server-issued challenge and returns the proof envelope. */
  sign(challenge: GhostChallenge): Promise<GhostProof>;
  /**
   * Destroys the local identity. Deliberately not called "logout": there is
   * no account to log out of. The old identity becomes permanently
   * inaccessible; the next createGhost() produces a new one.
   */
  reset(): Promise<void>;
}

export interface RecoverGhostInput {
  recoverySecret: string;
  recoveryRecord: GhostRecoveryRecord;
  /** Injectable for tests. Defaults to globalThis.crypto. */
  crypto?: Crypto;
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
    typeof record.createdAt === "number" &&
    (record.ghostId === undefined ||
      (typeof record.ghostId === "string" && isGhostId(record.ghostId))) &&
    (record.credentialId === undefined || typeof record.credentialId === "string")
  );
}

async function completeRecord(
  record: IdentityRecord,
  cryptoApi: Crypto,
  operation: "createGhost" | "recoverGhost",
): Promise<IdentityRecord> {
  const publicKeyRaw = new Uint8Array(record.publicKeyRaw);
  const ghostId = record.ghostId ?? (await deriveGhostId(publicKeyRaw, cryptoApi.subtle));
  const credentialId =
    record.credentialId ?? (await deriveCredentialId(publicKeyRaw, cryptoApi.subtle));
  const completed = { ...record, ghostId, credentialId };
  if (record.ghostId === undefined || record.credentialId === undefined) {
    await saveIdentity(completed, operation);
  }
  return completed;
}

async function generateCredential(
  cryptoApi: Crypto,
  operation: "createGhost" | "recoverGhost",
): Promise<{ privateKey: CryptoKey; publicKeyRaw: ArrayBuffer; credentialId: string }> {
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
      operation,
      cause: error,
    });
  }
  return {
    privateKey: keyPair.privateKey,
    publicKeyRaw,
    credentialId: await deriveCredentialId(new Uint8Array(publicKeyRaw), cryptoApi.subtle),
  };
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
    return completeRecord(existing, cryptoApi, "createGhost");
  }

  const identityMaterial = new Uint8Array(32);
  cryptoApi.getRandomValues(identityMaterial);
  const credential = await generateCredential(cryptoApi, "createGhost");

  const fresh: IdentityRecord = {
    id: "default",
    version: PROTOCOL_VERSION,
    algorithm: ALGORITHM,
    ghostId: await createGhostId(identityMaterial, cryptoApi.subtle),
    credentialId: credential.credentialId,
    privateKey: credential.privateKey,
    publicKeyRaw: credential.publicKeyRaw,
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
  return completeRecord(winner, cryptoApi, "createGhost");
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

export async function recoverGhost(input: RecoverGhostInput): Promise<Ghost> {
  const cryptoApi = input.crypto ?? globalThis.crypto;
  if (cryptoApi?.subtle === undefined) {
    throw new GhostError({
      code: "UNSUPPORTED",
      message: "Web Crypto (crypto.subtle) is not available in this runtime.",
      operation: "recoverGhost",
    });
  }
  assertRecoveryRecord(input.recoveryRecord, "recoverGhost");
  const authorityId = await deriveRecoveryAuthorityId(
    input.recoverySecret,
    cryptoApi.subtle,
  );
  if (authorityId !== input.recoveryRecord.authorityId) {
    throw new GhostError({
      code: "RECOVERY_FAILED",
      message: "recovery secret does not match this Ghost",
      operation: "recoverGhost",
    });
  }

  // Never clobber a different identity's non-extractable key — that would
  // destroy it permanently. The app must reset() deliberately first.
  const existing = await loadIdentity("recoverGhost");
  if (existing !== undefined && isIdentityRecord(existing)) {
    const existingGhostId =
      existing.ghostId ??
      (await deriveGhostId(new Uint8Array(existing.publicKeyRaw), cryptoApi.subtle));
    if (existingGhostId !== input.recoveryRecord.ghostId) {
      throw new GhostError({
        code: "RECOVERY_FAILED",
        message:
          "a different Ghost identity already exists in this browser — reset() it before recovering another",
        operation: "recoverGhost",
      });
    }
  }

  const credential = await generateCredential(cryptoApi, "recoverGhost");
  const recovered: IdentityRecord = {
    id: "default",
    version: PROTOCOL_VERSION,
    algorithm: ALGORITHM,
    ghostId: input.recoveryRecord.ghostId,
    credentialId: credential.credentialId,
    privateKey: credential.privateKey,
    publicKeyRaw: credential.publicKeyRaw,
    createdAt: Date.now(),
    recovery: { ...input.recoveryRecord },
  };
  await saveIdentity(recovered, "recoverGhost");
  return instantiate({ crypto: cryptoApi });
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
  const id = record.ghostId;
  const credentialId = record.credentialId;
  if (id === undefined || credentialId === undefined) {
    throw new GhostError({
      code: "IDENTITY_CORRUPTED",
      message: "the stored identity record is missing identity metadata",
      operation: "createGhost",
    });
  }
  const publicKey = encodeBase64Url(publicKeyRaw);
  let destroyed = false;

  return {
    id,
    credentialId,
    publicKey,
    ...(record.recovery !== undefined ? { recovery: record.recovery } : {}),
    async enableRecovery(): Promise<GhostRecoverySetup> {
      if (destroyed) {
        throw new GhostError({
          code: "KEY_NOT_FOUND",
          message: "this identity has been reset",
          operation: "enableRecovery",
        });
      }
      const recoverySecret = createRecoverySecret(cryptoApi);
      const recoveryRecord: GhostRecoveryRecord = {
        version: PROTOCOL_VERSION,
        method: "recovery-secret",
        ghostId: id,
        authorityId: await deriveRecoveryAuthorityId(
          recoverySecret,
          cryptoApi.subtle,
        ),
        createdAt: Date.now(),
      };
      await saveIdentity({ ...record, recovery: recoveryRecord }, "enableRecovery");
      return { recoverySecret, recoveryRecord };
    },
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
        credentialId,
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
